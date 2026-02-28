import json
import logging

logger = logging.getLogger(__name__)

class ResponseAnalyzer:
    @staticmethod
    def extract_structure(obj):
        """
        Recursively extract the structural skeleton of a JSON object.
        Converts values to their types to focus on the schema.
        """
        if isinstance(obj, dict):
            return {k: ResponseAnalyzer.extract_structure(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            # For lists, we represent the structure of its items
            if len(obj) > 0:
                # Merge structures of all items to get a comprehensive schema
                merged_structure = {}
                for item in obj:
                    item_struct = ResponseAnalyzer.extract_structure(item)
                    if isinstance(item_struct, dict):
                        merged_structure.update(item_struct)
                return [merged_structure] if merged_structure else ["list_of_any"]
            return ["empty_list"]
        else:
            return type(obj).__name__

    @staticmethod
    def compare_structures(struct1, struct2):
        """
        Compare two structural skeletons and return a similarity score (0.0 to 1.0).
        """
        if type(struct1) != type(struct2):
            return 0.0

        if isinstance(struct1, dict) and isinstance(struct2, dict):
            keys1 = set(struct1.keys())
            keys2 = set(struct2.keys())
            
            if not keys1 and not keys2:
                return 1.0
                
            intersection = keys1.intersection(keys2)
            union = keys1.union(keys2)
            
            # Base similarity on keys
            key_similarity = len(intersection) / len(union)
            
            # Deep similarity on matching keys
            deep_similarities = []
            for k in intersection:
                deep_similarities.append(ResponseAnalyzer.compare_structures(struct1[k], struct2[k]))
                
            if deep_similarities:
                return (key_similarity + (sum(deep_similarities) / len(deep_similarities))) / 2
            return key_similarity
            
        elif isinstance(struct1, list) and isinstance(struct2, list):
            if len(struct1) == 0 and len(struct2) == 0:
                return 1.0
            if len(struct1) == 0 or len(struct2) == 0:
                return 0.0
            return ResponseAnalyzer.compare_structures(struct1[0], struct2[0])
            
        else:
            return 1.0 if struct1 == struct2 else 0.5 # Same type

    @staticmethod
    def calculate_distance(resp1_text, resp2_text):
        """
        Calculate structural distance between two JSON strings.
        Distance = 1.0 - Similarity. 
        Distance 0.0 means structurally identical.
        Distance 1.0 means completely different.
        """
        try:
            obj1 = json.loads(resp1_text)
            obj2 = json.loads(resp2_text)
        except json.JSONDecodeError:
            # If not JSON, simple length comparison
            len_ratio = min(len(resp1_text), len(resp2_text)) / max(len(resp1_text), len(resp2_text)) if max(len(resp1_text), len(resp2_text)) > 0 else 1.0
            return 1.0 - len_ratio

        struct1 = ResponseAnalyzer.extract_structure(obj1)
        struct2 = ResponseAnalyzer.extract_structure(obj2)
        
        similarity = ResponseAnalyzer.compare_structures(struct1, struct2)
        return 1.0 - similarity

    @staticmethod
    def is_bfla_bypass(high_status, low_status, high_text, low_text, distance_threshold=0.2):
        """
        Determine if the low privilege access constitutes a BFLA bypass.
        """
        # If low priv gets explicitly rejected, no bypass
        if low_status in [401, 403]:
            return False
            
        # If both get 2xx, and structural distance is small, it's a bypass
        if 200 <= high_status < 300 and 200 <= low_status < 300:
            distance = ResponseAnalyzer.calculate_distance(high_text, low_text)
            if distance <= distance_threshold:
                return True
                
        return False
