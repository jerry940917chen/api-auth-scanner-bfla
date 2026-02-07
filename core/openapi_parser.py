from typing import List, Dict, Any
import httpx
import json
import sys
print("INTERPRETER:", sys.executable)
def fetch_openapi_spec(url: str) -> Dict[str, Any]:
    """
    從 URL 獲取 OpenAPI 規範 (JSON)。

    Args:
        url (str): OpenAPI JSON 的 URL。

    Returns:
        Dict[str, Any]: 解析後的 OpenAPI 字典。
    """
    try:
        response = httpx.get(url)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"獲取 OpenAPI 規範失敗: {e}")
        return {}

def extract_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    從 OpenAPI 規範中提取端點資訊。

    Args:
        spec (Dict[str, Any]): OpenAPI 規範字典。

    Returns:
        List[Dict[str, Any]]: 端點列表，每個端點包含 path, method, parameters 等資訊。
    """
    endpoints = []
    paths = spec.get("paths", {})
    
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue
            
            endpoint_info = {
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "parameters": details.get("parameters", []),
                "security": details.get("security", [])
            }
            endpoints.append(endpoint_info)
            
    return endpoints

def find_bola_candidates(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    篩選可能存在 BOLA 漏洞的端點 (通常包含路徑參數 ID)。

    Args:
        endpoints (List[Dict[str, Any]]): 所有端點列表。

    Returns:
        List[Dict[str, Any]]: 候選端點列表。
    """
    candidates = []
    for ep in endpoints:
        # 簡單判斷：如果路徑中有 {id} 或類似參數，則視為 BOLA 測試候選
        if "{" in ep["path"] and "}" in ep["path"]:
            candidates.append(ep)
    return candidates
