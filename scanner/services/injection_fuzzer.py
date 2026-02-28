import json
import logging
import asyncio
import time
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class InjectionFuzzer:
    SQL_ERROR_PAYLOADS = ["'", "\"", "\\", "';--", "\");--"]
    SQL_BOOLEAN_PAYLOADS = ["' OR 1=1--", "\" OR 1=1--", "' OR 'a'='a", "admin' --"]
    SQL_TIME_PAYLOADS = ["WAITFOR DELAY '0:0:5'", "sleep(5)", "pg_sleep(5)"]
    
    NOSQL_JSON_PAYLOADS = [
        {"$gt": ""},
        {"$ne": None},
        {"$where": "sleep(5000)"}
    ]

    @staticmethod
    async def run_injection_tests(client, scan_id: int, base_url: str, endpoint: Dict[str, Any], headers: Dict[str, str], repo) -> List[Dict]:
        vulns = []
        method = endpoint["method"]
        path = endpoint["path"]
        
        # Test Query Parameters if any, or Path Parameters 
        # For simplicity, we inject into path parameters if they exist
        test_path = path
        if "{" in test_path:
            # Try path injection
            for payload in InjectionFuzzer.SQL_BOOLEAN_PAYLOADS:
                import re
                injected_path = re.sub(r'\{.*?\}', payload, path)
                if injected_path != path:
                    try:
                        resp = await client.request(method, f"{base_url}{injected_path}", headers=headers)
                        # Basic boolean check: If we magically get a 200 or 201 with ' OR 1=1
                        # And we're assuming the base case (without injection) might be 404 or 401
                        if 200 <= resp.status_code < 300:
                            logger.info(f"Scan {scan_id}: Possible SQLi (Boolean/Path) at {method} {injected_path}")
                            vuln_data = {
                                "vuln_type": "SQL Injection",
                                "endpoint": f"{method} {path}",
                                "description": f"Boolean-based SQL Injection detected via path parameter payload: {payload}",
                                "severity": "Critical",
                                "evidence": f"Status: {resp.status_code}, Payload: {payload}"
                            }
                            repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
                            break # Don't flood
                    except Exception as e:
                        pass
        
        # Test JSON Body Injection for POST/PUT/PATCH
        if method in ["POST", "PUT", "PATCH"]:
            for payload in InjectionFuzzer.NOSQL_JSON_PAYLOADS:
                # Target typical fields
                json_body = {
                    "username": payload,
                    "password": "password",
                    "email": payload,
                    "id": payload
                }
                
                try:
                    start_time = time.time()
                    resp = await client.request(method, f"{base_url}{path}", headers=headers, json=json_body)
                    elapsed = time.time() - start_time
                    
                    if elapsed > 4.0 and "sleep" in str(payload):
                         logger.info(f"Scan {scan_id}: NoSQL Time-based Injection at {method} {path}")
                         vuln_data = {
                             "vuln_type": "NoSQL Injection (Time-based)",
                             "endpoint": f"{method} {path}",
                             "description": "Time-based NoSQL Injection detected via JSON body '$where' operator.",
                             "severity": "Critical",
                             "evidence": f"Response took {elapsed:.2f}s with payload {payload}"
                         }
                         repo.add_vulnerability(scan_id, vuln_data)
                         vulns.append(vuln_data)
                         
                    elif 200 <= resp.status_code < 300 and payload == {"$ne": None}:
                        # If a query successfully returns with $ne None where normal auth needed
                        logger.info(f"Scan {scan_id}: NoSQL Boolean Injection at {method} {path}")
                        vuln_data = {
                             "vuln_type": "NoSQL Injection (Boolean)",
                             "endpoint": f"{method} {path}",
                             "description": "JSON Operator NoSQL Injection detected. The '$ne' or '$gt' payload successfully bypassed normal parameter validation.",
                             "severity": "Critical",
                             "evidence": f"Status: {resp.status_code}, Payload: {payload}"
                        }
                        repo.add_vulnerability(scan_id, vuln_data)
                        vulns.append(vuln_data)
                         
                except Exception as e:
                    pass

        return vulns
