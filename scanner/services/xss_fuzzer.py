import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class XssFuzzer:
    XSS_PAYLOADS = [
        "<script>alert('xss_test')</script>",
        "\"><img src=x onerror=prompt('xss_test') />",
    ]
    
    # Simple SSTI payloads
    SSTI_PAYLOADS = {
        "{{7*7}}": "49",
        "${7*7}": "49"
    }

    @staticmethod
    async def run_xss_tests(client, scan_id: int, base_url: str, endpoint: Dict[str, Any], headers: Dict[str, str], repo) -> List[Dict]:
        vulns = []
        method = endpoint["method"]
        path = endpoint["path"]
        
        # Test Query / Path Parameters
        if "{" in path:
            for payload in XssFuzzer.XSS_PAYLOADS:
                import re
                injected_path = re.sub(r'\{.*?\}', payload, path)
                if injected_path != path:
                    try:
                        resp = await client.request(method, f"{base_url}{injected_path}", headers=headers)
                        # An XSS is only valid if the exact payload is reflected unescaped in the response body
                        if 200 <= resp.status_code < 500 and payload in resp.text:
                            logger.info(f"Scan {scan_id}: XSS VULN FOUND at {method} {injected_path}")
                            vuln_data = {
                                "vuln_type": "Cross-Site Scripting (XSS)",
                                "endpoint": f"{method} {path}",
                                "description": f"Reflected XSS detected! The payload '{payload}' was reflected unaltered in the HTTP response.",
                                "severity": "High",
                                "evidence": f"Payload reflected string: {payload}"
                            }
                            repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
                            break
                    except Exception as e:
                        pass
                        
        # Test JSON Body for POST/PUT/PATCH
        if method in ["POST", "PUT", "PATCH"]:
            # Combine payloads
            all_payloads = XssFuzzer.XSS_PAYLOADS + list(XssFuzzer.SSTI_PAYLOADS.keys())
            
            for payload in all_payloads:
                json_body = {
                    "username": payload,
                    "comment": payload,
                    "description": payload,
                    "email": payload
                }
                
                try:
                    resp = await client.request(method, f"{base_url}{path}", headers=headers, json=json_body)
                    
                    if 200 <= resp.status_code < 500:
                        # Check XSS Reflection
                        if payload in XssFuzzer.XSS_PAYLOADS and payload in resp.text:
                            logger.info(f"Scan {scan_id}: XSS Body Reflection at {method} {path}")
                            vuln_data = {
                                "vuln_type": "Cross-Site Scripting (XSS)",
                                "endpoint": f"{method} {path}",
                                "description": f"JSON body payload '{payload}' was reflected directly into the response.",
                                "severity": "High",
                                "evidence": f"Unescaped payload in response body."
                            }
                            repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
                            break
                            
                        # Check SSTI Evaluation
                        if payload in XssFuzzer.SSTI_PAYLOADS:
                            expected_output = XssFuzzer.SSTI_PAYLOADS[payload]
                            if expected_output in resp.text and payload not in resp.text:
                                logger.info(f"Scan {scan_id}: SSTI Code Execution at {method} {path}")
                                vuln_data = {
                                    "vuln_type": "Server-Side Template Injection (SSTI)",
                                    "endpoint": f"{method} {path}",
                                    "description": f"Template string '{payload}' was dynamically evaluated to '{expected_output}'.",
                                    "severity": "Critical",
                                    "evidence": f"Evaluated mathematical expression observed."
                                }
                                repo.add_vulnerability(scan_id, vuln_data)
                                vulns.append(vuln_data)
                                break
                                
                except Exception as e:
                    pass

        return vulns
