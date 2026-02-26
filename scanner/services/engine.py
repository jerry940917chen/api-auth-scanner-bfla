import asyncio
import httpx
import traceback
import logging
from typing import List, Dict, Any, Optional
from scanner.repositories import ScanRepository
from core.openapi_parser import extract_endpoints, find_bola_candidates
from core.authorization import check_bfla_vulnerability, check_bola_vulnerability
from api.schemas import ScanOptions

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ScannerEngine:
    def __init__(self, db_session):
        self.repo = ScanRepository(db_session)

    async def run_scan(self, scan_id: int):
        scan = self.repo.get(scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found.")
            return
        
        logger.info(f"Scan {scan_id}: Starting scan execution.")
        
        # Determine options (can be stored in scan model in future, using defaults for now)
        # Determine options 
        if scan.scan_options:
            options = ScanOptions(**scan.scan_options)
        else:
            options = ScanOptions() 
        
        self.repo.update_status(scan_id, "running")
        
        try:
            # 1. Fetch OpenAPI
            project = scan.project
            if not project.base_url:
                raise Exception("Project missing base_url")
            
            openapi_url = project.openapi_url or f"{project.base_url}/openapi.json"
            logger.info(f"Scan {scan_id}: Fetching OpenAPI from {openapi_url}")
            
            async with httpx.AsyncClient(timeout=options.timeout_seconds) as client:
                resp = await client.get(openapi_url)
                resp.raise_for_status()
                spec = resp.json()
                
            endpoints = extract_endpoints(spec)
            logger.info(f"Scan {scan_id}: Extracted {len(endpoints)} endpoints.")

            if not endpoints:
                raise Exception("No endpoints found in OpenAPI spec")
            
            # Filter endpoints
            target_endpoints = self._filter_endpoints(endpoints, options)
            logger.info(f"Scan {scan_id}: Target endpoints count: {len(target_endpoints)}")
            
            # 2. Get Profiles
            profiles = self.repo.get_profiles(scan_id)
            # Simple logic: Need at least one low-priv user (e.g. alice) to test BFLA against admin endpoints
            # For MVP, finding "alice" or first "user" role
            tester_profile = next((p for p in profiles if p.role == "user"), None)
            if not tester_profile and profiles:
                tester_profile = profiles[0] # Fallback
            
            if not tester_profile:
                # No profiles provided, can't auth scan
                logger.warning(f"Scan {scan_id}: No profiles found for auth scan!")
            else:
                logger.info(f"Scan {scan_id}: Using profile '{tester_profile.name}' (role={tester_profile.role}) for BFLA checks.")
            
            # 3. Scanning Loop
            vuln_count = 0
            vuln_summary = {"High": 0, "Medium": 0, "Low": 0}
            
            async with httpx.AsyncClient(timeout=options.timeout_seconds) as client:
                semaphore = asyncio.Semaphore(options.concurrency)
                
                tasks = []
                for ep in target_endpoints:
                    # Check for cancellation before scheduling
                    # We check the DB status fresh
                    self.repo.db.refresh(scan)
                    if scan.status == "canceled":
                        logger.info(f"Scan {scan_id}: Cancellation detected. Stopping scan.")
                        break

                    # Debug prints
                    if tester_profile:
                         print(f"DEBUG: Checking {ep['path']} with profile {tester_profile.name}, options={options.include_paths}", flush=True)

                    if (options.include_paths or "/admin" in ep["path"] or "/debug" in ep["path"]) and tester_profile:
                        # BFLA Check
                        tasks.append(
                            self._check_bfla(
                                client, 
                                semaphore, 
                                scan_id, 
                                project.base_url, 
                                ep, 
                                tester_profile.token
                            )
                        )

                    # BOLA Check
                    if "{" in ep["path"] and "}" in ep["path"] and tester_profile:
                        tasks.append(
                            self._check_bola(
                                client,
                                semaphore,
                                scan_id,
                                project.base_url,
                                ep,
                                tester_profile.token
                            )
                        )

                if scan.status != "canceled":
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Process results
                    for res in results:
                        if res and isinstance(res, dict): # if vuln found
                            vuln_count += 1
                            sev = res.get("severity", "High")
                            vuln_summary[sev] = vuln_summary.get(sev, 0) + 1

            if scan.status != "canceled":
                # Update summary counts manually since we are about to save
                scan.summary_counts = vuln_summary
                self.repo.update_status(scan_id, "completed")
                logger.info(f"Scan {scan_id}: Completed. Found {vuln_count} vulnerabilities.")
            
        except Exception as e:
            traceback.print_exc()
            logger.error(f"Scan {scan_id}: Failed with error: {e}")
            self.repo.update_status(scan_id, "failed", error=str(e))

    def _filter_endpoints(self, endpoints: List[Dict], options: ScanOptions) -> List[Dict]:
        filtered = []
        for ep in endpoints:
            path = ep["path"]
            if options.include_paths:
                if not any(inc in path for inc in options.include_paths):
                    continue
            if options.exclude_paths:
                if any(exc in path for exc in options.exclude_paths):
                    continue
            filtered.append(ep)
        return filtered[:options.max_endpoints]

    async def _check_bfla(self, client, semaphore, scan_id, base_url, endpoint, token):
        async with semaphore:
            try:
                method = endpoint["method"]
                path = endpoint["path"]
                logger.debug(f"Scan {scan_id}: Checking {method} {path}")
                
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                json_body = {"user_id": 2} if method in ["POST", "PUT", "PATCH"] else None
                
                resp = await client.request(
                    method, 
                    f"{base_url}{path}", 
                    headers=headers, 
                    json=json_body
                )
                print(f"DEBUG: {method} {path} -> {resp.status_code}", flush=True)
                
                if check_bfla_vulnerability(resp):
                    logger.info(f"Scan {scan_id}: VULNERABILITY FOUND at {method} {path}")
                    vuln_data = {
                        "vuln_type": "BFLA",
                        "endpoint": f"{method} {path}",
                        "description": "Endpoint accessible by low-privilege user",
                        "severity": "High",
                        "evidence": f"Status: {resp.status_code}"
                    }
                    self.repo.add_vulnerability(scan_id, vuln_data)
                    return vuln_data
            except Exception as e:
                # Log individual endpoint failure but don't fail entire scan
                logger.error(f"Error scanning {endpoint['path']}: {e}")
                pass
    async def _check_bola(self, client, semaphore, scan_id, base_url, endpoint, token):
        async with semaphore:
            try:
                method = endpoint["method"]
                path = endpoint["path"]
                vuln_found = False
                test_path = path
                
                headers = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                
                # Simple BOLA Mutation: Replace {id} or {username} with a known common victim identifier
                if "{username}" in path:
                    # Try a few common usernames in vAmPI
                    for victim in ["admin", "name1", "vampi"]:
                        test_path = path.replace("{username}", victim)
                        logger.debug(f"Scan {scan_id}: Checking BOLA {method} {test_path}")
                        resp = await client.request(method, f"{base_url}{test_path}", headers=headers)
                        print(f"DEBUG BOLA: {method} {test_path} -> {resp.status_code}", flush=True)
                        if check_bola_vulnerability(resp):
                            vuln_found = True
                            break
                elif "{id}" in path:
                    for victim in ["1", "2", "0"]:
                        test_path = path.replace("{id}", victim)
                        logger.debug(f"Scan {scan_id}: Checking BOLA {method} {test_path}")
                        resp = await client.request(method, f"{base_url}{test_path}", headers=headers)
                        if check_bola_vulnerability(resp):
                            vuln_found = True
                            break
                elif "{" in path:
                    import re
                    test_path = re.sub(r'\{.*?\}', "1", path)
                    resp = await client.request(method, f"{base_url}{test_path}", headers=headers)
                    if check_bola_vulnerability(resp):
                        vuln_found = True
                
                if vuln_found:
                    logger.info(f"Scan {scan_id}: BOLA VULNERABILITY FOUND at {method} {test_path}")
                    vuln_data = {
                        "vuln_type": "BOLA",
                        "endpoint": f"{method} {test_path}",
                        "description": "Unauthorized access to object/resource belonging to others",
                        "severity": "High",
                        "evidence": f"Status: {resp.status_code}"
                    }
                    self.repo.add_vulnerability(scan_id, vuln_data)
                    return vuln_data
            except Exception as e:
                logger.error(f"Error scanning BOLA {endpoint['path']}: {e}")
        return None
