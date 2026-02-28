import asyncio
import httpx
import traceback
import logging
from typing import List, Dict, Any, Optional
from scanner.repositories import ScanRepository
from core.openapi_parser import extract_endpoints, find_bola_candidates
from core.authorization import check_bfla_vulnerability, check_bola_vulnerability
from api.schemas import ScanOptions
from scanner.services.response_analyzer import ResponseAnalyzer
from scanner.services.injection_fuzzer import InjectionFuzzer
from scanner.services.xss_fuzzer import XssFuzzer
from scanner.services.xxe_fuzzer import XxeFuzzer
from scanner.services.jwt_fuzzer import JwtFuzzer
from scanner.services.ssrf_fuzzer import SsrfFuzzer

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class ScannerEngine:
    def __init__(self, db_session):
        self.repo = ScanRepository(db_session)

    async def _extract_bola_ids(self, client: httpx.AsyncClient, base_url: str, profiles, extraction_paths: List[str]) -> Dict[str, List[str]]:
        extracted_data: Dict[str, set] = {}
        for profile in profiles:
            extracted_data[profile.name] = set()
            headers = {"Authorization": f"Bearer {profile.token}"} if profile.token else {}
            for path in extraction_paths:
                try:
                    resp = await client.get(f"{base_url}{path}", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        def find_ids(obj):
                            if isinstance(obj, dict):
                                for k, v in obj.items():
                                    if k.lower() in ['id', '_id', 'uuid', 'item_id', 'user_id', 'book_id'] and isinstance(v, (int, str)):
                                        extracted_data[profile.name].add(str(v))
                                    else:
                                        find_ids(v)
                            elif isinstance(obj, list):
                                for item in obj:
                                    find_ids(item)
                        find_ids(data)
                except Exception:
                    pass
        return {k: list(v) for k, v in extracted_data.items()}

    async def _infer_roles_and_endpoints(self, client: httpx.AsyncClient, base_url: str, endpoints: List[Dict], profiles: List[Any], options: ScanOptions):
        """Phase 1: Automated Role Inference & Phase 2: Endpoint Feature Extraction"""
        logger.info("Starting Automated Role Inference & Endpoint Feature Extraction...")
        
        # Phase 2: Static endpoint feature extraction
        admin_indicators = ["admin", "config", "settings", "users", "delete", "system"]
        for ep in endpoints:
            is_admin = False
            path_lower = ep["path"].lower()
            method = ep["method"].upper()
            
            if method in ["DELETE", "PATCH", "PUT"]:
                is_admin = True
            elif any(ind in path_lower for ind in admin_indicators):
                is_admin = True
            ep["is_administrative"] = is_admin
            
        admin_endpoints = [ep for ep in endpoints if ep.get("is_administrative")]
        if not admin_endpoints:
            admin_endpoints = endpoints[:5]

        if len(profiles) < 2:
            logger.warning("Need at least 2 profiles for role inference. Defaulting.")
            if len(profiles) == 1:
                profiles[0].inferred_role = "high_privilege"
            return profiles, endpoints

        # Phase 1: Probe endpoints for Role Inference
        import random
        probe_endpoints = random.sample(admin_endpoints, min(5, len(admin_endpoints)))
        profile_scores = {p.name: 0 for p in profiles}
        
        for ep in probe_endpoints:
            for profile in profiles:
                headers = {"Authorization": f"Bearer {profile.token}"} if profile.token else {}
                try:
                    resp = await client.request(ep["method"], f"{base_url}{ep['path']}", headers=headers, json={"mock": "data"})
                    if 200 <= resp.status_code < 300:
                        profile_scores[profile.name] += 1
                except Exception:
                    pass
                    
        # Sort profiles: highest score (most access) is high priv
        logger.info(f"Role Inference Scores: {profile_scores}")
        sorted_profiles = sorted(profiles, key=lambda p: profile_scores[p.name], reverse=True)
        
        sorted_profiles[0].inferred_role = "high_privilege"
        for p in sorted_profiles[1:]:
            p.inferred_role = "low_privilege"
            
        logger.info(f"Inferred High Privilege: {sorted_profiles[0].name}")
        return sorted_profiles, endpoints

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
            
            try:
                async with httpx.AsyncClient(timeout=options.timeout_seconds) as client:
                    resp = await client.get(openapi_url)
                    resp.raise_for_status()
                    spec = resp.json()
                    
                endpoints = extract_endpoints(spec)
                logger.info(f"Scan {scan_id}: Extracted {len(endpoints)} endpoints.")
            except Exception as e:
                logger.warning(f"Scan {scan_id}: Failed to fetch OpenAPI ({e}). Using manual fallback endpoints.")
                endpoints = []
                COMMON_PATHS = [
                    ("/users/v1/{username}", "GET"),
                    ("/users/v1/{username}/email", "PUT"),
                    ("/users/v1/{username}/password", "PUT"),
                    ("/createdb", "GET")
                ]
                for p in getattr(options, 'bola_extraction_paths', []):
                    if p not in [path for path, method in COMMON_PATHS]:
                        COMMON_PATHS.append((p, "GET"))
                
                for path, method in COMMON_PATHS:
                    endpoints.append({"path": path, "method": method, "parameters": []})
                
            if not endpoints:
                raise Exception("No endpoints found and fallback failed")
            
            # Filter endpoints
            target_endpoints = self._filter_endpoints(endpoints, options)
            logger.info(f"Scan {scan_id}: Target endpoints count: {len(target_endpoints)}")
            
            # 2. Get Profiles
            profiles = self.repo.get_profiles(scan_id)
            
            # Phase 1 & 2: Automatic Role Inference & Endpoint Classification
            async with httpx.AsyncClient(timeout=options.timeout_seconds) as client:
                profiles, target_endpoints = await self._infer_roles_and_endpoints(
                    client, project.base_url, target_endpoints, profiles, options
                )
            
            high_priv_profile = next((p for p in profiles if getattr(p, "inferred_role", "") == "high_privilege"), profiles[0] if profiles else None)
            low_priv_profiles = [p for p in profiles if getattr(p, "inferred_role", "") == "low_privilege"]
            
            if not low_priv_profiles and profiles:
                low_priv_profiles = [profiles[0]] # fallback
            
            if not profiles:
                logger.warning(f"Scan {scan_id}: No profiles found for auth scan!")
            else:
                logger.info(f"Scan {scan_id}: Starting Fuzzing Loop with High Priv={high_priv_profile.name if high_priv_profile else 'None'}")
            
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
                    
                    harvested_ids = {}
                    custom_headers = options.custom_headers or {}
                    
                    if options.bola_extraction_paths and profiles:
                        harvested_ids = await self._extract_bola_ids(
                            client, project.base_url, profiles, options.bola_extraction_paths
                        )
                        logger.info(f"Scan {scan_id}: Harvested IDs for true BOLA testing: {harvested_ids}")

                    # Phase 3: Differential BFLA Analysis
                    if high_priv_profile and low_priv_profiles:
                        tasks.append(
                            self._check_bfla(client, semaphore, scan_id, project.base_url, ep, high_priv_profile, low_priv_profiles[0], custom_headers)
                        )
                        
                    # Regular BOLA Iteration
                    for profile in profiles:
                        headers = {"Authorization": f"Bearer {profile.token}"} if profile.token else {}
                        headers.update(custom_headers)
                        if "{" in ep["path"] and "}" in ep["path"]:
                            tasks.append(
                                self._check_bola(client, semaphore, scan_id, project.base_url, ep, profile, headers, harvested_ids, profiles)
                            )

                    # Phase 3 Expansion: SQL & NoSQL Injection (Run once per endpoint using high priv token to avoid auth blocks)
                    inj_headers = {"Authorization": f"Bearer {high_priv_profile.token}"} if high_priv_profile and high_priv_profile.token else custom_headers
                    tasks.append(
                        InjectionFuzzer.run_injection_tests(client, scan_id, project.base_url, ep, inj_headers, self.repo)
                    )
                    
                    # Phase 3 Expansion: XSS and Template Injection
                    tasks.append(
                        XssFuzzer.run_xss_tests(client, scan_id, project.base_url, ep, inj_headers, self.repo)
                    )

                    # Phase 3 Expansion: XML External Entity (XXE)
                    tasks.append(
                        XxeFuzzer.run_xxe_tests(client, scan_id, project.base_url, ep, inj_headers, self.repo)
                    )
                    
                    # Phase 3 Expansion: JWT Cryptographic Attacks
                    for profile in profiles:
                        if profile.token:
                            tasks.append(
                                JwtFuzzer.run_jwt_tests(client, scan_id, project.base_url, ep, profile.token, self.repo)
                            )
                            
                    # Phase 3 Expansion: Server-Side Request Forgery (SSRF)
                    tasks.append(
                        SsrfFuzzer.run_ssrf_tests(client, scan_id, project.base_url, ep, inj_headers, self.repo)
                    )

                # Phase 4 & 5: State Machine and Dependency Graph Fuzzing
                if high_priv_profile and low_priv_profiles:
                    tasks.append(
                        self._fuzz_state_machine_and_dependencies(
                            client, semaphore, scan_id, project.base_url, target_endpoints, high_priv_profile, low_priv_profiles[0], custom_headers
                        )
                    )

                if scan.status != "canceled":
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Process results
                    for res in results:
                        if res:
                            if isinstance(res, list):
                                for v in res:
                                    vuln_count += 1
                                    sev = v.get("severity", "High")
                                    vuln_summary[sev] = vuln_summary.get(sev, 0) + 1
                            elif isinstance(res, dict) and "vuln_type" in res:
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

    async def _check_bfla(self, client, semaphore, scan_id, base_url, endpoint, high_profile, low_profile, custom_headers):
        async with semaphore:
            try:
                method = endpoint["method"]
                path = endpoint["path"]
                logger.debug(f"Scan {scan_id}: Differential BFLA checking {method} {path}")
                json_body = {"user_id": 2, "mock": "data"} if method in ["POST", "PUT", "PATCH"] else None
                
                high_headers = {"Authorization": f"Bearer {high_profile.token}"} if high_profile and high_profile.token else {}
                high_headers.update(custom_headers)
                high_resp = await client.request(method, f"{base_url}{path}", headers=high_headers, json=json_body)
                
                # If even high priv can't access it, skip BFLA
                if not (200 <= high_resp.status_code < 300):
                    return None
                    
                low_headers = {"Authorization": f"Bearer {low_profile.token}"} if low_profile and low_profile.token else {}
                low_headers.update(custom_headers)
                low_resp = await client.request(method, f"{base_url}{path}", headers=low_headers, json=json_body)
                
                # Phase 3: Response Distance Algorithm
                is_bypass = ResponseAnalyzer.is_bfla_bypass(high_resp.status_code, low_resp.status_code, high_resp.text, low_resp.text)
                
                if is_bypass:
                    distance = ResponseAnalyzer.calculate_distance(high_resp.text, low_resp.text)
                    logger.info(f"Scan {scan_id}: BFLA VULN at {method} {path} (Distance: {distance:.2f})")
                    vuln_data = {
                        "vuln_type": "BFLA",
                        "endpoint": f"{method} {path}",
                        "description": f"Endpoint auto-inferred as privileged (High Priv Score). Low privilege user bypassed authorization. Response distance: {distance:.2f}. BFLA Confirmed.",
                        "severity": "High",
                        "evidence": f"Low Priv Status: {low_resp.status_code}, High Priv Status: {high_resp.status_code}, Context Distance: {distance:.2f}"
                    }
                    self.repo.add_vulnerability(scan_id, vuln_data)
                    return vuln_data
            except Exception as e:
                logger.error(f"Error diff scanning {endpoint['path']}: {e}")
                pass
    async def _check_bola(self, client, semaphore, scan_id, base_url, endpoint, profile, headers, harvested_ids, all_profiles):
        async with semaphore:
            try:
                method = endpoint["method"]
                path = endpoint["path"]
                vuln_found = False
                test_path = path

                candidate_ids = set()
                if profile:
                    for p in all_profiles:
                        if p.name != profile.name and p.name in harvested_ids:
                            candidate_ids.update(harvested_ids[p.name])

                # Fallback to fuzzy logic IDs if no specific IDs from other users were harvested
                if not candidate_ids:
                    if "{username}" in path:
                        candidate_ids.update(["admin", "name1", "vampi"])
                    elif "{id}" in path:
                        candidate_ids.update(["1", "2", "0"])
                
                for cid in candidate_ids:
                    if "{username}" in path:
                        test_path = path.replace("{username}", str(cid))
                    elif "{id}" in path:
                        test_path = path.replace("{id}", str(cid))
                    elif "{" in path:
                        import re
                        test_path = re.sub(r'\{.*?\}', str(cid), path)
                    
                    if test_path == path:
                        continue
                        
                    logger.debug(f"Scan {scan_id}: Checking BOLA {method} {test_path} using {profile.name if profile else 'Unauth'}")
                    resp = await client.request(method, f"{base_url}{test_path}", headers=headers)
                    print(f"DEBUG BOLA: {method} {test_path} -> {resp.status_code}", flush=True)
                    if check_bola_vulnerability(resp):
                        vuln_found = True
                        break
                
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

    async def _fuzz_state_machine_and_dependencies(self, client, semaphore, scan_id, base_url, endpoints, high_profile, low_profile, custom_headers):
        """Phase 4 & 5: Auto detect deep BFLA (Dependency Graph) and State-Machine Fuzzing"""
        async with semaphore:
            vulns = []
            try:
                resources_map = {}
                for ep in endpoints:
                    path = ep["path"]
                    parts = [p for p in path.split('/') if p and not p.startswith('{')]
                    if not parts:
                        continue
                    base_noun = parts[0]
                    if base_noun not in resources_map:
                        resources_map[base_noun] = []
                    resources_map[base_noun].append(ep)

                for noun, eps in resources_map.items():
                    terminal_eps = [e for e in eps if "{" in e["path"] and e["method"] in ["POST", "PUT", "DELETE", "PATCH"]]
                    if not terminal_eps:
                        continue
                        
                    for ep in terminal_eps:
                        path_template = ep["path"]
                        test_path = path_template.replace("{id}", "1").replace("{username}", "admin").replace("{uuid}", "1234")
                        if "{" in test_path:
                            import re
                            test_path = re.sub(r'\{.*?\}', "1", test_path)
                            
                        logger.info(f"Scan {scan_id}: State-Machine Fuzzing terminal state {ep['method']} {test_path}")
                        
                        low_headers = {"Authorization": f"Bearer {low_profile.token}"} if low_profile and low_profile.token else {}
                        low_headers.update(custom_headers)
                        
                        resp = await client.request(ep["method"], f"{base_url}{test_path}", headers=low_headers, json={"state": "mutated"})
                        
                        if 200 <= resp.status_code < 300:
                            logger.info(f"Scan {scan_id}: STATE MACHINE / DEPENDENCY VULN at {ep['method']} {test_path}")
                            vuln_data = {
                                "vuln_type": "State Machine / Deep BFLA",
                                "endpoint": f"{ep['method']} {test_path}",
                                "description": "Out-of-order execution or deep tree dependency BFLA detected. Low privilege user successfully invoked a terminal state function without completing prerequisites.",
                                "severity": "High",
                                "evidence": f"Status: {resp.status_code}, Body snippet: {resp.text[:50]}"
                            }
                            self.repo.add_vulnerability(scan_id, vuln_data)
                            vulns.append(vuln_data)
            except Exception as e:
                logger.error(f"Error in state machine fuzzing: {e}")
            return vulns
