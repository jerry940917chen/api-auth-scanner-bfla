import httpx
import asyncio
from datetime import datetime
from typing import List, Dict
from sqlalchemy.orm import Session
import sys
from pathlib import Path

# 確保相對匯入正常
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.openapi_parser import fetch_openapi_spec, extract_endpoints
from core.authorization import check_bola_vulnerability, check_bfla_vulnerability
from scanner.models import Scan, Vulnerability, VulnerabilityType
from scanner.db import SessionLocal

class Scanner:
    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan with id {scan_id} not found")
        self.project = self.scan.project

    async def run(self, profiles: List[Dict[str, str]]):
        self.scan.status = "running"
        self.db.commit()

        try:
            endpoints = []
            if self.project.openapi_url:
                spec = fetch_openapi_spec(self.project.openapi_url)
                endpoints = extract_endpoints(spec)

            users = [p for p in profiles if p.get("role") == "user"]
            admins = [p for p in profiles if p.get("role") == "admin"]

            async with httpx.AsyncClient() as client:
                for ep in endpoints:
                    path = ep["path"]
                    method = ep["method"]

                    # BOLA 檢測
                    if "{" in path and "}" in path and len(users) >= 2:
                        target_id = 1
                        attacker = users[1]
                        test_url = f"{self.project.base_url}{path}"
                        test_url = (
                            test_url.replace("{account_id}", str(target_id))
                                    .replace("{tx_id}", str(target_id))
                                    .replace("{user_id}", str(target_id))
                                    .replace("{id}", str(target_id))
                        )

                        headers = {"Authorization": f"Bearer {attacker['token']}"}
                        resp = await client.request(method, test_url, headers=headers)

                        if check_bola_vulnerability(resp):
                            v = Vulnerability(
                                scan_id=self.scan.id,
                                vuln_type=VulnerabilityType.BOLA.value,
                                endpoint=f"{method} {path}",
                                description=f"User {attacker['name']} could access {test_url}",
                                evidence=f"{resp.status_code} {resp.text[:200]}...",
                                severity="High",
                            )
                            self.db.add(v)
                            self.db.commit()

                    # BFLA 檢測
                    if "/admin" in path and users:
                        attacker = users[0]
                        test_url = f"{self.project.base_url}{path}"
                        headers = {"Authorization": f"Bearer {attacker['token']}"}
                        json_body = {"user_id": 2} if method in ["POST", "PUT"] else None

                        resp = await client.request(method, test_url, headers=headers, json=json_body)
                        if check_bfla_vulnerability(resp):
                            v = Vulnerability(
                                scan_id=self.scan.id,
                                vuln_type=VulnerabilityType.BFLA.value,
                                endpoint=f"{method} {path}",
                                description=f"Normal user accessed admin endpoint {path}",
                                evidence=f"{resp.status_code} {resp.text[:200]}...",
                                severity="High",
                            )
                            self.db.add(v)
                            self.db.commit()

            self.scan.status = "completed"
            self.scan.completed_at = datetime.utcnow()
            self.db.commit()

        except Exception as e:
            self.scan.status = "failed"
            self.db.commit()
            raise
        finally:
            self.db.close()

def run_scan_task(scan_id: int, profiles: List[Dict]):
    """同步包裝器，用於 BackgroundTasks"""
    db = SessionLocal()
    scanner = Scanner(db, scan_id)
    asyncio.run(scanner.run(profiles))