import httpx
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime
import asyncio

from core.openapi_parser import fetch_openapi_spec, extract_endpoints, find_bola_candidates
from core.authorization import check_bola_vulnerability, check_bfla_vulnerability
from core.jwt_utils import get_user_id_from_token
from .models import Scan, Vulnerability, VulnerabilityType, Project
from .db import SessionLocal

class Scanner:
    def __init__(self, db: Session, scan_id: int):
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan with id {scan_id} not found")
        self.project = self.scan.project

    async def run(self, profiles: List[Dict[str, str]]):
        """
        執行掃描任務。
        
        Args:
            profiles (List[Dict]): 用戶設定檔列表，包含 token 和 role。
                                   例如: [{"name": "alice", "token": "...", "role": "user"}]
        """
        print(f"開始掃描 Project: {self.project.name} (Scan ID: {self.scan_id})")
        self.scan.status = "running"
        self.db.commit()

        try:
            # 1. 獲取端點列表
            endpoints = []
            if self.project.openapi_url:
                print(f"Fetching OpenAPI spec from {self.project.openapi_url}")
                spec = fetch_openapi_spec(self.project.openapi_url)
                endpoints = extract_endpoints(spec)
            else:
                # 若無 OpenAPI，這裡可擴展為手動列表或爬蟲，目前簡單略過
                print("No OpenAPI URL provided, skipping automatic discovery.")
                # 但為了 Demo，如果沒提供，我們可以假設一些預設端點 (僅作測試 fallback)
                pass

            # 2. 執行測試
            vulns = []
            
            # 分離 User 和 Admin Token
            users = [p for p in profiles if p.get("role") == "user"]
            admins = [p for p in profiles if p.get("role") == "admin"]
            
            if not users or not admins:
                print("Warning: Need at least one user and one admin for full coverage.")

            # 對每個端點進行測試
            async with httpx.AsyncClient() as client:
                for ep in endpoints:
                    path = ep["path"]
                    method = ep["method"]
                    print(f"Testing {method} {path}...")

                    # BOLA 測試 (針對帶 ID 的路徑)
                    if "{" in path and "}" in path and len(users) >= 2:
                        # 簡單策略：假設路徑中的參數是 id，嘗試用 User A 的 Token 訪問 ID 1 (假設屬於 User A)，
                        # 然後用 User B (User ID 2) 去訪問 User A 的資源 (ID 1)
                        # 這是一個簡化的 Demo 邏輯
                        
                        target_id = 1 # 假設 User 1 的資源 ID 為 1
                        attacker = users[1] # User 2
                        victim = users[0] # User 1
                        
                        test_url = f"{self.project.base_url}{path.replace('{account_id}', str(target_id)).replace('{tx_id}', str(target_id)).replace('{user_id}', str(target_id))}"
                        # 簡單替換常見參數名，實際應更強大
                        if "{" in test_url: # 若還有未替換的，嘗試替換通用 {id}
                             test_url = test_url.replace('{id}', str(target_id))

                        # 執行攻擊請求
                        headers = {"Authorization": f"Bearer {attacker['token']}"}
                        try:
                            resp = await client.request(method, test_url, headers=headers)
                            
                            is_vuln = check_bola_vulnerability(resp)
                            if is_vuln:
                                v = Vulnerability(
                                    scan_id=self.scan.id,
                                    vuln_type=VulnerabilityType.BOLA,
                                    endpoint=f"{method} {path}",
                                    description=f"User {attacker['name']} could access resource of another user at {test_url}",
                                    evidence=f"Request to {test_url} with User {attacker['name']} token returned {resp.status_code}. Body: {resp.text[:200]}...",
                                    severity="High"
                                )
                                self.db.add(v)
                                self.db.commit()
                                print(f"FOUND BOLA at {path}")
                        except Exception as e:
                            print(f"Error testing BOLA on {path}: {e}")

                    # BFLA 測試 (針對 Admin 路徑)
                    if "/admin" in path and users:
                        attacker = users[0] # 普通用戶
                        test_url = f"{self.project.base_url}{path}"
                        headers = {"Authorization": f"Bearer {attacker['token']}"}
                        
                        # 對於 POST/PUT，可能需要 Body。Demo 中簡單處理，若需要 Body 則可能失敗，
                        # 但如果 BFLA 存在，伺服器可能在驗證 Body 前就通過了 Auth 檢查 (或 Body 隨便給)
                        # 這裡簡單給個空 Body 或 dummy
                        json_body = {} 
                        if method in ["POST", "PUT"]:
                             json_body = {"user_id": 2} # 針對 promote 端點的猜測

                        try:
                            resp = await client.request(method, test_url, headers=headers, json=json_body)
                            
                            is_vuln = check_bfla_vulnerability(resp)
                            if is_vuln:
                                v = Vulnerability(
                                    scan_id=self.scan.id,
                                    vuln_type=VulnerabilityType.BFLA,
                                    endpoint=f"{method} {path}",
                                    description=f"Normal user {attacker['name']} could access admin endpoint {path}",
                                    evidence=f"Request to {test_url} with normal user token returned {resp.status_code}. Body: {resp.text[:200]}...",
                                    severity="High"
                                )
                                self.db.add(v)
                                self.db.commit()
                                print(f"FOUND BFLA at {path}")
                        except Exception as e:
                             print(f"Error testing BFLA on {path}: {e}")

            self.scan.status = "completed"
            self.scan.completed_at = datetime.utcnow()
            self.db.commit()
            print("掃描完成。")

        except Exception as e:
            print(f"掃描發生錯誤: {e}")
            self.scan.status = "failed"
            self.db.commit()
        finally:
            self.db.close()

async def run_scan_task(scan_id: int, profiles: List[Dict]):
    """
    非同步任務包裝器，用於在後台執行掃描。
    """
    db = SessionLocal()
    scanner = Scanner(db, scan_id)
    await scanner.run(profiles)
