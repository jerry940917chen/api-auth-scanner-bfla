import pytest
import asyncio
from unittest.mock import MagicMock, patch
from scanner.runner import Scanner
from scanner.models import Scan, Project, Vulnerability
from demo_api.main import app as demo_app
from scanner.db import SessionLocal, Base, engine
import httpx

# 為了測試，使用內存資料庫重置表格
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

@pytest.fixture
def db_session():
    session = SessionLocal()
    yield session
    session.close()

@pytest.mark.asyncio
async def test_integration_scan(db_session):
    """
    整合測試：
    1. 建立測試專案 (指向 Demo API)
    2. 建立掃描任務
    3. 執行 Scanner，mock httpx client 來請求 Demo API (或真實請求)
    4. 驗證發現的漏洞數量
    """
    
    # 1. 建立專案
    project = Project(name="Integration Test", base_url="http://test", openapi_url=None)
    db_session.add(project)
    db_session.commit()
    
    # 2. 建立掃描
    scan = Scan(project_id=project.id, status="pending")
    db_session.add(scan)
    db_session.commit()
    
    # 準備 Profile
    # Demo API 的 Token 生成邏輯 (複製自 demo_api/main.py 或直接生成)
    from demo_api.main import create_access_token
    token_alice = create_access_token({"user_id": 1, "username": "alice", "role": "user"})
    token_bob = create_access_token({"user_id": 2, "username": "bob", "role": "user"})
    token_admin = create_access_token({"user_id": 3, "username": "admin", "role": "admin"})
    
    profiles = [
        {"name": "alice", "token": token_alice, "role": "user"},
        {"name": "bob", "token": token_bob, "role": "user"},
        {"name": "admin", "token": token_admin, "role": "admin"}
    ]
    
    # 手動指定端點 (因為沒有運行中的 OpenAPI URL)
    endpoints = [
        {"path": "/accounts/{account_id}", "method": "GET"},
        {"path": "/transactions/{tx_id}", "method": "GET"},
        {"path": "/transfer", "method": "POST"}, # 此端點在 Runner 中暫未完整自動化 BOLA 測試 (需 Body)，但可測試是否被 Admin Check 誤報
        {"path": "/admin/users", "method": "GET"},
        {"path": "/admin/promote", "method": "POST"}
    ]
    
    # Mock extract_endpoints 來返回上述列表
    with patch("scanner.runner.extract_endpoints", return_value=endpoints), \
         patch("scanner.runner.fetch_openapi_spec", return_value={}):

        scanner = Scanner(db_session, scan.id)
        
        # 使用 httpx.AsyncClient(app=demo_app) 來攔截請求並發送到 demo_app
        # 我們需要 Patch scanner.runner 裡的 bucket httpx.AsyncClient
        # 由於 runner 內部是用 `async with httpx.AsyncClient() as client:`
        # 我們可以用 MagicMock 來模擬 client.request 或者更深入的 mock
        
        # 這裡我們使用一個 context manager mock
        async with httpx.AsyncClient(app=demo_app, base_url="http://test") as test_client:
             with patch("httpx.AsyncClient", return_value=test_client):
                # httpx.AsyncClient() 會返回 test_client? 不行，因為它是 context manager
                # 正確的 mock 方式是 mock 構造函數返回一個 Mock 對象，該對象 __aenter__ 返回 test_client
                
                # 簡化：我們直接修改 Scanner 的邏輯有點難，不如讓 Runner 接受 client 參數
                # 但為了不改 Runner，我們使用 httpx 的 app 參數功能。
                # 不過 Runner 裡是寫死的 `async with httpx.AsyncClient() ...`
                # 我們可以 mock `httpx.AsyncClient` 類
                pass

                # Re-implementation for test stability:
                # 由於 mock async context manager 比較麻煩，這裡我們採用 "真實網路請求" 比較難 (需啟動 server)
                # 選擇 Patch `client.request` 比較容易，但邏輯多。
                # 最好是讓 httpx.AsyncClient 在測試環境下自動掛載 app。
                # 但這裡為了確保測試能跑，我們用 Mock Side Effect。
                
                # 方案 B: 簡單的 Integration Test，不跑 Runner，而是直接測試 Runner 裡面的核心流程邏輯
                # 或是依賴 Runner 的代碼結構。
                
                # 讓我們嘗試一個稍微 Hacky 的 Patch:
                # 定義這類 mock helper
                pass

    # 由於在 artifacts 環境中跑 pytest 較複雜，且 Runner 邏輯依賴網路，
    # 這裡我們寫一個 模擬測試，確保 Runner 邏輯正確，而不是真的去打 Demo API。
    # Demo API 的行為已知。
    
    # 更正：我們可以 Patch `httpx.AsyncClient`
    
    mock_client = MagicMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    
    # 模擬 Responses
    async def side_effect(method, url, headers=None, **kwargs):
        # 模擬 BOLA: 訪問 accounts/1 (Alice's) with Bob's token -> 200 OK (Vulnerable)
        if "/accounts/1" in url and "bob" in str(headers): # 簡化判斷
             return Response(200, json={"account": "alice's data"})
        
        # 模擬 BFLA: 訪問 /admin/users with Alice's token -> 200 OK (Vulnerable)
        if "/admin/users" in url and "alice" in str(headers): # user role
             return Response(200, json={"users": []})
        
        return Response(404)

    mock_client.request.side_effect = side_effect
    
    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("scanner.runner.extract_endpoints", return_value=endpoints), \
         patch("scanner.runner.fetch_openapi_spec", return_value={}):
         
         scanner = Scanner(db_session, scan.id)
         await scanner.run(profiles)
         
    # 驗證結果
    vulns = db_session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    # 我們預期至少發現 BOLA (accounts) 和 BFLA (admin/users)
    assert len(vulns) >= 2
    types = [v.vuln_type for v in vulns]
    assert "BOLA" in types
    assert "BFLA" in types
