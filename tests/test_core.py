import pytest
from httpx import Response
from core.authorization import check_bola_vulnerability, check_bfla_vulnerability
from core.jwt_utils import decode_token

def test_check_bola_vulnerability():
    # 測試：未授權訪問成功 (200 OK) -> 應檢測為漏洞
    response = Response(200, json={"data": "sensitive"})
    assert check_bola_vulnerability(response) is True

    # 測試：未授權訪問被拒絕 (403 Forbidden) -> 應視為安全
    response = Response(403)
    assert check_bola_vulnerability(response) is False

    # 測試：找不到資源 (404) -> 應視為安全 (或至少非 BOLA)
    response = Response(404)
    assert check_bola_vulnerability(response) is False

def test_check_bfla_vulnerability():
    # 測試：普通用戶訪問 Admin 頁面成功 (200 OK) -> 漏洞
    response = Response(200, json={"admin": "data"})
    assert check_bfla_vulnerability(response) is True

    # 測試：被拒絕 (403) -> 安全
    response = Response(403)
    assert check_bfla_vulnerability(response) is False

def test_jwt_utils():
    # 這裡僅測試解碼邏輯 (不驗證簽名，因為沒密鑰)
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoidXNlciJ9.signature_ignored"
    decoded = decode_token(token, verify=False)
    assert decoded["user_id"] == 1
    assert decoded["role"] == "user"
