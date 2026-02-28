from typing import Optional
from httpx import Response

def check_bola_vulnerability(response: Response, expected_status: int = 403) -> bool:
    """
    檢測 BOLA (Broken Object Level Authorization) 漏洞。
    
    當一個非授權用戶嘗試訪問另一個用戶的資源時，我們期望伺服器返回 403 Forbidden (或 401/404)。
    如果伺服器返回 200 OK (且包含數據)，則可能存在 BOLA 漏洞。

    Args:
        response (Response): HTTP 回應物件。
        expected_status (int): 期望的安全狀態碼 (通常為 403)。

    Returns:
        bool: 若發現漏洞返回 True，否則返回 False。
    """
    # 如果狀態碼是 2xx，表示請求成功，這在攻擊模擬中是不應該發生的 (除非資源本身是公開的，但掃描器應針對受保護資源測試)
    if 200 <= response.status_code < 300:
        # 進一步檢查：有時 API 會返回 200 但內容是用戶未登入等錯誤訊息，這裡假設 200 且有內容即為潛在漏洞
        # 可以根據專案需求增加對 Response Body 的檢查
        return True
    
    # 若返回期望的錯誤碼 (如 403, 401) 或 404 (找不到資源，也算是一種隱晦的拒絕)，則視為安全
    if response.status_code in [401, 403, 404]:
        return False

    # 若返回 500 等其他錯誤，通常不視為 BOLA，但可能是不穩定
    return False

def check_bfla_vulnerability(response: Response, expected_status: int = 403) -> bool:
    """
    檢測 BFLA (Broken Function Level Authorization) 漏洞。

    當低權限用戶嘗試訪問高權限 (如管理員) 功能時，期望被拒絕。
    
    Args:
        response (Response): HTTP 回應物件。
        expected_status (int): 期望的安全狀態碼。

    Returns:
        bool: 若發現漏洞返回 True，否則返回 False。
    """
    # 邏輯類似 BOLA，若低權限用戶操作成功 (2xx)，則為漏洞
    if 200 <= response.status_code < 300:
        return True
    
    return False

def check_mass_assignment_vulnerability(response: Response) -> bool:
    """
    檢測 Mass Assignment (批量賦值) 漏洞。
    
    當嘗試注入敏感欄位 (如 is_admin) 時，如果伺服器返回成功 (2xx)，
    且沒有提示非法輸入，則可能存在漏洞。
    """
    if 200 <= response.status_code < 300:
        return True
    return False

def check_rate_limiting_vulnerability(responses: list[Response]) -> bool:
    """
    檢測 Rate Limiting (頻率限制缺失) 漏洞。
    
    如果在短時間內的連續請求中，沒有任何一個請求回傳 429 Too Many Requests，
    則判定為存在頻率限制缺失漏洞。
    """
    for resp in responses:
        if resp.status_code == 429:
            return False # 有觸發限制，安全
    return True # 全部成功，代表無限制，危險

def check_data_exposure_vulnerability(response: Response, sensitive_fields: list[str]) -> list[str]:
    """
    檢測 Excessive Data Exposure (過度資料洩漏) 漏洞。
    
    檢查 JSON 回應中是否包含敏感欄位名稱。
    """
    found_fields = []
    try:
        data = response.json()
        
        def search_sensitive(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(s.lower() in k.lower() for s in sensitive_fields):
                        found_fields.append(k)
                    search_sensitive(v)
            elif isinstance(obj, list):
                for item in obj:
                    search_sensitive(item)
                    
        search_sensitive(data)
    except Exception:
        pass
    
    return list(set(found_fields))

def check_cors_vulnerability(response: Response) -> Optional[str]:
    """
    檢測 CORS (Cross-Origin Resource Sharing) 誤設定。
    """
    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    if allow_origin == "*":
        return "Wildcard Access-Control-Allow-Origin found"
    return None

def check_security_headers_vulnerability(response: Response) -> list[str]:
    """
    檢測缺失的安全性標頭。
    """
    missing = []
    headers = response.headers
    if "X-Content-Type-Options" not in headers:
        missing.append("X-Content-Type-Options")
    if "X-Frame-Options" not in headers:
        missing.append("X-Frame-Options")
    if "Content-Security-Policy" not in headers:
        missing.append("Content-Security-Policy")
    if "Strict-Transport-Security" not in headers:
        missing.append("Strict-Transport-Security")
    return missing

def check_error_exposure_vulnerability(response: Response) -> Optional[str]:
    """
    檢測過度詳細的錯誤訊息 (Verbose Error Messages)。
    """
    if response.status_code >= 500:
        content = response.text.lower()
        indicators = ["stack trace", "traceback", "internal server error:", "exception", "debug_info"]
        for ind in indicators:
            if ind in content:
                return f"Internal details exposed in 5xx error: {ind}"
    return None

def check_unversioned_api_vulnerability(path: str) -> bool:
    """
    檢測 API 是否缺少版本控制 (Improper Inventory Management)。
    """
    import re
    # Check if path contains v1, v2, v3 etc.
    if not re.search(r'/v[0-9]+', path):
        return True
    return False

def check_broken_auth_vulnerability(response: Response) -> bool:
    """
    檢測 Broken Authentication。
    如果一個受保護的資源在沒有提供 Token 的情況下回傳 2xx，則可能存在漏洞。
    """
    if 200 <= response.status_code < 300:
        return True
    return False

def check_ssrf_vulnerability(response: Response) -> bool:
    """
    檢測 SSRF (Server Side Request Forgery)。
    簡易檢測：如果注入 URL 後的回傳包含特定的標籤或結構，則可能存在漏洞。
    """
    # 這裡可以根據實際實驗環境增加檢測邏輯
    # 例如是否存在 metadata 服務的回傳 (AWS/GCP)
    indicators = ["latest/meta-data", "root:", "google-compute-metadata"]
    content = response.text.lower()
    for ind in indicators:
        if ind in content:
            return True
    return False
