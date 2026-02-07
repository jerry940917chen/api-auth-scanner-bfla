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
