import jwt
from typing import Dict, Any, Optional

def decode_token(token: str, verify: bool = False, key: str = "", algorithms: list = ["HS256"]) -> Dict[str, Any]:
    """
    解碼 JWT Token。
    
    Args:
        token (str): JWT Token 字串。
        verify (bool): 是否驗證簽名。預設為 False (僅解碼 payload)。
        key (str): 若 verify 為 True，需提供密鑰。
        algorithms (list): 允許的演算法列表。

    Returns:
        Dict[str, Any]: 解碼後的 Payload 字典。
    """
    try:
        if verify:
            return jwt.decode(token, key, algorithms=algorithms)
        else:
            return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        # 在實際應用中可能需要記錄錯誤
        print(f"Token 解碼失敗: {e}")
        return {}

def get_user_id_from_token(token: str, id_field: str = "user_id") -> Optional[Any]:
    """
    從 Token 中獲取用戶 ID。

    Args:
        token (str): JWT Token。
        id_field (str): Payload 中代表用戶 ID 的欄位名稱。

    Returns:
        Optional[Any]: 用戶 ID，若未找到則返回 None。
    """
    payload = decode_token(token, verify=False)
    return payload.get(id_field)

def get_user_role_from_token(token: str, role_field: str = "role") -> Optional[str]:
    """
    從 Token 中獲取用戶角色。

    Args:
        token (str): JWT Token。
        role_field (str): Payload 中代表角色的欄位名稱。

    Returns:
        Optional[str]: 用戶角色，若未找到則返回 None。
    """
    payload = decode_token(token, verify=False)
    return payload.get(role_field)
