from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from typing import Optional, List
import jwt
import os

app = FastAPI(title="Vulnerable Demo API", version="1.0.0")

# 配置
SECRET_KEY = os.getenv("DEMO_API_SECRET_KEY", "demosecret")
ALGORITHM = os.getenv("DEMO_API_ALGORITHM", "HS256")

# 模擬數據
USERS = {
    1: {"username": "alice", "role": "user"},
    2: {"username": "bob", "role": "user"},
    3: {"username": "admin", "role": "admin"}
}

ACCOUNTS = {
    1001: {"owner_id": 1, "balance": 1000},
    1002: {"owner_id": 2, "balance": 2000}
}

TRANSACTIONS = {
    5001: {"tx_id": 5001, "account_id": 1001, "amount": -100, "note": "Groceries"},
    5002: {"tx_id": 5002, "account_id": 1002, "amount": -50, "note": "Gas"}
}

# 模型
class TransferRequest(BaseModel):
    source_account: int
    dest_account: int
    amount: float

class PromoteRequest(BaseModel):
    user_id: int

# 輔助函數
def create_access_token(data: dict):
    """產生不過期的研究用 Token。"""
    return jwt.encode(data.copy(), SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != 'bearer':
            raise HTTPException(status_code=401, detail="Invalid Auth Scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Token")

# 端點

@app.get("/")
def root():
    return {"message": "Welcome to the Vulnerable Demo API"}

@app.post("/login")
def login(username: str):
    """
    簡化的登入，不檢查密碼，直接發放 Token。
    """
    user = next((u for uid, u in USERS.items() if u["username"] == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 找到 user_id
    user_id = next(uid for uid, u in USERS.items() if u["username"] == username)
    token = create_access_token({"user_id": user_id, "username": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

# --- BOLA Vulnerabilities ---

@app.get("/accounts/{account_id}")
def get_account(account_id: int, user: dict = Depends(get_current_user_token)):
    """
    [BOLA] 獲取帳戶詳情。
    漏洞：未檢查請求的 account_id 是否屬於當前用戶。
    """
    # 正常應該檢查: if ACCOUNTS[account_id]["owner_id"] != user["user_id"]: raise 403
    account = ACCOUNTS.get(account_id)
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # 漏洞點：直接返回數據
    return {"account_id": account_id, **account}

@app.get("/transactions/{tx_id}")
def get_transaction(tx_id: int, user: dict = Depends(get_current_user_token)):
    """
    [BOLA] 獲取交易詳情。
    漏洞：未檢查交易歸屬權。
    """
    tx = TRANSACTIONS.get(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    return tx

@app.post("/transfer")
def transfer(req: TransferRequest, user: dict = Depends(get_current_user_token)):
    """
    [BOLA] 轉帳。
    漏洞：允許用戶指定 source_account，且未檢查該帳戶是否屬於調用者。
    """
    # 漏洞點：直接扣款
    src = ACCOUNTS.get(req.source_account)
    if not src:
         raise HTTPException(status_code=404, detail="Source account not found")
    
    # 這裡省略了餘額檢查邏輯，重點是授權
    return {"status": "success", "message": f"Transferred {req.amount} from {req.source_account} to {req.dest_account}"}

# --- BFLA Vulnerabilities ---

@app.get("/admin/users")
def list_users(user: dict = Depends(get_current_user_token)):
    """
    [BFLA] 列出所有用戶。
    漏洞：雖然路徑包含 /admin，但未驗證用戶角色是否為 admin。
    """
    # 正常應該檢查: if user["role"] != "admin": raise 403
    # 漏洞點：未檢查角色
    return {"users": USERS}

@app.post("/admin/promote")
def promote_user(req: PromoteRequest, user: dict = Depends(get_current_user_token)):
    """
    [BFLA] 提升用戶權限。
    漏洞：普通用戶可調用此管理功能。
    """
    # 漏洞點：未檢查角色
    target_user = USERS.get(req.user_id)
    if target_user:
        target_user["role"] = "admin"
        return {"status": "success", "message": f"User {req.user_id} promoted to admin"}
    return {"status": "error", "message": "User not found"}
