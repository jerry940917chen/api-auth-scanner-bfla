class RemediationService:
    """
    Merges AI-generated content with static fallback templates to produce
    complete remediation data for each vulnerability finding.
    """

    STATIC_TEMPLATES = {
        "BFLA": {
            "title": "Broken Function Level Authorization (BFLA) — API1:2023",
            "business_impact": "攻擊者可以用普通用戶身份呼叫管理功能，導致帳號提權、資料竄改或系統控制。對企業造成法規違規（如 GDPR、PCI-DSS）和聲譽損失。",
            "root_cause": "API 端點未在伺服器端驗證調用者的角色權限，僅依賴前端隱藏按鈕或 UI 限制，未實施真正的後端授權檢查。",
            "technical_analysis": "掃描器使用低權限 token 成功呼叫應僅限管理員的端點，伺服器返回 200 OK 而非 403 Forbidden，確認後端缺少角色驗證邏輯。",
            "remediation_steps": "1. 在每個敏感端點加入角色檢查 decorator\n2. 建立集中式權限中介層 (middleware)\n3. 採用 RBAC（角色存取控制）框架\n4. 定期進行授權邏輯的 Code Review\n5. 在 CI/CD 中加入自動化授權測試",
            "code_example": "```python\n# FastAPI 範例：正確的角色檢查\nfrom fastapi import Depends, HTTPException\n\ndef require_admin(current_user = Depends(get_current_user)):\n    if current_user.role != 'admin':\n        raise HTTPException(status_code=403, detail='Admin only')\n    return current_user\n\n@router.get('/admin/users')\ndef get_users(admin = Depends(require_admin)):\n    return db.query(User).all()\n```",
            "compliance_standards": "OWASP API1:2023 (Broken Object Level Authorization) | PCI-DSS Req 6.4.1 (Protect against unauthorized access) | NIST SP 800-53 AC-3 (Access Enforcement)",
            "priority": "Immediate"
        },
        "BOLA": {
            "title": "Broken Object Level Authorization (BOLA) — API1:2023",
            "business_impact": "攻擊者可以遍歷 ID 存取任意用戶的資料，導致大規模個資洩漏，違反 GDPR 等法規，面臨高額罰款。",
            "root_cause": "API 在處理請求時，只驗證用戶是否已登錄，未驗證請求中的資源 ID 是否屬於該用戶。",
            "technical_analysis": "攻擊者只需修改 URL 中的物件 ID（如 /users/123 改為 /users/124）即可存取他人資料，伺服器無任何阻攔。",
            "remediation_steps": "1. 在每次資料查詢時加入 owner 驗證\n2. 使用 UUID 替代自增 ID\n3. 建立資源擁有者中介層\n4. 記錄所有跨用戶存取嘗試\n5. 定期滲透測試驗證修復效果",
            "code_example": "```python\n# 正確做法：查詢時加入 user_id 過濾\n@router.get('/items/{item_id}')\ndef get_item(item_id: int, current_user = Depends(get_current_user), db = Depends(get_db)):\n    item = db.query(Item).filter(\n        Item.id == item_id,\n        Item.owner_id == current_user.id  # 關鍵：驗證擁有者\n    ).first()\n    if not item:\n        raise HTTPException(404, 'Not found')\n    return item\n```",
            "compliance_standards": "OWASP API1:2023 | GDPR Article 25 (Data Protection by Design) | ISO 27001 A.9.4 (Access Control)",
            "priority": "Immediate"
        },
        "Data Exposure": {
            "title": "Excessive Data Exposure — API3:2023",
            "business_impact": "敏感資料（如密碼雜湊、個人識別資訊）暴露給未授權用戶，違反 GDPR 個資保護規範，並為後續攻擊提供情報。",
            "root_cause": "API 直接回傳資料庫物件的所有欄位，未經過過濾，依賴前端來決定顯示哪些欄位。",
            "technical_analysis": "API 回應包含技術性敏感欄位（如 password_hash、internal_id、admin_flag），攻擊者可利用這些資訊進行後續攻擊。",
            "remediation_steps": "1. 定義並使用回應 Schema（只包含必要欄位）\n2. 在後端過濾，不依賴前端\n3. 使用 Pydantic response_model 自動過濾\n4. 定期稽核 API 回應內容\n5. 對敏感欄位加密或遮罩",
            "code_example": "```python\n# 使用 Pydantic 過濾回應\nclass UserPublic(BaseModel):  # 只暴露安全的欄位\n    id: int\n    username: str\n    email: str\n    # 注意：沒有 password, role, internal_id\n\n@router.get('/users', response_model=List[UserPublic])\ndef get_users(db = Depends(get_db)):\n    return db.query(User).all()  # Pydantic 自動過濾\n```",
            "compliance_standards": "OWASP API3:2023 | GDPR Article 5(1)(c) (Data Minimization) | PCI-DSS Req 3.4 (Protect stored cardholder data)",
            "priority": "High"
        },
        "Missing Security Headers": {
            "title": "Missing Security Headers — 安全標頭缺失",
            "business_impact": "缺少安全標頭使 API 易受 XSS、Clickjacking 等瀏覽器層面攻擊，並可能使攻擊者利用 MIME 嗅探進行資料竊取。",
            "root_cause": "伺服器未設定現代安全標頭，OWASP 建議的最小標頭集合未被實施。",
            "technical_analysis": "HTTP 回應缺少 X-Content-Type-Options、X-Frame-Options、Strict-Transport-Security 等關鍵標頭，使瀏覽器安全策略失效。",
            "remediation_steps": "1. 在 API 框架層加入安全標頭中介層\n2. 設定 HSTS（強制 HTTPS）\n3. 設定 Content-Security-Policy\n4. 設定 X-Frame-Options: DENY\n5. 使用掃描工具定期驗證標頭",
            "code_example": "```python\n# FastAPI 中加入安全標頭中介層\nfrom fastapi.middleware import Middleware\nfrom starlette.middleware.base import BaseHTTPMiddleware\n\nclass SecurityHeadersMiddleware(BaseHTTPMiddleware):\n    async def dispatch(self, request, call_next):\n        response = await call_next(request)\n        response.headers['X-Content-Type-Options'] = 'nosniff'\n        response.headers['X-Frame-Options'] = 'DENY'\n        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n        response.headers['X-XSS-Protection'] = '1; mode=block'\n        return response\n```",
            "compliance_standards": "OWASP API7:2023 (Security Misconfiguration) | NIST SP 800-44 (Web Server Security) | CIS Benchmark for Web Servers",
            "priority": "Medium"
        },
        "Improper Inventory Management": {
            "title": "Improper Inventory Management — API9:2023",
            "business_impact": "未記錄的 API 端點（Shadow API）繞過安全管控，使攻擊者可透過舊版/測試端點進行未授權操作。",
            "root_cause": "API 文件（如 OpenAPI spec）未全面涵蓋所有啟用的端點，或開發環境端點被意外暴露在生產環境。",
            "technical_analysis": "掃描器發現可存取但未在 API 文件中記錄的端點，表示存在影子 API，這些端點通常缺少安全審查。",
            "remediation_steps": "1. 建立完整的 API 清單並持續更新\n2. 廢棄舊版 API 端點\n3. 在生產環境中停用開發/測試端點\n4. 實施 API 網關統一管理所有流量\n5. 定期掃描未記錄的端點",
            "code_example": "```python\n# 在生產環境中停用文件端點\nimport os\napp = FastAPI(\n    docs_url='/docs' if os.getenv('ENV') != 'production' else None,\n    redoc_url='/redoc' if os.getenv('ENV') != 'production' else None,\n    openapi_url='/openapi.json' if os.getenv('ENV') != 'production' else None\n)\n```",
            "compliance_standards": "OWASP API9:2023 (Improper Inventory Management) | ISO 27001 A.12.6 (Technical Vulnerability Management) | PCI-DSS Req 6.2",
            "priority": "Low"
        },
    }

    @staticmethod
    def get_remediation(vuln_type: str, endpoint: str = "", llm_content: dict = None) -> dict:
        """
        Merges AI-generated content with static templates.
        AI content takes priority; static templates are fallback.
        """
        base = RemediationService.STATIC_TEMPLATES.get(vuln_type, {
            "title": vuln_type,
            "business_impact": "此漏洞可能導致未授權操作或敏感資料洩漏，請聯繫安全專家進行人工評估。",
            "root_cause": "API 端點存在安全設計缺陷。",
            "technical_analysis": "基於自動化掃描行為特徵判定。",
            "remediation_steps": "1. 識別漏洞根因\n2. 實施適當的存取控制\n3. 加入輸入驗證\n4. 進行安全代碼審查\n5. 部署後驗證修復效果",
            "code_example": "# 請根據具體漏洞類型參考 OWASP 修復指南",
            "compliance_standards": "OWASP API Security Top 10 | NIST Cybersecurity Framework",
            "priority": "High"
        })

        if llm_content and isinstance(llm_content, dict):
            # Merge AI content over static base — AI wins unless field is empty
            return {
                "title": base.get("title", vuln_type),
                "business_impact": llm_content.get("business_impact") or base.get("business_impact", ""),
                "root_cause": llm_content.get("root_cause") or base.get("root_cause", ""),
                "technical_analysis": llm_content.get("technical_analysis") or base.get("technical_analysis", ""),
                "remediation_steps": llm_content.get("remediation_steps") or base.get("remediation_steps", ""),
                "code_example": llm_content.get("code_example") or base.get("code_example", ""),
                "compliance_standards": llm_content.get("compliance_standards") or base.get("compliance_standards", ""),
                "priority": llm_content.get("priority") or base.get("priority", "High"),
                "solution": llm_content.get("remediation_steps") or base.get("remediation_steps", ""),  # legacy compat
                "best_practice": llm_content.get("compliance_standards") or base.get("compliance_standards", ""),
                "impact": llm_content.get("business_impact") or base.get("business_impact", ""),
            }

        # Static fallback — add legacy keys for template compat
        result = dict(base)
        result["solution"] = base.get("remediation_steps", "")
        result["best_practice"] = base.get("compliance_standards", "")
        result["impact"] = base.get("business_impact", "")
        return result
