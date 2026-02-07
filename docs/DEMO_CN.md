# API 授權漏洞掃描器 (API Auth Scanner) - 演示指南

本指南將引導您完成 API 授權掃描器的演示流程。此演示將模擬對一個易受攻擊的 API (`demo_api`) 進行 BFLA (Broken Function Level Authorization) 漏洞掃描。

## 演示環境架構

*   **Scanner Service**: 核心掃描引擎 (FastAPI + SQLAlchemy + Docker)。
*   **Demo API**: 一個故意包含漏洞的目標 API (端口 8000/8001)。
*   **PostgreSQL/SQLite**: 數據庫 (本 MVP 使用 SQLite 存儲於 Volume)。

## 1. 環境準備 (Prerequisites)

確保您已安裝：
*   **Docker Desktop** (確保 Docker Compose 可用)
*   **PowerShell** (Windows 默認終端)

## 2. 啟動服務 (Start Services)

在項目根目錄下打開終端 (Terminal)，執行以下命令以構建並啟動容器：

```powershell
# 停止舊容器並清空數據 (推薦，確保環境乾淨)
docker-compose down -v

# 構建並後台啟動服務
docker-compose up -d --build
```

等待約 10-20 秒，確保所有服務啟動完畢。您可以使用 `docker-compose ps` 檢查狀態。

## 3. 執行自動化演示腳本 (Run Demo Script)

我們提供了一個 PowerShell 腳本，自動完成以下步驟：
1.  **獲取 Token**: 從 Demo API 登錄 `admin` 和 `alice` (普通用戶)。
2.  **創建項目**: 在掃描器中註冊 Demo API。
3.  **發起掃描**: 配置掃描任務（使用 `alice` 的 Token 測試 `/admin` 路徑）。
4.  **輪詢狀態**: 等待掃描完成。
5.  **獲取報告**: 下載並顯示掃描結果。

執行腳本：

```powershell
./scripts/demo_run.ps1
```

## 4. 驗證結果 (Verification)

腳本執行完畢後，您應該能在終端看到類似以下的輸出：

*   **Status**: `completed`
*   **Vulnerabilities Found**: `2` (或更多)
*   **Severity Counts**: `{"High": 2}`

### 預期發現的漏洞
Demo API 在 `/admin` 路徑下故意留有 BFLA 漏洞，掃描器應檢測到：
1.  `POST /admin/promote` - 普通用戶 `alice` 可以訪問。
2.  `GET /admin/users` - 普通用戶 `alice` 可以訪問。

### 查看詳細報告
您可以通過瀏覽器或 curl 下載完整報告：

*   **JSON 報告**: `http://localhost:8000/scans/1/report.json`
*   **PDF 報告**: `http://localhost:8000/scans/1/report.pdf`

## 6. vAmPI 漏洞環境演示 (Advanced Demo)

除了基礎 Demo，我們還整合了 **OWASP vAmPI** (Vulnerable API) 來演示更真實的攻擊場景。

### 執行 vAmPI 掃描
```powershell
./scripts/demo_scan_vampi.ps1
```

### 預期發現 (Expected Findings)
掃描器應該會檢測到 **BFLA (Broken Function Level Authorization)** 漏洞：
*   **Endpoint**: `/users/v1/_debug`
*   **原因**: 普通用戶 (Guest) 可以訪問應僅限管理員的調試接口。
*   **驗證方式**:
    1.  檢查腳本輸出中的 "Found X BFLA vulnerabilities"。
    2.  查看生成的報告 (JSON/PDF)。
    3.  參考 `docs/demo_env/vampi_test_matrix.md` 查看完整的漏洞對照表。

---
## 7. 常見問題排除 (Troubleshooting)

*   **腳本報錯 "Invalid URI"**: 確保您在正確的項目根目錄下執行命令，並且 Docker 容器正在運行。
*   **找不到漏洞 (Vulnerabilities Found: 0)**:
    *   檢查 `scanner` 容器日誌：`docker-compose logs scanner`。
    *   確保 `demo_api` 容器正常運行且可被 `scanner` 容器訪問 (它們在同一個 Docker 網絡中)。
*   **掃描一直顯示 "running"**:
    *   可能是掃描引擎報錯卡住。您可以嘗試重啟服務：`docker-compose restart scanner`。
