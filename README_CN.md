# API 授權漏洞掃描器：研究原型 (API Authorization Vulnerability Scanner)

> **狀態**: 研究原型 (碩士論文級)  
> **重點**: 越權功能級授權 (BFLA) 與 BOLA 檢測  
> **版本**: 1.0.0

## 1. 摘要 (Abstract)

本倉庫包含了一個自動化 API 安全掃描器的實作，旨在研究 **越權功能級授權 (BFLA)** 的檢測。與依賴模糊測試 (Fuzzing) 的傳統 DAST 工具不同，本掃描器實作了一個基於角色的狀態分析引擎，通過將有效的使用者權限與特權端點訪問進行交叉比對，來檢測授權邏輯缺陷。

系統採用容器化設計，並包含一個自定義的易受攻擊目標 (`demo_api`) 以及與 **OWASP vAmPI** 的整合，以在受控環境中演示檢測能力。

## 2. 方法論 (Methodology)

本掃描器基於 **主體-代理模型 (Principal-Agent Model)** 來驗證授權策略：
1.  **策略攝取**: 解析 OpenAPI (Swagger) 規範以建立端點地圖。
2.  **角色側寫**: 接受多個具有有效憑證的使用者設定檔（例如：`User`、`Admin`）。
3.  **跨情境重放 (Cross-Context Replay)**:
    *   擷取特權使用者 (Admin) 的基準請求。
    *   使用非特權使用者 (Guest/User) 的會話令牌 (Session Token) 重放嚴格定義的請求。
    *   分析 HTTP 狀態碼和回應結構，以識別未經授權的成功狀態（策略執行中的偽陰性）。

## 3. 倉庫結構 (Repository Structure)

```
├── scanner/           # 核心掃描引擎 (FastAPI + Python)
│   ├── services/      # 掃描邏輯與啟發式算法
│   └── models/        # SQLAlchemy ORM 模型
├── demo_api/          # 特意設計的易受攻擊銀行 API (測試目標)
├── scripts/           # 用於實驗與演示的自動化腳本
├── docs/              # 研究文檔與測試矩陣
│   ├── demo_env/      # vAmPI 與 Demo 目標規格
│   └── thesis/        # (可選) 擴展方法論筆記
├── data/              # 運行時數據庫存儲 (Git 忽略)
├── docker-compose.yml # 用於可重現實驗的編排文件
└── requirements.txt   # Python 依賴
```

## 4. 可重現性 (Reproducibility)

本實驗設計為可使用 Docker Compose 完全重現。

### 前置需求
*   Docker & Docker Compose
*   PowerShell (或 Linux/Mac 的 Bash，提供的腳本為 PS1 格式)

### 設置與執行

1.  **初始化環境**
    啟動 Scanner、Demo API 和 vAmPI 服務：
    ```bash
    docker-compose up -d --build
    ```

2.  **執行驗證實驗 (Demo API)**
    執行自動化測試腳本以掃描 `demo_api` 目標：
    ```powershell
    ./scripts/demo_run.ps1
    ```
    *預期結果*: 檢測到 2 個 BFLA 漏洞 (在 `/admin/promote` 上的權限提升)。

3.  **執行進階實驗 (vAmPI)**
    針對 OWASP vAmPI 目標執行掃描：
    ```powershell
    ./scripts/demo_scan_vampi.ps1
    ```
    *預期結果*: 在 `/users/v1/_debug` 端點上檢測到 BOLA/BFLA 漏洞。

## 5. 檢測到的漏洞摘要

| 目標 ID | 漏洞類型 (OWASP API Top 10) | 端點 | 嚴重性 | 檢測啟發式 (Detection Heuristic) |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-DEMO-01** | **API5:2023** Broken Function Level Auth | `POST /admin/promote` | 高 | 角色 `User` 成功執行了 `Admin` 操作。 |
| **CVE-DEMO-02** | **API5:2023** Broken Function Level Auth | `GET /admin/users` | 高 | 角色 `User` 存取了敏感的管理列表。 |
| **CVE-VAMPI-01**| **API1:2023** Broken Object Level Auth | `GET /users/v1/_debug`| 高 | 非特權存取了除錯資訊。 |

## 6. 安全與倫理考量

*   **僅供研究使用**: 本工具是一個主動式漏洞掃描器。它試圖繞過授權控制。請僅在您擁有明確書面許可的目標上使用（例如：localhost、受控實驗室環境）。
*   **無惡意負載**: 掃描器專注於邏輯缺陷（授權繞過）而非注入攻擊（XSS、SQLi），最大限度地降低數據損壞的風險，但副作用（狀態更改）是可能的。
*   **機密管理**: 提供的 `docker-compose.yml` 使用默認憑證 (`demosecret`) 僅用於可重現性。**切勿**在生產網絡中部署此配置。

## 7. 授權 (License)

本項目根據 MIT 許可證開源，用於學術和教育用途。
