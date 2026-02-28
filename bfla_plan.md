# "Automatic Detection of Broken Function Level Authorization in REST APIs" 實作項目規劃

基於該學術界主流論文與概念，Automatic BFLA Detection (自動化 BFLA 偵測) 的核心在於**「無需人工標註」或「最少人工介入」**的情況下，系統能自動識別 API 端點的權限層級，並加以測試。

為了將這個概念實作進我們現有 API Auth Scanner，建議開發以下進階模組方向：

## 1. 自動化角色推斷 (Automated Role Inference)
目前的掃描器依賴用戶手動告訴我們「這把 Token 是 admin，這把是 user」。
- **實作項目**：基於 API 回應形狀 (Response Shape) 與端點語意 (Endpoint Semantics) 自動推斷 Token 擁有的權限層級。
- **技術細節**：如果 Token A 能存取 `DELETE /users/{id}`，而 Token B 得到 403，引擎自動學習「Token A 權限 > Token B」。

## 2. 基於靜態與動態分析的特徵提取 (Feature Extraction for Endpoints)
- **實作項目**：實作 NLP 或特徵比對模組來分析 OpenAPI Specification 或 URL 結構。
- **技術細節**：將端點自動分群為 `Administrative` (如 `/admin`, `DELETE`, `/config`) 與 `Regular` (如 `/profile`, `GET`)。
- **結合 LLM (GPT)**：讓 GPT 分析端點名稱與參數，給出「權限敏感度分數 (Sensitivity Score)」。

## 3. 差異化回應分析 (Differential Response Analysis)
BFLA 最難的地方是區分「此資源不存在 (404/400)」與「你無權訪問此資源但系統假裝它不存在 (404/401/403)」。
- **實作項目**：建立回應距離算法 (Response Distance Algorithm)。
- **技術細節**：比較高權限 Token 與低權限 Token 對同一端點的回應。如果狀態碼不同（例如高權限得 200，低權限得 200 但長度/欄位不同，或是 403），能精確捕捉繞過與權限邊界。

## 4. 依賴關係圖建構 (Dependency Graph Construction)
複雜的 BFLA 通常發生在深層資源，例如 `POST /departments/{id}/users`。
- **實作項目**：在掃描前建立資源建立與存取的拓樸圖 (API Dependency Graph)。
- **技術細節**：引擎先用最高權限創建資源，收集所有 IDs，然後再用低權限去測試這些「深層」端點，確保測試覆蓋到系統的各個角落。

## 5. 狀態機與越權插隊測試 (State-Machine Fuzzing)
- **實作項目**：針對需要多步驟的 API (例如：1. 建立訂單 -> 2. 付款 -> 3. 退款) 進行越權插隊測試。
- **技術細節**：使用低權限 Token 嘗試直接呼叫「退款 (Refund)」這個功能層級 (Function Level) 的端點，即使它跳過了正常流程。

---

以上五點是這篇文獻（與軟體工程實務）中最主流的 Automatic BFLA 解析模組。
