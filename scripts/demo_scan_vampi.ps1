# scripts/demo_scan_vampi.ps1
# 自動化 vAmPI 漏洞目標的掃描流程（Harder + 更可觀測）

$ErrorActionPreference = "Stop"

# Scanner API（跑在宿主機 8000）
$ScannerUrl    = "http://localhost:9000"

# vAmPI：scanner 容器內要用 service name + container port
$VampiUrl      = "http://vampi:5000"

# vAmPI：宿主機檢查用
$VampiLocalUrl = "http://localhost:9001"

Write-Host "=== vAmPI Security Scan Demo / vAmPI 安全掃描演示 ===" -ForegroundColor Cyan
Write-Host "ScannerUrl    : $ScannerUrl" -ForegroundColor DarkGray
Write-Host "VampiUrl      : $VampiUrl (container internal)" -ForegroundColor DarkGray
Write-Host "VampiLocalUrl : $VampiLocalUrl (host)" -ForegroundColor DarkGray

# 0. 強制提醒：你 compose 必須是 5000:5000（不能是 127.0.0.1:5000:5000）
Write-Host "`n[0] Sanity Check / 連線健檢..." -ForegroundColor Yellow
try {
    $r0 = Invoke-WebRequest -Uri "$VampiLocalUrl/" -Method Get -TimeoutSec 5
    Write-Host "    Host -> vAmPI OK: HTTP $($r0.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "    Host -> vAmPI FAILED. Check docker-compose vampi ports (must be 5000:5000)." -ForegroundColor Red
    throw
}

# 1. 初始化 vAmPI DB（可選）
Write-Host "`n[1] Init vAmPI DB / 初始化資料庫..." -ForegroundColor Yellow
try {
    $resp = Invoke-WebRequest -Uri "$VampiLocalUrl/createdb" -Method Get -TimeoutSec 10
    Write-Host "    vAmPI DB initialized: HTTP $($resp.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "    /createdb call failed (may already be initialized). Continuing..." -ForegroundColor DarkGray
}

# 2. 檢查 OpenAPI 是否存在（重要：路徑錯會直接導致 0）
Write-Host "`n[2] Checking OpenAPI / 檢查 OpenAPI..." -ForegroundColor Yellow
$OpenApiLocal = "$VampiLocalUrl/openapi.json"
try {
    $oa = Invoke-WebRequest -Uri $OpenApiLocal -Method Get -TimeoutSec 10
    Write-Host "    OpenAPI reachable: HTTP $($oa.StatusCode) -> $OpenApiLocal" -ForegroundColor Green
} catch {
    Write-Host "    Cannot fetch openapi.json at $OpenApiLocal" -ForegroundColor Red
    Write-Host "    Try browsing $VampiLocalUrl/docs to confirm actual OpenAPI path." -ForegroundColor Red
    throw
}

# 3. 註冊 vAmPI 目標
Write-Host "`n[3] Registering vAmPI Target / 註冊 vAmPI 目標..." -ForegroundColor Yellow
$headers = @{ "Content-Type" = "application/json" }

$projBody = @{
    name       = "OWASP vAmPI"
    base_url   = $VampiUrl
    openapi_url= "$VampiUrl/openapi.json"
} | ConvertTo-Json

try {
    $project = Invoke-RestMethod -Method Post -Uri "$ScannerUrl/projects" -Headers $headers -Body $projBody
    Write-Host "    Project Created: ID=$($project.id)" -ForegroundColor Green
} catch {
    $projects = Invoke-RestMethod -Method Get -Uri "$ScannerUrl/projects"
    $project = $projects | Where-Object { $_.name -eq "OWASP vAmPI" } | Select-Object -First 1
    if ($project) {
        Write-Host "    Using existing project: ID=$($project.id)" -ForegroundColor Green
    } else {
        throw "Failed to create or find project OWASP vAmPI."
    }
}

# 4. 啟動掃描
Write-Host "`n[4] Starting Scan / 啟動掃描..." -ForegroundColor Yellow

# 重點改動：
# - 不給 dummy token，避免掃描器強行加 Authorization 造成干擾
# - include_paths 用 vAmPI 常見/高命中漏洞 seed（對齊你矩陣）
# - 把 /users 改成 /users/v1
# - 加入 /_debug 與 /createdb（Misconfig / Debug）
$scanBodyObj = @{
    profiles = @(
        @{ name = "guest"; role = "anonymous"; token = "" }
    )
    scan_options = @{
        timeout_seconds = 15
        concurrency     = 5
        include_paths   = @(
            "/users/v1",          # 常見 user endpoints
            "/users/v1/",         # 避免工具拼接 bug
            "/users/v1/_debug",   # 你要的 debug 類
            "/_debug",            # 有些版本在根
            "/createdb"           # misconfig
        )
    }
}

$scanBody = $scanBodyObj | ConvertTo-Json -Depth 10
Write-Host "    Scan include_paths: $($scanBodyObj.scan_options.include_paths -join ', ')" -ForegroundColor DarkGray

$scanResp = Invoke-RestMethod -Method Post -Uri "$ScannerUrl/projects/$($project.id)/scans" -Headers $headers -Body $scanBody
$scanId = $scanResp.scan_id
Write-Host "    Scan Started: ID=$scanId" -ForegroundColor Green

# 5. 輪詢狀態
Write-Host "`n[5] Polling / 輪詢中..." -ForegroundColor Yellow
$maxRetries = 45
for ($i = 0; $i -lt $maxRetries; $i++) {
    $scan = Invoke-RestMethod -Method Get -Uri "$ScannerUrl/scans/$scanId"
    $status = $scan.status
    Write-Host "." -NoNewline -ForegroundColor Cyan
    if ($status -in @("completed", "failed", "canceled")) {
        Write-Host "`n    Status: $status" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 2
}

# 6. Report (JSON)
Write-Host "`n[6] Report Summary (JSON)" -ForegroundColor Yellow
$report = Invoke-RestMethod -Uri "$ScannerUrl/scans/$scanId/report.json"

$vcount = 0
if ($report -and $report.scan -and $report.scan.vulnerabilities) {
    $vcount = $report.scan.vulnerabilities.Count
}

Write-Host "    Vulnerabilities: $vcount" -ForegroundColor Cyan
if ($vcount -gt 0) {
    $report.scan.vulnerabilities | ForEach-Object {
        Write-Host ("    - [{0}] {1}" -f $_.vuln_type, $_.endpoint) -ForegroundColor Red
    }
} else {
    Write-Host "    No findings. If this persists, check scanner logs for request failures/timeouts." -ForegroundColor Yellow
    Write-Host "    Tip: ensure docker-compose vampi ports is '5000:5000' (NOT 127.0.0.1 binding)." -ForegroundColor Yellow
}

# 7. PDF（可選：你現在 weasyprint/pydyf 會炸，先不要自動叫）
Write-Host "`n[7] PDF Report (Optional)" -ForegroundColor Yellow
Write-Host "    Skipped by default because PDF generation may fail due to weasyprint/pydyf mismatch." -ForegroundColor DarkGray
Write-Host "    If needed: open $ScannerUrl/scans/$scanId/report.pdf" -ForegroundColor DarkGray
