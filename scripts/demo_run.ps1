# scripts/demo_run.ps1
# Requires PowerShell 5.1+ or pwsh (PowerShell Core)

$ErrorActionPreference = "Stop"
$ScannerUrl = "http://localhost:8000"
$DemoAuthUrl = "http://localhost:8001"

Write-Host "=== API Auth Scanner Demo Run / 演示運行 ===" -ForegroundColor Cyan

# 1. Login to Demo API to get tokens
Write-Host "`n[1] Fetching tokens from Demo API / 獲取測試 Token..." -ForegroundColor Yellow
try {
    $aliceResp = Invoke-RestMethod -Method Post -Uri "$DemoAuthUrl/login?username=alice"
    $aliceToken = $aliceResp.access_token
    Write-Host "    Got Alice token (User)" -ForegroundColor DarkGray
    
    $adminResp = Invoke-RestMethod -Method Post -Uri "$DemoAuthUrl/login?username=admin"
    $adminToken = $adminResp.access_token
    Write-Host "    Got Admin token (Admin)" -ForegroundColor DarkGray
}
catch {
    Write-Error "Failed to fetch tokens. Is demo_api running? / 無法獲取 Token，請檢查 demo_api 是否運行。"
    exit 1
}

# 2. Create Project
Write-Host "`n[2] Creating Project / 創建項目..." -ForegroundColor Yellow
$headers = @{ "Content-Type" = "application/json" }
$projBody = @{
    name        = "Demo API Target"
    base_url    = "http://demo_api:8000"
    openapi_url = "http://demo_api:8000/openapi.json"
} | ConvertTo-Json

try {
    $project = Invoke-RestMethod -Method Post -Uri "$ScannerUrl/projects" -Headers $headers -Body $projBody
    Write-Host "    Project Created: ID=$($project.id), Name='$($project.name)'" -ForegroundColor Green
}
catch {
    Write-Warning "    Failed to create project (might exist). Listing projects... / 項目創建失敗（可能已存在），嘗試讀取現有項目..."
    $projects = Invoke-RestMethod -Method Get -Uri "$ScannerUrl/projects"
    $project = $projects | Select-Object -First 1
    if (-not $project) {
        Write-Error "No projects found and creation failed. / 找不到任何項目。"
        exit 1
    }
    Write-Host "    Using existing project: ID=$($project.id)" -ForegroundColor Green
}

# 3. Start Scan / 啟動掃描
Write-Host "`n[3] Starting Scan / 啟動掃描..." -ForegroundColor Yellow
$scanBody = @{
    profiles     = @(
        @{ name = "alice"; role = "user"; token = $aliceToken },
        @{ name = "admin"; role = "admin"; token = $adminToken }
    )
    scan_options = @{
        timeout_seconds = 10
        concurrency     = 5
        include_paths   = @("/admin")
    }
} | ConvertTo-Json -Depth 10

try {
    $scanResp = Invoke-RestMethod -Method Post -Uri "$ScannerUrl/projects/$($project.id)/scans" -Headers $headers -Body $scanBody
    $scanId = $scanResp.scan_id
    Write-Host "    Scan Started: ID=$scanId status=$($scanResp.status)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to start scan: $_"
    exit 1
}

# 4. Poll Status / 輪詢狀態
Write-Host "`n[4] Polling Scan Status / 等待掃描完成..." -ForegroundColor Yellow
$maxRetries = 30
for ($i = 0; $i -lt $maxRetries; $i++) {
    $scan = Invoke-RestMethod -Method Get -Uri "$ScannerUrl/scans/$scanId"
    $status = $scan.status
    
    # Simple progress bar effect
    Write-Host "." -NoNewline -ForegroundColor Cyan
    
    if ($status -in @("completed", "failed", "canceled")) {
        Write-Host "`n    Status: $status -> DONE" -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 2
}

# 5. Get Report
Write-Host "`n[5] Retrieving Report / 獲取報告..." -ForegroundColor Yellow
try {
    $report = Invoke-RestMethod -Method Get -Uri "$ScannerUrl/scans/$scanId/report.json"
    Write-Host "    Report Summary / 報告摘要:" -ForegroundColor Cyan
    Write-Output "    ----------------"
    Write-Output "    Status: $($report.scan.status)"
    Write-Output "    Vulnerabilities Found / 發現漏洞數: $($report.scan.vulnerabilities.Count)"
    if ($report.scan.summary_counts) {
        Write-Output "    Severity Counts / 嚴重程度分佈: $($report.scan.summary_counts | ConvertTo-Json -Compress)"
    }
    Write-Output "    ----------------"
    
    # Check for specific expected findings
    $vulns = $report.scan.vulnerabilities
    if ($vulns) {
        $bfla = $vulns | Where-Object { $_.vuln_type -eq "BFLA" }
        Write-Host "    Found $($bfla.Count) BFLA vulnerabilities / 發現 $($bfla.Count) 個 BFLA 漏洞:" -ForegroundColor Green
        $bfla | ForEach-Object { Write-Host "      - [BFLA] $($_.endpoint) (Severity: $($_.severity))" -ForegroundColor Red }
        
        Write-Host "`n    Detail Report URL (PDF): $ScannerUrl/scans/$scanId/report.pdf" -ForegroundColor Cyan
    }
    else {
        Write-Warning "    No vulnerabilities found! / 未發現漏洞！"
    }

}
catch {
    Write-Error "Failed to get report: $_"
}

Write-Host "`n=== Demo Completed / 演示結束 ===" -ForegroundColor Cyan
Write-Host "Detail Report URL (JSON): http://localhost:8000/scans/$scanId/report.json"
Write-Host "Detail Report URL (PDF) : http://localhost:8000/scans/$scanId/report.pdf"

try {
    Invoke-WebRequest "http://localhost:8000/scans/$scanId/report.pdf" -Method Get -TimeoutSec 8 | Out-Null
    Write-Host "PDF check: OK" -ForegroundColor Green
} catch {
    Write-Host "PDF check: FAILED (known dependency mismatch). Use JSON for demo." -ForegroundColor Yellow
}
