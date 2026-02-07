$ErrorActionPreference = "Stop"

function Get-PythonPath {
    param([string]$Version)
    try {
        # Try finding via py launcher
        $pyPath = py -$Version -c "import sys; print(sys.executable)" 2>$null
        if ($pyPath) { return $pyPath.Trim() }
        
        # Fallback to checking registry or path if convenient, but py launcher is standard
        # Try direct command if on path
        $directCmd = "python$Version"
        $pyPath = & $directCmd -c "import sys; print(sys.executable)" 2>$null
        if ($pyPath) { return $pyPath.Trim() }
    }
    catch {
        return $null
    }
    return $null
}

Write-Host "=== Dual-Environment Bootstrap ===" -ForegroundColor Cyan

# 1. Detect Python Versions
Write-Host "`n[1/6] Detecting Python Versions..."
$RuntimeVersion = "3.13"
$StaticVersions = @("3.12", "3.11", "3.13")

$RuntimePython = Get-PythonPath -Version $RuntimeVersion
if (-not $RuntimePython) {
    Write-Error "CRITICAL: Python $RuntimeVersion not found. Please install it."
    exit 1
}
Write-Host "  Found Runtime Python ($RuntimeVersion): $RuntimePython" -ForegroundColor Green

$StaticPython = $null
$SelectedStaticVersion = $null
foreach ($ver in $StaticVersions) {
    $path = Get-PythonPath -Version $ver
    if ($path) {
        $StaticPython = $path
        $SelectedStaticVersion = $ver
        break
    }
}

if (-not $StaticPython) {
    Write-Error "CRITICAL: Neither Python 3.12 nor 3.11 found for static analysis."
    exit 1
}
Write-Host "  Found Static Python ($SelectedStaticVersion): $StaticPython" -ForegroundColor Green

# 2. Create Virtual Environments
Write-Host "`n[2/6] Creating Virtual Environments..."

$VenvRuntime = ".venv313"
$VenvStatic = ".venv312" # Keeping name constant even if 3.11 used, as per spec request, or should we match? 
# Spec said: ".venv312 Interpreter: Python 3.12" but also "3.12 (preferred) or 3.11".
# To strictly follow spec requirements for naming:
if ($SelectedStaticVersion -ne "3.12") {
    Write-Warning "Using $SelectedStaticVersion but creating .venv312 as specifically requested."
}

function Create-Venv {
    param($PythonPath, $VenvDir)
    if (Test-Path $VenvDir) {
        Write-Host "  $VenvDir exists, skipping creation." -ForegroundColor Gray
    }
    else {
        Write-Host "  Creating $VenvDir using $PythonPath..."
        & $PythonPath -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { throw "Failed to create venv at $VenvDir" }
    }
}

Create-Venv -PythonPath $RuntimePython -VenvDir $VenvRuntime
Create-Venv -PythonPath $StaticPython -VenvDir $VenvStatic

# 3. Upgrade Pip
Write-Host "`n[3/6] Upgrading Pip..."
& "$VenvRuntime\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
& "$VenvStatic\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
Write-Host "  Pip upgraded in both environments." -ForegroundColor Green

# 4. Install Dependencies
Write-Host "`n[4/6] Installing Dependencies..."

# Runtime
if (Test-Path "requirements.txt") {
    Write-Host "  Installing runtime deps to $VenvRuntime..."
    & "$VenvRuntime\Scripts\python.exe" -m pip install -r requirements.txt | Out-Null
}
else {
    Write-Warning "  requirements.txt not found!"
}

# Static
Write-Host "  Installing static tools to $VenvStatic..."
& "$VenvStatic\Scripts\python.exe" -m pip install pyre-check mypy | Out-Null
Write-Host "  Dependencies installed." -ForegroundColor Green

# 5. Configure Pyre
Write-Host "`n[5/6] Configuring Pyre..."
$AbsVenvStatic = Convert-Path "$VenvStatic\Scripts\python.exe"
$PyreConfig = @{
    source_directories = @(".")
    python_binary      = $AbsVenvStatic
}
$PyreJson = $PyreConfig | ConvertTo-Json -Depth 2
$PyreJson | Set-Content "pyre_configuration.json"
Write-Host "  pyre_configuration.json written with python_binary: $AbsVenvStatic" -ForegroundColor Green

# 6. Sanity Checks
Write-Host "`n[6/6] Sanity Checks..."

# Runtime Check
Write-Host "  Checking Runtime ($VenvRuntime)..." -NoNewline
try {
    & "$VenvRuntime\Scripts\python.exe" -c "import httpx; import sys; print('  [OK] ' + sys.executable)"
}
catch {
    Write-Error "  [FAIL] Failed to import httpx in runtime env."
}

# Static Check
Write-Host "  Checking Static ($VenvStatic)..." -NoNewline
try {
    $PyreVer = & "$VenvStatic\Scripts\pyre.exe" --version
    Write-Host "  [OK] Pyre $PyreVer" -ForegroundColor Green
}
catch {
    Write-Error "  [FAIL] Pyre failed to run."
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "Run Application:"
Write-Host "  $VenvRuntime\Scripts\python core\openapi_parser.py"
Write-Host "Run Static Analysis:"
Write-Host "  $VenvStatic\Scripts\pyre check"
Write-Host "  $VenvStatic\Scripts\mypy ."
