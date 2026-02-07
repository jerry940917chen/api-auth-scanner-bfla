# API Security Demo Environment

**WARNING: This environment contains intentionally vulnerable services. DO NOT expose to the public internet.**

## Overview
This environment demonstrates automated API security scanning against:
1.  **vAmPI** (Vulnerable API): An intentionaly vulnerable API implementing OWASP Top 10 security flaws.
2.  **demo_api**: A custom lightweight target.

## Architecture
-   **Scanner**: The analysis engine.
-   **vAmPI**: Bound to `127.0.0.1:5000` (Isolated from external network).
-   **Network**: All services communicate via an internal Docker network `scanner-net`.

## Usage

### 1. Start Environment
```bash
make demo-up
# Or
docker-compose up -d --build
```

### 2. Run Scan
```bash
make demo-scan
# Or
pwsh ./scripts/demo_scan_vampi.ps1
```

### 3. Stop Environment
```bash
make demo-down
# Or
docker-compose down -v
```

## Scanner Targets

| Service | Base URL (Internal) | Local Access |
|---------|---------------------|--------------|
| vAmPI   | `http://vampi:5000` | `http://localhost:5000` |

## Expected Findings
The scanner should detect:
-   **BOLA/IDOR**: Unauthorized access to user resources.
-   **BFLA**: Unauthorized access to administrative endpoints.
-   **Information Leakage**: Excessive data exposure in responses.
