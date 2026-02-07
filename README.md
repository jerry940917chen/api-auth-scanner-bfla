# API Authorization Vulnerability Scanner: A Research Prototype

> **Status**: Research Prototype (Master's Thesis Level)  
> **Focus**: Broken Function Level Authorization (BFLA) & BOLA Detection  
> **Version**: 1.0.0

## 1. Abstract

This repository contains the implementation of an automated API security scanner developed for research into **Broken Function Level Authorization (BFLA)** detection. Unlike traditional DAST tools that rely on fuzzing, this scanner implements a role-based state analysis engine to detect authorization logic flaws by cross-referencing valid user permissions against privileged endpoint access.

The system is containerized and includes a custom vulnerable target (`demo_api`) and integration with **OWASP vAmPI** to demonstrate detection capabilities in a controlled environment.

## 2. Methodology

The scanner operates on a **Principal-Agent Model** to verify authorization policies:
1.  **Policy Ingestion**: Parses OpenAPI (Swagger) specifications to build an endpoint map.
2.  **Role Profiling**: Accepts multiple user profiles (e.g., `User`, `Admin`) with valid credentials.
3.  **Cross-Context Replay**:
    *   Captures baseline requests from a privileged user (Admin).
    *   Replays strictly defined requests using an unprivileged user's (Guest/User) session token.
    *   Analyzes HTTP status codes and response structures to identify unauthorized success states (False Negatives in policy enforcement).

## 3. Repository Structure

```
├── scanner/           # Core Scanner Engine (FastAPI + Python)
│   ├── services/      # Scanning Logic & Heuristics
│   └── models/        # SQLAlchemy ORM Models
├── demo_api/          # Intentionally Vulnerable Banking API (Target)
├── scripts/           # Automation for Experiments & Demonstrations
├── docs/              # Research Documentation & Test Matrices
│   ├── demo_env/      # vAmPI & Demo Target Specs
│   └── thesis/        # (Optional) Extended Methodology Notes
├── data/              # Runtime Database Storage (Ignored in Git)
├── docker-compose.yml # Orchestration for Reproducible Experiments
└── requirements.txt   # Python Dependencies
```

## 4. Reproducibility

This experiment is designed to be fully reproducible using Docker Compose.

### Prerequisites
*   Docker & Docker Compose
*   PowerShell (or Bash for Linux/Mac, scripts provided are PS1)

### Setup & Execution

1.  **Initialize Environment**
    Start the Scanner, Demo API, and vAmPI services:
    ```bash
    docker-compose up -d --build
    ```

2.  **Run Validation Experiment (Demo API)**
    Execute the automated test script to scan the `demo_api` target:
    ```powershell
    ./scripts/demo_run.ps1
    ```
    *Expected Outcome*: Detection of 2 BFLA vulnerabilities (Privilege Escalation on `/admin/promote`).

3.  **Run Advanced Experiment (vAmPI)**
    Execute the scan against the OWASP vAmPI target:
    ```powershell
    ./scripts/demo_scan_vampi.ps1
    ```
    *Expected Outcome*: Detection of BOLA/BFLA vulnerabilities on `/users/v1/_debug` endpoints.

## 5. Summary of Detected Vulnerabilities

| Target ID | Vulnerability Type (OWASP API Top 10) | Endpoint | Severity | Detection Heuristic |
| :--- | :--- | :--- | :--- | :--- |
| **CVE-DEMO-01** | **API5:2023** Broken Function Level Auth | `POST /admin/promote` | High | Role `User` successfully executed `Admin` action. |
| **CVE-DEMO-02** | **API5:2023** Broken Function Level Auth | `GET /admin/users` | High | Role `User` accessed sensitive administrative list. |
| **CVE-VAMPI-01**| **API1:2023** Broken Object Level Auth | `GET /users/v1/_debug`| High | Unprivileged access to debug information. |

## 6. Security & Ethical Considerations

*   **Research Use Only**: This tool is an active vulnerability scanner. It attempts to bypass authorization controls. Use only on targets where you have explicit written permission (e.g., localhost, controlled lab environments).
*   **No Malicious Payloads**: The scanner focuses on logic flaws (auth bypass) rather than injection attacks (XSS, SQLi), minimizing the risk of data corruption, but side effects (state changes) are possible.
*   **Secrets Management**: The provided `docker-compose.yml` uses default credentials (`demosecret`) solely for reproducibility. **DO NOT** deploy this configuration in a production network.

## 7. License

This project is open-sourced under the MIT License for academic and educational use.
