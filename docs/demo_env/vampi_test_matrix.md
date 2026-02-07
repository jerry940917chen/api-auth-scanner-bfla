# OWASP vAmPI - Guaranteed Vulnerability Test Matrix

## Overview
**Target System**: OWASP vAmPI (Vulnerable API)
**Purpose**: Validation of API security scanners and offensive research.
**Base URL**: `http://localhost:5000` (Local) / `http://vampi:5000` (Docker Internal)

## Test Matrix

| Test ID | OWASP API Top 10 (2023) | Target Endpoint | Method | Auth State | Attack Technique | Sample Payload / Request | Expected Evidence | Detection Signal | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | **API1:2023** Broken Object Level Authorization (BOLA) | `/users/v1/_debug/{user_id}` | `GET` | User (Alice) | **ID Manipulation**<br>Accessing another user's debug info by changing `user_id`. | `GET /users/v1/_debug/1` (Alice requests ID 1 - Admin) | Response contains Admin user object/secrets. | **HTTP 200 OK** + Sensitive Data (JSON) | **High** |
| **T-02** | **API1:2023** Broken Object Level Authorization (BOLA) | `/users/v1/{username}` | `GET` | User (Alice) | **ID Manipulation**<br>Accessing another user's profile by changing `username`. | `GET /users/v1/admin` (Alice requests 'admin') | Response contains Admin profile details. | **HTTP 200 OK** | **High** |
| **T-03** | **API2:2023** Broken Authentication | `/users/v1/login` | `POST` | None | **Password Brute Force / Weak Auth**<br>System allows unlimited login attempts or accepts weak passwords. | `POST /users/v1/login`<br>`{"username": "admin", "password": "password1"}` | System returns token (if cracked) or no lockout on failure. | **HTTP 200 OK** (on success) | **Critical** |
| **T-04** | **API3:2023** Broken Object Property Level Authorization (Mass Assignment) | `/users/v1/{username}/password` | `PUT` | User (Alice) | **Mass Assignment**<br>Updating password of another user via BOLA + Mass Assignment. | `PUT /users/v1/admin/password`<br>`{"password": "hacked"}` | Password updated for target user. | **HTTP 200 OK** + "Password updated" | **High** |
| **T-05** | **API3:2023** Broken Object Property Level Authorization (Excessive Data Exposure) | `/users/v1` | `GET` | User | **Data Leakage**<br>Endpoint returns all user fields including sensitive ones. | `GET /users/v1` | Response JSON array contains `password`, `email`, `admin: true` for all users. | **HTTP 200 OK** + Regex match on password/email patterns | **Medium** |
| **T-06** | **API6:2023** Unrestricted Access to Sensitive Business Flows | `/createdb` | `GET` | None | **Business Logic Abuse**<br>Resetting the database without auth. | `GET /createdb` | Database is reset/re-seeded. | **HTTP 200 OK** + "Database created" | **High** |
| **T-07** | **API7:2023** Server Side Request Forgery (SSRF) | *Not standard in basic vAmPI* | - | - | - | - | - | - | - |
| **T-08** | **API8:2023** Security Misconfiguration | `/users/v1/_debug` | `GET` | User | **Debug Endpoint Enabled**<br>Leaving debug endpoints exposed. | `GET /users/v1/_debug` | Returns stack trace or debug info. | **HTTP 200 OK** + Debug info | **Medium** |
| **T-09** | **Injection** (SQL/NoSQL) | `/users/v1/login` | `POST` | None | **SQL Injection**<br>Bypassing auth with SQLi payload. | `POST /users/v1/login`<br>`{"username": "admin' --", "password": "any"}` | Logged in as admin. | **HTTP 200 OK** + JWT Token | **Critical** |
| **T-10** | **Lack of Resources & Rate Limiting** | `/users/v1` | `GET` | None | **DoS**<br>Repeated requests without blocking. | `GET /users/v1` (Repeat 100x) | All requests succeed (no 429). | **HTTP 200 OK** (Consistency) | **Medium** |

## Instructions for Validation
1.  **Environment**: Ensure vAmPI is running (`make demo-up`).
2.  **Tools**: Use `curl`, Postman, or the provided `demo_scan_vampi.ps1` script.
3.  **Note**: The automated scanner currently covers **T-01** and **T-02** (BOLA) and portions of **T-05** via BFLA checks in the demo script. Manual verification recommended for Injection and Mass Assignment.
