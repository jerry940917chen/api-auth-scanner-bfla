# Advanced API Security Research: Hard-to-Detect Vulnerability Matrix
**Target System**: OWASP vAmPI  
**Focus**: Automated Scanner Blind Spots (State, Logic, Context)

## 1. Threat Model & Research Rationale

Standard API scanners (DAST) typically operate on a "stateless fuzzing" model: they enumerate endpoints from an OpenAPI spec and send malformed payloads in isolation. They struggle with **Temporal** and **Contextual** vulnerabilities.

*   **Temporal Blindness**: Scanners rarely understand that Request B must usually follow Request A to trigger a state change (e.g., "Upgrade Role" then "Admin Action").
*   **Contextual Blindness**: Scanners struggle to differentiate "valid user data" from "other user's data" without explicit configuration (seed data), making BOLA detection difficult when IDs are opaque.
*   **Semantic Blindness**: Scanners cannot infer business logic (e.g., "resetting the database shouldn't be allowed for an anonymous user").

This matrix is designed to exploit these specific architectural limitations.

## 2. Advanced Hard-to-Detect Test Matrix

| Test ID | OWASP Category | Complexity | Target Endpoint(s) | Preconditions | Auth Context | Attack Sequence (Multi-Step) | Why Scanners Fail | Expected Outcome | Manual Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ADV-01** | **BOLA (API1:2023)**<br>_Cross-Reference via Leaked ID_ | **High** | 1. `GET /users/v1`<br>2. `GET /users/v1/_debug/{id}` | Users exist in DB | User A | **Step 1**: Call `/users/v1` to leak list of all users and their IDs (Excessive Data Exposure).<br>**Step 2**: Extract `id` of User B from Step 1 response.<br>**Step 3**: Call `/_debug/{id}` using User A's token but User B's ID. | **Correlation Failure**: Scanners rarely extract data from Response A to populate Request B parameters dynamically. | **HTTP 200 OK**<br>Returns User B's private debug info (password hash/secrets). | 1. Login as Alice.<br>2. Get list, find Bob's ID.<br>3. Request Bob's debug info.<br>4. Verify PII in response. |
| **ADV-02** | **BFLA (API5:2023)**<br>_Privilege Escalation via Mass Assignment_ | **Very High** | 1. `POST /users/v1/login`<br>2. `PUT /users/v1/{user}`<br>3. `GET /users/v1/_debug` | Valid User Account | User -> Admin (Spoofed) | **Step 1**: Login as User A.<br>**Step 2**: specific `PUT` request targeting own profile, injecting `{"admin": true}` or `{"role": "admin"}` (Mass Assignment).<br>**Step 3**: Attempt to access Admin-only endpoint `/_debug`. | **State Machine Failure**: Scanners don't try to "upgrade" their own state via property injection and then retry previously forbidden endpoints. | **HTTP 200 OK**<br>Access granted to Admin resources after self-promotion. | 1. Check `/_debug` (403).<br>2. PUT `{"admin":true}` to self.<br>3. Check `/_debug` (200). |
| **ADV-03** | **Business Logic Abuse (API6:2023)**<br>_Unauthenticated State Reset_ | **High** | `GET /createdb` | None | None | **Step 1**: Observe system contains data.<br>**Step 2**: Call `/createdb` without auth.<br>**Step 3**: System state is wiped/reset. | **Semantic Blindness**: Scanners see a 200 OK as a "success" (valid test) rather than a "vulnerability" (availability impact/DoS). They presume all exposed GETs are safe. | **HTTP 200 OK**<br>Database is reset to default state (DoS). | 1. Create a tailored user.<br>2. Hit `/createdb`.<br>3. Verify user is gone. |
| **ADV-04** | **Chained: Mass Assignment + BOLA**<br>_Password Reset of Peer_ | **High** | 1. `GET /users/v1`<br>2. `PUT /users/v1/{user}/password` | Multiple Users | User A | **Step 1**: Enumerate users to find User B's username.<br>**Step 2**: Construct `PUT` request to `/users/v1/{UserB}/password` using User A's token but accessing User B's path. | **Role/Graph Failure**: Requires understanding that `PUT /password` is state-changing and testing if User A acts on User B. Scanners often stick to "Self" tests. | **HTTP 200 OK**<br>Alice successfully changes Bob's password. | 1. Login Alice.<br>2. Change Bob's pass.<br>3. Login Bob with new pass (Success). |
| **ADV-05** | **Injection (API8:2023)**<br>_Auth Bypass SQLi_ | **Medium** | `POST /users/v1/login` | None | None | **Step 1**: Submit login with username `admin' --`.<br>**Step 2**: System bypasses password check.<br>**Step 3**: Returns valid JWT for admin. | **Payload Context**: Simple SQLi is detectable, but *using* the resulting token for subsequent high-privilege scanning is a correlation step often missed. | **HTTP 200 OK**<br>JWT Token returned. | 1. Send Payload.<br>2. Decode JWT.<br>3. Verify `sub` is `admin`. |

## 3. Analysis: Automated Scanner Blind Spots

Based on the matrix above, standard scanners will fail detection for the following reasons:

1.  **Lack of Dynamic Correlation (ADV-01)**: Tools treat the API as a bag of endpoints. They do not learn: "I need an ID for this parameter; let me find an endpoint that returns IDs and use one."
2.  **Stateless Execution (ADV-02, ADV-03)**: Tools do not track the *semantic consequence* of a request (e.g., "I just made myself an admin"). They expect the state to be constant throughout the scan.
3.  **Ambiguous Success Signals (ADV-03)**: For a scanner, a `200 OK` on `/createdb` looks like a healthy API response, not a critical operational hazard. It lacks the business context to know that resetting the DB is malicious.
4.  **Identity Segregation (ADV-04)**: Most scanners use a single "Tester" token. They cannot effectively test "User A accessing User B" because they don't maintain two distinct active sessions to verify cross-contamination.

## 4. Research Implications

To detect these vulnerabilities, next-generation compliance and security tools must move beyond Fuzzing and adopt **Graph-Based Execution**:
1.  **Dependency Modeling**: Inferring `Producer -> Consumer` relationships between endpoints (e.g., `list_users` produces `user_id`).
2.  **State Tracking**: Monitoring user attributes (Roles, Permissions) and reacting when they change during a scan.
3.  **Multi-Actor Simulation**: Instantiating (at minimum) two concurrent user sessions (`Attacker` and `Victim`) to deterministically prove BOLA and Data Leaks.
