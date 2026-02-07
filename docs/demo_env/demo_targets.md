# Demo Targets

## vAmPI (Vulnerable REST API)

vAmPI is a vulnerable API made with Flask and it includes vulnerabilities from the OWASP Top 10 2017 for APIs.

### Base URL
-   Internal: `http://vampi:5000`
-   External: `http://127.0.0.1:5000`

### Vulnerabilities to Test
1.  **Broken Object Level Authorization (BOLA)**
    -   Endpoint: `GET /users/v1/_debug/{user_id}`
    -   Description: Accessing other users' details without authorization.

2.  **Broken User Authentication**
    -   Endpoint: `POST /users/v1/login`
    -   Description: Validating password strength or token integrity (if applicable).

3.  **Excessive Data Exposure**
    -   Endpoint: `GET /users/v1`
    -   Description: APIs returning full object data including sensitive fields.

### OpenAPI Config
The OpenAPI spec is available at:
-   `/openapi.json`
