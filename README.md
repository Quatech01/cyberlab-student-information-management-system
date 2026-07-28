# Student Information Management System

A secure full-stack web application for managing student records in a UK educational institution, demonstrating production-grade DevSecOps practices: JWT authentication, RBAC, CSRF protection, parameterised SQL, bcrypt hashing, rate limiting, and security headers.

## What This Demonstrates

UK schools store some of the most sensitive data about children: medical conditions, SEN status, safeguarding notes, and free school meal eligibility. This project shows how to build a secure multi-role data management system that enforces strict access boundaries — an admin sees everything, a teacher sees only their form group, a student sees only their own record, and a parent sees only their linked children.

Key security concepts demonstrated:

- **JWT with short-lived access tokens and revocable refresh tokens** — 15-minute access tokens limit exposure; refresh tokens stored in the database can be revoked on logout
- **CSRF protection via JWT jti** — the token's unique ID acts as the CSRF token; any state-changing request must echo it back in the `X-CSRF-Token` header
- **Role-Based Access Control** — four roles (admin, teacher, student, parent) enforced in middleware, not per-route conditionals
- **Parameterised queries throughout** — every DB operation uses prepared statements; SQL injection strings are stored safely or rejected
- **bcrypt password hashing** — cost factor 12 for credential storage
- **UK-specific student data** — UPN (Unique Pupil Number), SEN status (none/support/EHCP), FSM eligibility, year groups 7–13

## How It Works

```
backend/          Express API (JWT auth, RBAC middleware, SQLite via node:sqlite)
  routes/         auth.js, students.js, admin.js
  middleware/     auth.js (JWT verify + role check), csrf.js (jti comparison)
  db/             schema.sql + lazy DatabaseSync singleton
frontend/         Self-contained SPA (index.html) — no build step, no CDN
tests/            28 node:test assertions covering all six test groups
```

The backend serves the frontend at `/` and the API at `/api/*`. On first startup, five seed users (admin, two teachers, a parent, a student) and five student records are created automatically.

## Quick Start

```bash
# Install and start the backend
cd backend && npm install
node index.js
# Server starts on http://127.0.0.1:4000

# Open the UI
# Visit http://127.0.0.1:4000 in your browser
# Demo login: admin / Admin@CyberLab1

# Run the security tool (tests)
cd ../tests && npm test
```

## Example API Output

```json
GET /api/students  (as admin)

[
  {
    "id": 1,
    "upn": "A123456789001",
    "first_name": "Alice",
    "last_name": "Smith",
    "date_of_birth": "2010-09-01",
    "year_group": 7,
    "form_group": "7A",
    "sen_status": "none",
    "fsm_eligible": false,
    "home_address": "1 Maple Avenue, London, SW1A 1AA",
    "gdpr_consent": true,
    "created_at": "2024-09-01T08:00:00.000Z"
  }
]
```

```json
POST /api/auth/login  →  200 OK

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4-e5f6-...",
  "csrf_token": "f7g8h9i0-j1k2-..."
}
```

## Key Takeaways

1. **Access tokens should be short-lived** — 15 minutes limits the damage window if a token is stolen
2. **Refresh tokens enable revocation** — storing them server-side means logout actually works (stateless JWTs alone cannot be revoked)
3. **CSRF protection is necessary even with JWTs** — if tokens are ever moved to cookies, CSRF attacks apply; the jti double-submit pattern works for both scenarios
4. **Row-level security belongs in the query, not the handler** — the `/api/students` route returns different data for each role because the SQL differs, not because data is filtered after the fact
5. **UPN format validation is not input sanitisation** — parameterised queries are the sanitisation; format validation is business rule enforcement

## Further Reading

- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [UK DfE Data Protection Toolkit for Schools](https://www.gov.uk/government/publications/data-protection-toolkit-for-schools)
