# Student Information Management System

A secure full-stack web application for managing student records in a UK educational institution.

## What This Demonstrates

This project demonstrates defensive implementation of a real-world school management information system (MIS). It covers every layer of a production-grade web application's security posture:

- **JWT authentication** with short-lived access tokens (15 minutes) and server-side revocable refresh tokens (7 days), each stored as SHA-256 hashes in SQLite to prevent database leakage
- **Role-Based Access Control** across four roles (admin, teacher, student, parent) enforced in middleware before any route handler executes — no inline per-route checks
- **CSRF double-submit cookie protection** — a UUID CSRF token is set as a `SameSite=Strict` cookie on login; every state-changing request must echo it in the `X-CSRF-Token` header
- **Parameterised queries** via `node:sqlite`'s `DatabaseSync.prepare()` — user input never reaches raw SQL strings
- **bcrypt password hashing** at cost factor 12 — adaptive and GPU-resistant
- **Helmet security headers** — CSP, HSTS, X-Frame-Options DENY, X-Content-Type-Options, and others on every response
- **express-rate-limit** — auth endpoints limited to 20 req/15 min; API endpoints to 100 req/min
- **Input validation** — every API boundary validated with `express-validator`; UPN format checked with regex; year groups clamped to 7–13; emails validated per RFC
- **Audit log** — every login, student view, create, update, and delete is recorded with user ID, entity type, entity ID, and client IP

## Architecture

```
backend/          Express REST API
  db/             node:sqlite schema, initialisation, seed data
  middleware/     JWT auth, CSRF double-submit cookie, RBAC factories
  routes/         auth, students, admin
frontend/         Self-contained SPA (no build step, all CSS/JS inline)
tests/            node:test integration suite (28 tests)
```

The demo server seeds 8 students across year groups 9–12 with four form groups. Three students have user accounts (Emma Wilson / student, James Chen / student, Sofia Rahman / student). Two parents are linked to their children via a join table. Two teachers are assigned form groups.

## Quick Start

```bash
cd backend && npm install
node index.js
# Open http://127.0.0.1:3000
```

Demo credentials:

| Username     | Password       | Role    |
|--------------|----------------|---------|
| admin        | Admin@1234     | admin   |
| ms_johnson   | Teacher@1234   | teacher |
| emma.wilson  | Student@1234   | student |
| p.wilson     | Parent@1234    | parent  |

## Running Tests

```bash
cd tests && npm test
```

Tests start an isolated in-memory database on a random port, seed all demo data, and exercise all 28 assertions before shutting the server down.

## Example Output

```json
GET /api/students (admin)
[
  { "id": 1, "upn": "A123456789012", "first_name": "Emma",  "last_name": "Wilson",
    "year_group": 9, "form_group": "9A", "sen_status": "None", "fsm_eligibility": 0 },
  { "id": 2, "upn": "B234567890123", "first_name": "James", "last_name": "Chen",
    "year_group": 10, "form_group": "10A", "sen_status": "SEN Support", "fsm_eligibility": 0 },
  ...
]

GET /api/students (teacher ms_johnson — form groups 9A, 10A only)
[ Emma Wilson (9A), Oliver Martinez (9A), James Chen (10A), Noah Okafor (10A) ]

GET /api/students (student emma.wilson — own record only)
[ Emma Wilson (9A) ]
```

## Key Takeaways

1. **Row-level isolation is not enough** — teachers should see only their form group; parents only their children. Enforce this at the SQL level (`WHERE form_group IN (?)`, `JOIN parent_student`), not just in application logic.
2. **CSRF tokens must be bound to the session** — the double-submit cookie pattern is correct only when cookies are `SameSite=Strict`; `SameSite=None` without `Secure` makes it pointless.
3. **SHA-256 hash your refresh tokens before storing** — if the DB is compromised, raw tokens allow immediate impersonation; hashes do not.
4. **UPN is sensitive** — the Unique Pupil Number identifies a child across all English schools. Validate format server-side and never log it in plaintext error messages.
5. **Audit logs need IP addresses** — for safeguarding investigations, knowing which IP address accessed a student's medical record is as important as knowing which account.

## Further Reading

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [DfE — Unique Pupil Number guidance](https://www.gov.uk/government/publications/unique-pupil-numbers)
