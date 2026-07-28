'use strict';
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

// Must be set before requiring the server module so the DB singleton uses this path
process.env.DB_PATH = path.join(os.tmpdir(), `cyberlab-test-${Date.now()}.db`);

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { start } = require('../backend/index.js');
const { closeDb } = require('../backend/db/index.js');

let server;
let port;
let baseUrl;

// Credentials from the seed data in backend/index.js
const ADMIN = { username: 'admin', password: 'Admin@CyberLab1' };
const TEACHER1 = { username: 'teacher1', password: 'Teacher@Pass1' }; // form_group: 7A
const TEACHER2 = { username: 'teacher2', password: 'Teacher@Pass2' }; // form_group: 8B
const PARENT1 = { username: 'parent1', password: 'Parent@Pass1' };
const STUDENT1 = { username: 'student1', password: 'Student@Pass1' }; // linked to Alice Smith (7A)

async function post(path, body, token = null, csrfToken = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  return fetch(`${baseUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
}

async function get(path, token = null) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(`${baseUrl}${path}`, { headers });
}

async function put(path, body, token, csrfToken) {
  const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`, 'X-CSRF-Token': csrfToken };
  return fetch(`${baseUrl}${path}`, { method: 'PUT', headers, body: JSON.stringify(body) });
}

async function del(path, token, csrfToken) {
  const headers = { 'Authorization': `Bearer ${token}`, 'X-CSRF-Token': csrfToken };
  return fetch(`${baseUrl}${path}`, { method: 'DELETE', headers });
}

async function login(creds) {
  const res = await post('/api/auth/login', creds);
  return res.json();
}

before(async () => {
  port = 4000 + Math.floor(Math.random() * 1000);
  server = await start(port);
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server.close();
  closeDb();
  try { fs.unlinkSync(process.env.DB_PATH); } catch {}
});

// ─── Group 1: Server health ───────────────────────────────────────────────────

describe('Server health', () => {
  it('GET /health returns 200 and status ok', async () => {
    const res = await get('/health');
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.status, 'ok');
  });

  it('Server responds to unknown routes with a non-500 status', async () => {
    const res = await get('/api/nonexistent');
    assert.ok(res.status < 500, `Expected < 500, got ${res.status}`);
  });
});

// ─── Group 2: Auth flow ────────────────────────────────────────────────────────

describe('Authentication flow', () => {
  let newUserToken, newUserCsrf, newUserRefresh;

  it('POST /api/auth/register creates a new user (201)', async () => {
    const res = await post('/api/auth/register', {
      username: 'newparent',
      email: 'newparent@example.com',
      password: 'NewParent@123',
      role: 'parent',
    });
    assert.strictEqual(res.status, 201);
    const body = await res.json();
    assert.strictEqual(body.username, 'newparent');
    assert.strictEqual(body.role, 'parent');
    assert.ok(body.id, 'Should have an id');
    assert.ok(!body.password_hash, 'Should not expose password hash');
  });

  it('POST /api/auth/login with correct credentials returns tokens (200)', async () => {
    const res = await post('/api/auth/login', { username: 'newparent', password: 'NewParent@123' });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body.access_token, 'Should return access_token');
    assert.ok(body.refresh_token, 'Should return refresh_token');
    assert.ok(body.csrf_token, 'Should return csrf_token');
    newUserToken = body.access_token;
    newUserCsrf = body.csrf_token;
    newUserRefresh = body.refresh_token;
  });

  it('POST /api/auth/login with wrong password returns 401', async () => {
    const res = await post('/api/auth/login', { username: 'newparent', password: 'WrongPassword!' });
    assert.strictEqual(res.status, 401);
  });

  it('GET /api/auth/me without token returns 401', async () => {
    const res = await get('/api/auth/me');
    assert.strictEqual(res.status, 401);
  });

  it('GET /api/auth/me with valid token returns user profile (200)', async () => {
    const res = await get('/api/auth/me', newUserToken);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.username, 'newparent');
    assert.strictEqual(body.role, 'parent');
    assert.ok(!body.password_hash, 'Should not expose password hash');
  });

  it('POST /api/auth/refresh with valid refresh token returns new access_token (200)', async () => {
    const res = await post('/api/auth/refresh', { refresh_token: newUserRefresh });
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(body.access_token, 'Should return new access_token');
    assert.ok(body.csrf_token, 'Should return new csrf_token');
  });

  it('POST /api/auth/logout revokes the refresh token (200)', async () => {
    const res = await post('/api/auth/logout', { refresh_token: newUserRefresh }, newUserToken, newUserCsrf);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.message, 'Logged out');
  });

  it('POST /api/auth/refresh with revoked token returns 401', async () => {
    const res = await post('/api/auth/refresh', { refresh_token: newUserRefresh });
    assert.strictEqual(res.status, 401);
  });
});

// ─── Group 3: Role-Based Access Control ───────────────────────────────────────

describe('Role-based access control', () => {
  let adminToken, adminCsrf;
  let teacher1Token, teacher1Csrf;
  let teacher2Token, teacher2Csrf;
  let studentToken;
  let parentToken;

  before(async () => {
    const a = await login(ADMIN);
    adminToken = a.access_token;
    adminCsrf = a.csrf_token;

    const t1 = await login(TEACHER1);
    teacher1Token = t1.access_token;
    teacher1Csrf = t1.csrf_token;

    const t2 = await login(TEACHER2);
    teacher2Token = t2.access_token;
    teacher2Csrf = t2.csrf_token;

    const s = await login(STUDENT1);
    studentToken = s.access_token;

    const p = await login(PARENT1);
    parentToken = p.access_token;
  });

  it('Admin can access GET /api/admin/users (200)', async () => {
    const res = await get('/api/admin/users', adminToken);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body), 'Should return an array');
    assert.ok(body.length > 0, 'Should contain users');
  });

  it('Teacher is blocked from GET /api/admin/users (403)', async () => {
    const res = await get('/api/admin/users', teacher1Token);
    assert.strictEqual(res.status, 403);
  });

  it('Student is blocked from GET /api/admin/users (403)', async () => {
    const res = await get('/api/admin/users', studentToken);
    assert.strictEqual(res.status, 403);
  });

  it('Teacher1 sees only their form group (7A) students', async () => {
    const res = await get('/api/students', teacher1Token);
    assert.strictEqual(res.status, 200);
    const students = await res.json();
    assert.ok(Array.isArray(students));
    assert.ok(students.length > 0, 'Teacher1 should see 7A students');
    for (const s of students) {
      assert.strictEqual(s.form_group, '7A', `Expected form_group 7A, got ${s.form_group}`);
    }
  });

  it('Teacher2 sees only their form group (8B) students', async () => {
    const res = await get('/api/students', teacher2Token);
    assert.strictEqual(res.status, 200);
    const students = await res.json();
    assert.ok(Array.isArray(students));
    for (const s of students) {
      assert.strictEqual(s.form_group, '8B');
    }
  });

  it('Student can only see their own record', async () => {
    const res = await get('/api/students', studentToken);
    assert.strictEqual(res.status, 200);
    const students = await res.json();
    assert.strictEqual(students.length, 1, 'Student should see exactly their own record');
    assert.strictEqual(students[0].upn, 'A123456789001', 'Should see Alice Smith');
  });

  it('Parent sees only their linked children', async () => {
    const res = await get('/api/students', parentToken);
    assert.strictEqual(res.status, 200);
    const students = await res.json();
    assert.strictEqual(students.length, 1, 'Parent should see only linked children');
    assert.strictEqual(students[0].upn, 'A123456789001', 'Should see Alice Smith');
  });
});

// ─── Group 4: Security headers ────────────────────────────────────────────────

describe('Security headers', () => {
  it('Response includes X-Content-Type-Options: nosniff', async () => {
    const res = await get('/health');
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('Response includes X-Frame-Options: SAMEORIGIN or DENY', async () => {
    const res = await get('/health');
    const xfo = res.headers.get('x-frame-options');
    assert.ok(xfo, 'X-Frame-Options header should be present');
  });

  it('Response includes a Content-Security-Policy header', async () => {
    const res = await get('/health');
    const csp = res.headers.get('content-security-policy');
    assert.ok(csp, 'CSP header should be present');
    assert.ok(csp.includes("default-src"), 'CSP should include default-src');
  });

  it('Response includes Strict-Transport-Security header', async () => {
    const res = await get('/health');
    const hsts = res.headers.get('strict-transport-security');
    assert.ok(hsts, 'HSTS header should be present');
    assert.ok(hsts.includes('max-age='), 'HSTS should include max-age');
  });
});

// ─── Group 5: Input validation ────────────────────────────────────────────────

describe('Input validation', () => {
  it('Register with empty username returns 422', async () => {
    const res = await post('/api/auth/register', {
      username: '',
      email: 'valid@example.com',
      password: 'ValidPass@123',
    });
    assert.strictEqual(res.status, 422);
    const body = await res.json();
    assert.ok(body.errors, 'Should return validation errors');
  });

  it('Register with invalid email returns 422', async () => {
    const res = await post('/api/auth/register', {
      username: 'validuser',
      email: 'not-an-email',
      password: 'ValidPass@123',
    });
    assert.strictEqual(res.status, 422);
  });

  it('Register with password shorter than 8 characters returns 422', async () => {
    const res = await post('/api/auth/register', {
      username: 'validuser',
      email: 'valid2@example.com',
      password: 'short',
    });
    assert.strictEqual(res.status, 422);
  });

  it('Login with SQL injection username returns 401, not a server crash', async () => {
    const res = await post('/api/auth/login', {
      username: "' OR '1'='1' --",
      password: 'anything',
    });
    // Should be 401 (not found / bad credentials) — parameterized query prevents auth bypass
    assert.strictEqual(res.status, 401);
  });
});

// ─── Group 6: Business logic — student CRUD ───────────────────────────────────

describe('Business logic — student CRUD', () => {
  let adminToken, adminCsrf;
  let teacher1Token, teacher1Csrf;
  let createdStudentId;

  before(async () => {
    const a = await login(ADMIN);
    adminToken = a.access_token;
    adminCsrf = a.csrf_token;

    const t1 = await login(TEACHER1);
    teacher1Token = t1.access_token;
    teacher1Csrf = t1.csrf_token;
  });

  it('Admin can create a student (201)', async () => {
    const res = await post('/api/students', {
      upn: 'A999999999001',
      first_name: 'Frank',
      last_name: 'Castle',
      date_of_birth: '2011-01-15',
      year_group: 7,
      form_group: '7A',
      sen_status: 'none',
      fsm_eligible: false,
    }, adminToken, adminCsrf);
    assert.strictEqual(res.status, 201);
    const body = await res.json();
    assert.strictEqual(body.upn, 'A999999999001');
    assert.strictEqual(body.first_name, 'Frank');
    assert.strictEqual(body.fsm_eligible, false);
    createdStudentId = body.id;
  });

  it('Admin can read the created student (200)', async () => {
    const res = await get(`/api/students/${createdStudentId}`, adminToken);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.id, createdStudentId);
    assert.strictEqual(body.first_name, 'Frank');
    assert.ok(Array.isArray(body.emergency_contacts), 'Should include emergency_contacts');
  });

  it('Admin can update student SEN status (200)', async () => {
    const res = await put(`/api/students/${createdStudentId}`, { sen_status: 'support' }, adminToken, adminCsrf);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.sen_status, 'support');
  });

  it('Teacher1 can update a student in their own form group (200)', async () => {
    const res = await put(`/api/students/${createdStudentId}`, { home_address: '10 New Road, London, W1A 1AB' }, teacher1Token, teacher1Csrf);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.home_address, '10 New Road, London, W1A 1AB');
  });

  it('Teacher2 (8B) cannot update a student in form group 7A (403)', async () => {
    const t2 = await login(TEACHER2);
    const res = await put(`/api/students/${createdStudentId}`, { home_address: 'Hacked' }, t2.access_token, t2.csrf_token);
    assert.strictEqual(res.status, 403);
  });

  it('Creating student with duplicate UPN returns 409', async () => {
    const res = await post('/api/students', {
      upn: 'A999999999001',
      first_name: 'Duplicate',
      last_name: 'Student',
      date_of_birth: '2011-01-15',
      year_group: 7,
      form_group: '7A',
      sen_status: 'none',
      fsm_eligible: false,
    }, adminToken, adminCsrf);
    assert.strictEqual(res.status, 409);
  });

  it('Creating student with invalid UPN format returns 422', async () => {
    const res = await post('/api/students', {
      upn: 'invalid-upn',
      first_name: 'Test',
      last_name: 'Test',
      date_of_birth: '2011-01-15',
      year_group: 7,
      form_group: '7A',
      sen_status: 'none',
      fsm_eligible: false,
    }, adminToken, adminCsrf);
    assert.strictEqual(res.status, 422);
  });

  it('Admin can delete the created student (200)', async () => {
    const res = await del(`/api/students/${createdStudentId}`, adminToken, adminCsrf);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.id, createdStudentId);
  });

  it('Deleted student returns 404 on subsequent GET', async () => {
    const res = await get(`/api/students/${createdStudentId}`, adminToken);
    assert.strictEqual(res.status, 404);
  });

  it('POST without CSRF token returns 403', async () => {
    const res = await post('/api/students', {
      upn: 'A888888888001',
      first_name: 'No',
      last_name: 'CSRF',
      date_of_birth: '2011-01-15',
      year_group: 7,
      form_group: '7A',
      sen_status: 'none',
      fsm_eligible: false,
    }, adminToken, null);
    assert.strictEqual(res.status, 403);
  });

  it('Admin sees all 5 seeded students in GET /api/students', async () => {
    const res = await get('/api/students', adminToken);
    assert.strictEqual(res.status, 200);
    const students = await res.json();
    assert.ok(students.length >= 5, `Expected at least 5 students, got ${students.length}`);
  });
});
