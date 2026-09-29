'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { existsSync, unlinkSync } = require('node:fs');
const { join } = require('node:path');

// Fresh DB + minimum bcrypt cost so the test suite runs in seconds
const testDbPath = join(__dirname, '..', 'backend', 'test_cyberlab.db');
if (existsSync(testDbPath)) unlinkSync(testDbPath);
process.env.DB_PATH       = testDbPath;
process.env.BCRYPT_ROUNDS = '1';

const { start } = require('../backend/index.js');

// Wrap everything in one outer describe with concurrency:1 so all groups and
// all individual tests run sequentially — prevents concurrent bcrypt operations
// from saturating bcryptjs's setImmediate-based async loop and causing ECONNRESET.
describe('SIMS', { concurrency: 1 }, () => {

let server, baseUrl;
let adminToken, teacherToken, studentToken, parentToken;
let adminCsrf, teacherCsrf, studentCsrf, parentCsrf;
let createdStudentId;

function extractCsrf(res) {
  const raw = res.headers.get('set-cookie') || '';
  const m   = raw.match(/csrf_token=([^;,\s]+)/);
  return m ? m[1] : '';
}

async function api(path, method = 'GET', body = null, token = null, csrf = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (csrf && !['GET', 'HEAD'].includes(method)) {
    headers['Cookie']       = `csrf_token=${csrf}`;
    headers['X-CSRF-Token'] = csrf;
  }
  return fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
}

before(async () => {
  const port = 4200 + Math.floor(Math.random() * 700);
  server  = await start(port);
  baseUrl = `http://127.0.0.1:${port}`;

  let r, d;
  r = await api('/api/auth/login', 'POST', { username: 'admin',       password: 'Admin@1234'   });
  d = await r.json(); adminToken = d.access_token; adminCsrf = extractCsrf(r);

  r = await api('/api/auth/login', 'POST', { username: 'ms_johnson',  password: 'Teacher@1234' });
  d = await r.json(); teacherToken = d.access_token; teacherCsrf = extractCsrf(r);

  r = await api('/api/auth/login', 'POST', { username: 'emma.wilson', password: 'Student@1234' });
  d = await r.json(); studentToken = d.access_token; studentCsrf = extractCsrf(r);

  r = await api('/api/auth/login', 'POST', { username: 'p.wilson',    password: 'Parent@1234'  });
  d = await r.json(); parentToken = d.access_token; parentCsrf = extractCsrf(r);
});

after(() => server.close());

// ─── Group 1: Health ─────────────────────────────────────────────────────────
describe('Health', { concurrency: 1 }, () => {
  it('GET /health returns 200', async () => {
    const r = await fetch(`${baseUrl}/health`);
    assert.strictEqual(r.status, 200);
  });

  it('GET /health returns { status: "ok" }', async () => {
    const r = await fetch(`${baseUrl}/health`);
    const d = await r.json();
    assert.strictEqual(d.status, 'ok');
  });
});

// ─── Group 2: Auth flow ───────────────────────────────────────────────────────
describe('Auth flow', { concurrency: 1 }, () => {
  it('register a new user returns 201', async () => {
    const r = await api('/api/auth/register', 'POST', {
      username: 'new_test_user', email: 'new_test@demo.school.uk',
      password: 'TestPass@99',  role: 'student',
    });
    assert.strictEqual(r.status, 201);
    const d = await r.json();
    assert.ok(d.id);
    assert.strictEqual(d.role, 'student');
  });

  it('login with correct credentials returns access_token and refresh_token', async () => {
    const r = await api('/api/auth/login', 'POST', { username: 'admin', password: 'Admin@1234' });
    assert.strictEqual(r.status, 200);
    const d = await r.json();
    assert.ok(d.access_token,  'access_token missing');
    assert.ok(d.refresh_token, 'refresh_token missing');
  });

  it('login with wrong password returns 401', async () => {
    const r = await api('/api/auth/login', 'POST', { username: 'admin', password: 'WrongPass!' });
    assert.strictEqual(r.status, 401);
  });

  it('access protected route without token returns 401', async () => {
    const r = await fetch(`${baseUrl}/api/students`);
    assert.strictEqual(r.status, 401);
  });

  it('access protected route with valid token returns 200', async () => {
    const r = await api('/api/auth/me', 'GET', null, adminToken);
    assert.strictEqual(r.status, 200);
    const d = await r.json();
    assert.strictEqual(d.username, 'admin');
    assert.strictEqual(d.role,     'admin');
  });

  it('refresh token issues a new access_token', async () => {
    const loginR = await api('/api/auth/login', 'POST', { username: 'admin', password: 'Admin@1234' });
    const { refresh_token } = await loginR.json();
    const r = await api('/api/auth/refresh', 'POST', { refresh_token });
    assert.strictEqual(r.status, 200);
    const d = await r.json();
    assert.ok(d.access_token, 'new access_token missing');
  });
});

// ─── Group 3: RBAC ───────────────────────────────────────────────────────────
describe('RBAC', { concurrency: 1 }, () => {
  it('admin lists all 8 students', async () => {
    const r = await api('/api/students', 'GET', null, adminToken);
    assert.strictEqual(r.status, 200);
    const d = await r.json();
    assert.ok(d.length >= 8, `Expected >=8 students, got ${d.length}`);
  });

  it('teacher sees only their form-group students', async () => {
    const r = await api('/api/students', 'GET', null, teacherToken);
    assert.strictEqual(r.status, 200);
    const rows = await r.json();
    assert.ok(rows.length > 0, 'teacher should see at least one student');
    const allowed = new Set(['9A', '10A']);
    for (const s of rows) {
      assert.ok(allowed.has(s.form_group), `Unexpected form_group: ${s.form_group}`);
    }
  });

  it('student sees only their own record', async () => {
    const r = await api('/api/students', 'GET', null, studentToken);
    assert.strictEqual(r.status, 200);
    const rows = await r.json();
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].first_name, 'Emma');
  });

  it('teacher cannot create a student (403)', async () => {
    const r = await api('/api/students', 'POST',
      { upn: 'Z999999999999', first_name: 'Test', last_name: 'User',
        dob: '2010-01-01', year_group: 9, form_group: '9A' },
      teacherToken, teacherCsrf
    );
    assert.strictEqual(r.status, 403);
  });

  it('parent sees only their linked child', async () => {
    const r = await api('/api/students', 'GET', null, parentToken);
    assert.strictEqual(r.status, 200);
    const rows = await r.json();
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].first_name, 'Emma');
  });

  it('non-admin cannot access admin audit-log (403)', async () => {
    const r = await api('/api/admin/audit-log', 'GET', null, teacherToken);
    assert.strictEqual(r.status, 403);
  });
});

// ─── Group 4: Security headers ───────────────────────────────────────────────
describe('Security headers', { concurrency: 1 }, () => {
  let headers;
  before(async () => {
    const r = await fetch(`${baseUrl}/health`);
    headers = r.headers;
  });

  it('X-Content-Type-Options: nosniff', () => {
    assert.strictEqual(headers.get('x-content-type-options'), 'nosniff');
  });

  it('X-Frame-Options: DENY', () => {
    assert.strictEqual(headers.get('x-frame-options'), 'DENY');
  });

  it('Content-Security-Policy present', () => {
    assert.ok(headers.get('content-security-policy'), 'CSP header missing');
  });

  it('Strict-Transport-Security present', () => {
    assert.ok(headers.get('strict-transport-security'), 'HSTS header missing');
  });

  it('X-Powered-By absent (removed by Helmet)', () => {
    assert.strictEqual(headers.get('x-powered-by'), null);
  });
});

// ─── Group 5: Input validation ───────────────────────────────────────────────
describe('Input validation', { concurrency: 1 }, () => {
  it('register with empty username returns 422', async () => {
    const r = await api('/api/auth/register', 'POST', {
      username: '', email: 'x@demo.school.uk', password: 'TestPass@99',
    });
    assert.ok(r.status === 422 || r.status === 400);
  });

  it('register with invalid email returns 422', async () => {
    const r = await api('/api/auth/register', 'POST', {
      username: 'validuser2', email: 'not-an-email', password: 'TestPass@99',
    });
    assert.ok(r.status === 422 || r.status === 400);
  });

  it('create student with invalid UPN returns 422', async () => {
    const r = await api('/api/students', 'POST',
      { upn: 'INVALID', first_name: 'T', last_name: 'U',
        dob: '2010-01-01', year_group: 9, form_group: '9A' },
      adminToken, adminCsrf
    );
    assert.ok(r.status === 422 || r.status === 400);
  });

  it('create student with out-of-range year_group returns 422', async () => {
    const r = await api('/api/students', 'POST',
      { upn: 'Z000000000001', first_name: 'T', last_name: 'U',
        dob: '2010-01-01', year_group: 99, form_group: '9A' },
      adminToken, adminCsrf
    );
    assert.ok(r.status === 422 || r.status === 400);
  });

  it('SQL injection in login username does not crash server', async () => {
    const r = await api('/api/auth/login', 'POST', {
      username: "' OR '1'='1", password: 'anything',
    });
    assert.ok(r.status === 401 || r.status === 422);
  });
});

// ─── Group 6: Business logic ─────────────────────────────────────────────────
describe('Business logic', { concurrency: 1 }, () => {
  it('admin creates a student successfully', async () => {
    const r = await api('/api/students', 'POST', {
      upn: 'X000000000001', first_name: 'Test', last_name: 'Pupil',
      dob: '2010-06-15', year_group: 9, form_group: '9A',
      gender: 'M', sen_status: 'None', fsm_eligibility: false,
    }, adminToken, adminCsrf);
    assert.strictEqual(r.status, 201);
    const d = await r.json();
    assert.ok(d.id);
    createdStudentId = d.id;
  });

  it('admin updates the created student', async () => {
    assert.ok(createdStudentId, 'Need createdStudentId from previous test');
    const r = await api(`/api/students/${createdStudentId}`, 'PUT',
      { form_group: '9B' }, adminToken, adminCsrf
    );
    assert.strictEqual(r.status, 200);
  });

  it('updated student now belongs to new form_group', async () => {
    const r = await api(`/api/students/${createdStudentId}`, 'GET', null, adminToken);
    assert.strictEqual(r.status, 200);
    const d = await r.json();
    assert.strictEqual(d.form_group, '9B');
  });

  it('admin deletes the created student', async () => {
    const r = await api(`/api/students/${createdStudentId}`, 'DELETE', null, adminToken, adminCsrf);
    assert.strictEqual(r.status, 200);
  });

  it('deleted student returns 404', async () => {
    const r = await api(`/api/students/${createdStudentId}`, 'GET', null, adminToken);
    assert.strictEqual(r.status, 404);
  });

  it('admin audit log records student access', async () => {
    const sListR = await api('/api/students', 'GET', null, adminToken);
    const students = await sListR.json();
    if (students.length > 0) {
      await api(`/api/students/${students[0].id}`, 'GET', null, adminToken);
    }
    const r = await api('/api/admin/audit-log', 'GET', null, adminToken);
    assert.strictEqual(r.status, 200);
    const logs = await r.json();
    assert.ok(Array.isArray(logs));
    assert.ok(logs.length > 0, 'Audit log should have entries');
  });

  it('teacher cannot see student from another form group (403)', async () => {
    const allR = await api('/api/students', 'GET', null, adminToken);
    const all  = await allR.json();
    const ethan = all.find(s => s.last_name === 'Kowalski');
    assert.ok(ethan, 'Ethan Kowalski should exist');
    const r = await api(`/api/students/${ethan.id}`, 'GET', null, teacherToken);
    assert.strictEqual(r.status, 403);
  });

  it('parent cannot access another student (403)', async () => {
    const allR = await api('/api/students', 'GET', null, adminToken);
    const all  = await allR.json();
    const sofia = all.find(s => s.last_name === 'Rahman');
    assert.ok(sofia, 'Sofia Rahman should exist');
    const r = await api(`/api/students/${sofia.id}`, 'GET', null, parentToken);
    assert.strictEqual(r.status, 403);
  });

  it('emergency contacts returned for authorised user', async () => {
    const myR    = await api('/api/students', 'GET', null, studentToken);
    const myData = await myR.json();
    assert.ok(myData.length > 0, 'student should see their own record');
    const r = await api(`/api/students/${myData[0].id}/emergency-contacts`, 'GET', null, studentToken);
    assert.strictEqual(r.status, 200);
    const contacts = await r.json();
    assert.ok(Array.isArray(contacts));
    assert.ok(contacts.length >= 1, 'Emma should have at least one emergency contact');
  });

  it('CSRF missing on state-changing request returns 403', async () => {
    const headers = {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${adminToken}`,
    };
    const r = await fetch(`${baseUrl}/api/students`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ upn: 'Z999999999998', first_name: 'Bad', last_name: 'Actor',
        dob: '2010-01-01', year_group: 9, form_group: '9A' }),
    });
    assert.strictEqual(r.status, 403);
  });
});

}); // end outer describe
