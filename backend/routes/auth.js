'use strict';
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { createHash, randomUUID } = require('node:crypto');
const { body, validationResult } = require('express-validator');
const { getDb }              = require('../db/database');
const { authenticate, JWT_SECRET } = require('../middleware/auth');
const { generateCsrfToken }  = require('../middleware/csrf');

const router = express.Router();
const ACCESS_EXPIRY  = '15m';
const REFRESH_EXPIRY = '7d';

function signAccess(payload)  { return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_EXPIRY,  algorithm: 'HS256' }); }
function signRefresh(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_EXPIRY, algorithm: 'HS256' }); }
function hashToken(t) { return createHash('sha256').update(t).digest('hex'); }

// POST /api/auth/register
router.post('/register', [
  body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9._-]+$/),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }),
  body('role').optional().isIn(['admin', 'teacher', 'student', 'parent']),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(422).json({ errors: errs.array() });

  const { username, email, password, role = 'student' } = req.body;
  const db = getDb();

  try {
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) return res.status(409).json({ error: 'Username or email already exists' });

    const password_hash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS || '12'));
    const result = db.prepare(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)'
    ).run(username, email, password_hash, role);

    res.status(201).json({ id: Number(result.lastInsertRowid), username, email, role });
  } catch {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
router.post('/login', [
  body('username').trim().notEmpty(),
  body('password').notEmpty(),
], async (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(422).json({ errors: errs.array() });

  const { username, password } = req.body;
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  try {
    const payload = { sub: user.id, username: user.username, role: user.role };
    const accessToken  = signAccess(payload);
    const refreshToken = signRefresh({ ...payload, jti: randomUUID() });

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
      hashToken(refreshToken), user.id, expiresAt
    );

    const csrfToken = generateCsrfToken();
    res.setHeader('Set-Cookie', `csrf_token=${csrfToken}; Path=/; SameSite=Strict`);

    db.prepare(
      'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
    ).run(user.id, 'LOGIN', `User ${user.username} logged in`, req.ip || '127.0.0.1');

    res.json({ access_token: accessToken, refresh_token: refreshToken });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(401).json({ error: 'Refresh token required' });

  try {
    const decoded = jwt.verify(refresh_token, JWT_SECRET);
    const db = getDb();
    const stored = db.prepare(
      "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0 AND expires_at > datetime('now')"
    ).get(hashToken(refresh_token));

    if (!stored) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    const newAccessToken = signAccess({ sub: decoded.sub, username: decoded.username, role: decoded.role });
    res.json({ access_token: newAccessToken });
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// POST /api/auth/logout
router.post('/logout', authenticate, (req, res) => {
  const { refresh_token } = req.body || {};
  if (refresh_token) {
    getDb().prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(hashToken(refresh_token));
  }
  res.json({ message: 'Logged out successfully' });
});

// GET /api/auth/me
router.get('/me', authenticate, (req, res) => {
  const user = getDb().prepare(
    'SELECT id, username, email, role, created_at FROM users WHERE id = ?'
  ).get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

module.exports = router;
