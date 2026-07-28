'use strict';
const { Router } = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('node:crypto');
const { getDb } = require('../db/index.js');
const { authenticate, JWT_SECRET } = require('../middleware/auth.js');
const { csrfProtect } = require('../middleware/csrf.js');

const router = Router();
const REFRESH_EXPIRY_DAYS = 7;
const ACCESS_EXPIRY = '15m';

function signAccess(payload) {
  const jti = randomUUID();
  const token = jwt.sign({ ...payload, jti }, JWT_SECRET, { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' });
  return { token, jti };
}

const registerValidation = [
  body('username').trim().notEmpty().withMessage('Username is required')
    .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username may only contain letters, numbers, and underscores'),
  body('email').trim().isEmail().withMessage('Valid email required').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('role').optional().isIn(['student', 'parent']).withMessage('Role must be student or parent'),
];

router.post('/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

  const { username, email, password, role = 'student' } = req.body;
  const db = getDb();

  const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
  if (existing) return res.status(409).json({ error: 'Username or email already taken' });

  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare(
    'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)'
  ).run(username, email, hash, role);

  const id = Number(result.lastInsertRowid);
  db.prepare(
    'INSERT INTO audit_log (action, target_type, target_id, ip_address) VALUES (?, ?, ?, ?)'
  ).run('user_registered', 'user', id, req.ip || '');

  res.status(201).json({ id, username, email, role });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(String(password), user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const { token: access_token, jti } = signAccess({ sub: user.id, username: user.username, role: user.role });
  const refreshToken = randomUUID();
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRY_DAYS * 86400000).toISOString();

  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
  ).run(user.id, refreshToken, expiresAt);

  db.prepare(
    'INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)'
  ).run(user.id, 'login', req.ip || '');

  res.json({ access_token, refresh_token: refreshToken, csrf_token: jti });
});

router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

  const db = getDb();
  const stored = db.prepare(
    `SELECT rt.*, u.username, u.role
     FROM refresh_tokens rt
     JOIN users u ON rt.user_id = u.id
     WHERE rt.token = ?`
  ).get(refresh_token);

  if (!stored || stored.revoked || new Date(stored.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  const { token: access_token, jti } = signAccess({
    sub: stored.user_id,
    username: stored.username,
    role: stored.role,
  });

  res.json({ access_token, csrf_token: jti });
});

router.post('/logout', authenticate, csrfProtect, (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) {
    const db = getDb();
    db.prepare(
      'UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND user_id = ?'
    ).run(refresh_token, req.user.sub);
    db.prepare(
      'INSERT INTO audit_log (user_id, action, ip_address) VALUES (?, ?, ?)'
    ).run(req.user.sub, 'logout', req.ip || '');
  }
  res.json({ message: 'Logged out' });
});

router.get('/me', authenticate, (req, res) => {
  const db = getDb();
  const user = db.prepare(
    'SELECT id, username, email, role, form_group, created_at FROM users WHERE id = ?'
  ).get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

module.exports = router;
