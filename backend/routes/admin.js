'use strict';
const express = require('express');
const { getDb }             = require('../db/database');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

// GET /api/admin/audit-log (admin only)
router.get('/audit-log', authenticate, requireRole('admin'), (req, res) => {
  const db    = getDb();
  const limit  = Math.min(parseInt(req.query.limit)  || 100, 500);
  const offset = Math.max(parseInt(req.query.offset) || 0,   0);
  const logs = db.prepare(
    `SELECT al.*, u.username FROM audit_log al
     LEFT JOIN users u ON u.id = al.user_id
     ORDER BY al.timestamp DESC LIMIT ? OFFSET ?`
  ).all(limit, offset);
  res.json(logs);
});

// GET /api/admin/users (admin only)
router.get('/users', authenticate, requireRole('admin'), (req, res) => {
  const users = getDb().prepare(
    'SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC'
  ).all();
  res.json(users);
});

module.exports = router;
