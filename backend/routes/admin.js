'use strict';
const { Router } = require('express');
const { getDb } = require('../db/index.js');
const { authenticate, authorize } = require('../middleware/auth.js');

const router = Router();

// GET /api/admin/users — admin only
router.get('/users', authenticate, authorize('admin'), (req, res) => {
  const db = getDb();
  const users = db.prepare(
    'SELECT id, username, email, role, form_group, created_at FROM users ORDER BY created_at DESC'
  ).all();
  res.json(users);
});

// GET /api/admin/audit — admin only
router.get('/audit', authenticate, authorize('admin'), (req, res) => {
  const db = getDb();
  const logs = db.prepare(
    'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 200'
  ).all();
  res.json(logs);
});

// GET /api/admin/stats — admin only
router.get('/stats', authenticate, authorize('admin'), (req, res) => {
  const db = getDb();
  const totalStudents = db.prepare('SELECT COUNT(*) as count FROM students').get().count;
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  const senCount = db.prepare("SELECT COUNT(*) as count FROM students WHERE sen_status != 'none'").get().count;
  const fsmCount = db.prepare('SELECT COUNT(*) as count FROM students WHERE fsm_eligible = 1').get().count;

  const byYearGroup = db.prepare(
    'SELECT year_group, COUNT(*) as count FROM students GROUP BY year_group ORDER BY year_group'
  ).all();

  res.json({ totalStudents, totalUsers, senCount, fsmCount, byYearGroup });
});

module.exports = router;
