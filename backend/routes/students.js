'use strict';
const express = require('express');
const { body, param, validationResult } = require('express-validator');
const { getDb }               = require('../db/database');
const { authenticate, requireRole } = require('../middleware/auth');

const router = express.Router();

function canAccess(user, student, db) {
  if (user.role === 'admin') return true;
  if (user.role === 'teacher') {
    return !!db.prepare(
      'SELECT id FROM teacher_formgroup WHERE teacher_user_id = ? AND form_group = ?'
    ).get(user.sub, student.form_group);
  }
  if (user.role === 'student') return student.user_id === user.sub;
  if (user.role === 'parent') {
    return !!db.prepare(
      'SELECT id FROM parent_student WHERE parent_user_id = ? AND student_id = ?'
    ).get(user.sub, student.id);
  }
  return false;
}

// GET /api/students
router.get('/', authenticate, (req, res) => {
  const db = getDb();
  const COLS = 'id, upn, first_name, last_name, year_group, form_group, sen_status, fsm_eligibility, gender';
  let rows;

  if (req.user.role === 'admin') {
    rows = db.prepare(`SELECT ${COLS} FROM students ORDER BY last_name, first_name`).all();
  } else if (req.user.role === 'teacher') {
    const fgs = db.prepare('SELECT form_group FROM teacher_formgroup WHERE teacher_user_id = ?').all(req.user.sub);
    if (!fgs.length) return res.json([]);
    const ph = fgs.map(() => '?').join(',');
    rows = db.prepare(`SELECT ${COLS} FROM students WHERE form_group IN (${ph}) ORDER BY last_name, first_name`)
             .all(...fgs.map(r => r.form_group));
  } else if (req.user.role === 'student') {
    rows = db.prepare(`SELECT ${COLS} FROM students WHERE user_id = ?`).all(req.user.sub);
  } else if (req.user.role === 'parent') {
    rows = db.prepare(
      `SELECT s.id, s.upn, s.first_name, s.last_name, s.year_group, s.form_group, s.sen_status, s.fsm_eligibility, s.gender
       FROM students s JOIN parent_student ps ON ps.student_id = s.id
       WHERE ps.parent_user_id = ? ORDER BY s.last_name, s.first_name`
    ).all(req.user.sub);
  } else {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  res.json(rows);
});

// GET /api/students/:id
router.get('/:id', authenticate, [param('id').isInt({ min: 1 })], (req, res) => {
  if (!validationResult(req).isEmpty()) return res.status(422).json({ error: 'Invalid student id' });
  const db = getDb();
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(req.params.id));
  if (!student) return res.status(404).json({ error: 'Student not found' });
  if (!canAccess(req.user, student, db)) return res.status(403).json({ error: 'Access denied' });

  db.prepare(
    'INSERT INTO audit_log (user_id, action, entity_type, entity_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'VIEW_STUDENT', 'student', student.id, req.ip || '127.0.0.1');

  res.json(student);
});

// POST /api/students (admin only)
router.post('/', authenticate, requireRole('admin'), [
  body('upn').trim().isLength({ min: 13, max: 13 }).matches(/^[A-Z]\d{12}$/),
  body('first_name').trim().isLength({ min: 1, max: 50 }),
  body('last_name').trim().isLength({ min: 1, max: 50 }),
  body('dob').isDate(),
  body('year_group').isInt({ min: 7, max: 13 }),
  body('form_group').trim().isLength({ min: 1, max: 10 }),
  body('gender').optional().isIn(['M', 'F', 'Other']),
  body('sen_status').optional().isIn(['None', 'SEN Support', 'EHCP']),
  body('fsm_eligibility').optional().isBoolean(),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(422).json({ errors: errs.array() });

  const { upn, first_name, last_name, dob, year_group, form_group,
          gender = null, sen_status = 'None', fsm_eligibility = false } = req.body;
  const db = getDb();

  try {
    const result = db.prepare(
      `INSERT INTO students (upn, first_name, last_name, dob, year_group, form_group, gender, sen_status, fsm_eligibility)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(upn, first_name, last_name, dob, year_group, form_group, gender, sen_status, fsm_eligibility ? 1 : 0);

    db.prepare(
      'INSERT INTO audit_log (user_id, action, entity_type, entity_id, ip_address) VALUES (?, ?, ?, ?, ?)'
    ).run(req.user.sub, 'CREATE_STUDENT', 'student', Number(result.lastInsertRowid), req.ip || '127.0.0.1');

    res.status(201).json({ id: Number(result.lastInsertRowid), upn, first_name, last_name, year_group, form_group });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: 'UPN already exists' });
    res.status(500).json({ error: 'Failed to create student' });
  }
});

// PUT /api/students/:id (admin only)
router.put('/:id', authenticate, requireRole('admin'), [
  param('id').isInt({ min: 1 }),
  body('first_name').optional().trim().isLength({ min: 1, max: 50 }),
  body('last_name').optional().trim().isLength({ min: 1, max: 50 }),
  body('year_group').optional().isInt({ min: 7, max: 13 }),
  body('form_group').optional().trim().isLength({ min: 1, max: 10 }),
  body('sen_status').optional().isIn(['None', 'SEN Support', 'EHCP']),
  body('fsm_eligibility').optional().isBoolean(),
  body('gender').optional().isIn(['M', 'F', 'Other']),
], (req, res) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(422).json({ errors: errs.array() });

  const db = getDb();
  const id = Number(req.params.id);
  if (!db.prepare('SELECT id FROM students WHERE id = ?').get(id)) {
    return res.status(404).json({ error: 'Student not found' });
  }

  const { first_name, last_name, year_group, form_group, sen_status, fsm_eligibility, gender } = req.body;

  db.prepare(`UPDATE students SET
    first_name      = COALESCE(?, first_name),
    last_name       = COALESCE(?, last_name),
    year_group      = COALESCE(?, year_group),
    form_group      = COALESCE(?, form_group),
    sen_status      = COALESCE(?, sen_status),
    fsm_eligibility = COALESCE(?, fsm_eligibility),
    gender          = COALESCE(?, gender),
    updated_at      = datetime('now')
    WHERE id = ?
  `).run(
    first_name ?? null, last_name ?? null, year_group ?? null, form_group ?? null,
    sen_status ?? null,
    fsm_eligibility !== undefined ? (fsm_eligibility ? 1 : 0) : null,
    gender ?? null, id
  );

  db.prepare(
    'INSERT INTO audit_log (user_id, action, entity_type, entity_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'UPDATE_STUDENT', 'student', id, req.ip || '127.0.0.1');

  res.json({ message: 'Student updated' });
});

// DELETE /api/students/:id (admin only)
router.delete('/:id', authenticate, requireRole('admin'), [param('id').isInt({ min: 1 })], (req, res) => {
  if (!validationResult(req).isEmpty()) return res.status(422).json({ error: 'Invalid id' });
  const db = getDb();
  const id = Number(req.params.id);
  if (!db.prepare('SELECT id FROM students WHERE id = ?').get(id)) {
    return res.status(404).json({ error: 'Student not found' });
  }
  db.prepare('DELETE FROM students WHERE id = ?').run(id);
  db.prepare(
    'INSERT INTO audit_log (user_id, action, entity_type, entity_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'DELETE_STUDENT', 'student', id, req.ip || '127.0.0.1');
  res.json({ message: 'Student deleted' });
});

// GET /api/students/:id/emergency-contacts
router.get('/:id/emergency-contacts', authenticate, [param('id').isInt({ min: 1 })], (req, res) => {
  if (!validationResult(req).isEmpty()) return res.status(422).json({ error: 'Invalid id' });
  const db = getDb();
  const id = Number(req.params.id);
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(id);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  if (!canAccess(req.user, student, db)) return res.status(403).json({ error: 'Access denied' });
  res.json(db.prepare('SELECT * FROM emergency_contacts WHERE student_id = ? ORDER BY priority').all(id));
});

// GET /api/students/:id/medical
router.get('/:id/medical', authenticate, [param('id').isInt({ min: 1 })], (req, res) => {
  if (!validationResult(req).isEmpty()) return res.status(422).json({ error: 'Invalid id' });
  const db = getDb();
  const id = Number(req.params.id);
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(id);
  if (!student) return res.status(404).json({ error: 'Student not found' });
  if (!canAccess(req.user, student, db)) return res.status(403).json({ error: 'Access denied' });
  res.json(db.prepare('SELECT * FROM medical_info WHERE student_id = ?').get(id) || {});
});

module.exports = router;
