'use strict';
const { Router } = require('express');
const { body, validationResult } = require('express-validator');
const { getDb } = require('../db/index.js');
const { authenticate, authorize } = require('../middleware/auth.js');
const { csrfProtect } = require('../middleware/csrf.js');

const router = Router();

function formatStudent(row) {
  return {
    id: row.id,
    user_id: row.user_id || null,
    upn: row.upn,
    first_name: row.first_name,
    last_name: row.last_name,
    date_of_birth: row.date_of_birth,
    year_group: row.year_group,
    form_group: row.form_group,
    sen_status: row.sen_status,
    fsm_eligible: row.fsm_eligible === 1,
    home_address: row.home_address || null,
    medical_notes: row.medical_notes || null,
    gdpr_consent: row.gdpr_consent === 1,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function canAccessStudent(user, student) {
  if (user.role === 'admin') return true;
  if (user.role === 'teacher') {
    const db = getDb();
    const teacher = db.prepare('SELECT form_group FROM users WHERE id = ?').get(user.sub);
    return teacher && teacher.form_group === student.form_group;
  }
  if (user.role === 'student') return student.user_id === user.sub;
  if (user.role === 'parent') {
    const db = getDb();
    const link = db.prepare(
      'SELECT 1 FROM student_parent_links WHERE student_id = ? AND parent_user_id = ?'
    ).get(student.id, user.sub);
    return !!link;
  }
  return false;
}

const createValidation = [
  body('upn').trim().matches(/^[A-Z][0-9]{12}$/).withMessage('UPN must be a letter followed by 12 digits'),
  body('first_name').trim().notEmpty().isLength({ max: 50 }),
  body('last_name').trim().notEmpty().isLength({ max: 50 }),
  body('date_of_birth').isDate().withMessage('date_of_birth must be a valid date (YYYY-MM-DD)'),
  body('year_group').isInt({ min: 7, max: 13 }),
  body('form_group').trim().notEmpty().isLength({ max: 10 }),
  body('sen_status').isIn(['none', 'support', 'ehcp']),
  body('fsm_eligible').isBoolean(),
];

const updateValidation = [
  body('first_name').optional().trim().notEmpty().isLength({ max: 50 }),
  body('last_name').optional().trim().notEmpty().isLength({ max: 50 }),
  body('date_of_birth').optional().isDate(),
  body('year_group').optional().isInt({ min: 7, max: 13 }),
  body('form_group').optional().trim().notEmpty().isLength({ max: 10 }),
  body('sen_status').optional().isIn(['none', 'support', 'ehcp']),
  body('fsm_eligible').optional().isBoolean(),
  body('home_address').optional().trim().isLength({ max: 200 }),
  body('medical_notes').optional().trim().isLength({ max: 500 }),
];

// GET /api/students — role-filtered list
router.get('/', authenticate, (req, res) => {
  const db = getDb();
  let rows;

  if (req.user.role === 'admin') {
    rows = db.prepare('SELECT * FROM students ORDER BY last_name, first_name').all();
  } else if (req.user.role === 'teacher') {
    const teacher = db.prepare('SELECT form_group FROM users WHERE id = ?').get(req.user.sub);
    if (!teacher || !teacher.form_group) return res.json([]);
    rows = db.prepare(
      'SELECT * FROM students WHERE form_group = ? ORDER BY last_name, first_name'
    ).all(teacher.form_group);
  } else if (req.user.role === 'student') {
    rows = db.prepare('SELECT * FROM students WHERE user_id = ?').all(req.user.sub);
  } else if (req.user.role === 'parent') {
    rows = db.prepare(
      `SELECT s.* FROM students s
       INNER JOIN student_parent_links l ON s.id = l.student_id
       WHERE l.parent_user_id = ?
       ORDER BY s.last_name, s.first_name`
    ).all(req.user.sub);
  } else {
    return res.status(403).json({ error: 'Access denied' });
  }

  res.json(rows.map(formatStudent));
});

// GET /api/students/:id
router.get('/:id', authenticate, (req, res) => {
  const db = getDb();
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(req.params.id));
  if (!student) return res.status(404).json({ error: 'Student not found' });

  if (!canAccessStudent(req.user, student)) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const contacts = db.prepare(
    'SELECT id, name, relationship, phone, email, primary_contact FROM emergency_contacts WHERE student_id = ?'
  ).all(student.id);

  res.json({ ...formatStudent(student), emergency_contacts: contacts });
});

// POST /api/students — admin only
router.post('/', authenticate, authorize('admin'), csrfProtect, createValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

  const {
    upn, first_name, last_name, date_of_birth,
    year_group, form_group, sen_status, fsm_eligible,
    home_address = null, medical_notes = null,
  } = req.body;

  const db = getDb();
  const existing = db.prepare('SELECT id FROM students WHERE upn = ?').get(upn);
  if (existing) return res.status(409).json({ error: 'A student with this UPN already exists' });

  const result = db.prepare(
    `INSERT INTO students
       (upn, first_name, last_name, date_of_birth, year_group, form_group, sen_status, fsm_eligible, home_address, medical_notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(upn, first_name, last_name, date_of_birth, year_group, form_group, sen_status, fsm_eligible ? 1 : 0, home_address, medical_notes);

  const id = Number(result.lastInsertRowid);
  db.prepare(
    'INSERT INTO audit_log (user_id, action, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'student_created', 'student', id, req.ip || '');

  const created = db.prepare('SELECT * FROM students WHERE id = ?').get(id);
  res.status(201).json(formatStudent(created));
});

// PUT /api/students/:id — admin or teacher (own form group only)
router.put('/:id', authenticate, csrfProtect, updateValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

  const db = getDb();
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(req.params.id));
  if (!student) return res.status(404).json({ error: 'Student not found' });

  if (req.user.role === 'student' || req.user.role === 'parent') {
    return res.status(403).json({ error: 'Access denied' });
  }

  if (req.user.role === 'teacher') {
    const teacher = db.prepare('SELECT form_group FROM users WHERE id = ?').get(req.user.sub);
    if (!teacher || teacher.form_group !== student.form_group) {
      return res.status(403).json({ error: 'You can only update students in your form group' });
    }
    // Teachers cannot modify SEN status or FSM eligibility
    delete req.body.sen_status;
    delete req.body.fsm_eligible;
  }

  const allowed = ['first_name', 'last_name', 'date_of_birth', 'year_group', 'form_group',
    'sen_status', 'fsm_eligible', 'home_address', 'medical_notes'];
  const updates = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }
  if (updates.fsm_eligible !== undefined) {
    updates.fsm_eligible = updates.fsm_eligible ? 1 : 0;
  }

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  const setClauses = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  const values = [...Object.values(updates), Number(req.params.id)];
  db.prepare(`UPDATE students SET ${setClauses}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(...values);

  db.prepare(
    'INSERT INTO audit_log (user_id, action, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'student_updated', 'student', student.id, req.ip || '');

  const updated = db.prepare('SELECT * FROM students WHERE id = ?').get(student.id);
  res.json(formatStudent(updated));
});

// DELETE /api/students/:id — admin only
router.delete('/:id', authenticate, authorize('admin'), csrfProtect, (req, res) => {
  const db = getDb();
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(Number(req.params.id));
  if (!student) return res.status(404).json({ error: 'Student not found' });

  db.prepare('DELETE FROM emergency_contacts WHERE student_id = ?').run(student.id);
  db.prepare('DELETE FROM student_parent_links WHERE student_id = ?').run(student.id);
  db.prepare('DELETE FROM students WHERE id = ?').run(student.id);

  db.prepare(
    'INSERT INTO audit_log (user_id, action, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.sub, 'student_deleted', 'student', student.id, req.ip || '');

  res.json({ message: 'Student deleted', id: student.id });
});

module.exports = router;
