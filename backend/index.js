'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const { getDb, closeDb } = require('./db/index.js');

const authRouter = require('./routes/auth.js');
const studentsRouter = require('./routes/students.js');
const adminRouter = require('./routes/admin.js');

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

app.use('/api/auth', authLimiter);
app.use('/api/', apiLimiter);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/auth', authRouter);
app.use('/api/students', studentsRouter);
app.use('/api/admin', adminRouter);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

async function seedDefaultData() {
  const db = getDb();
  const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (existingAdmin) return;

  const seedUsers = [
    { username: 'admin', email: 'admin@cyberlab.local', password: 'Admin@CyberLab1', role: 'admin', form_group: null },
    { username: 'teacher1', email: 'teacher1@cyberlab.local', password: 'Teacher@Pass1', role: 'teacher', form_group: '7A' },
    { username: 'teacher2', email: 'teacher2@cyberlab.local', password: 'Teacher@Pass2', role: 'teacher', form_group: '8B' },
    { username: 'parent1', email: 'parent1@cyberlab.local', password: 'Parent@Pass1', role: 'parent', form_group: null },
    { username: 'student1', email: 'student1@cyberlab.local', password: 'Student@Pass1', role: 'student', form_group: null },
  ];

  const userIds = {};
  for (const u of seedUsers) {
    const hash = await bcrypt.hash(u.password, 12);
    const result = db.prepare(
      'INSERT INTO users (username, email, password_hash, role, form_group) VALUES (?, ?, ?, ?, ?)'
    ).run(u.username, u.email, hash, u.role, u.form_group);
    userIds[u.username] = Number(result.lastInsertRowid);
  }

  const insertStudent = db.prepare(
    `INSERT INTO students
       (user_id, upn, first_name, last_name, date_of_birth, year_group, form_group, sen_status, fsm_eligible, home_address)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const s1 = Number(insertStudent.run(userIds['student1'], 'A123456789001', 'Alice', 'Smith', '2010-09-01', 7, '7A', 'none', 0, '1 Maple Avenue, London, SW1A 1AA').lastInsertRowid);
  const s2 = Number(insertStudent.run(null, 'A123456789002', 'Bob', 'Jones', '2010-04-15', 7, '7A', 'support', 1, '25 Oak Street, London, E1 1AA').lastInsertRowid);
  const s3 = Number(insertStudent.run(null, 'A123456789003', 'Charlie', 'Brown', '2009-11-20', 8, '8B', 'none', 0, '7 Pine Road, London, N1 1AA').lastInsertRowid);
  const s4 = Number(insertStudent.run(null, 'A123456789004', 'Diana', 'Prince', '2009-03-08', 8, '8B', 'ehcp', 0, '42 Elm Close, London, W1A 1AA').lastInsertRowid);
  const s5 = Number(insertStudent.run(null, 'A123456789005', 'Edward', 'Norton', '2008-07-30', 9, '9C', 'none', 1, '15 Birch Lane, London, SE1 1AA').lastInsertRowid);

  db.prepare('INSERT INTO student_parent_links (student_id, parent_user_id) VALUES (?, ?)').run(s1, userIds['parent1']);

  db.prepare(
    'INSERT INTO emergency_contacts (student_id, name, relationship, phone, email, primary_contact) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(s1, 'Jane Smith', 'Mother', '07700900001', 'jane.smith@email.com', 1);

  db.prepare(
    'INSERT INTO emergency_contacts (student_id, name, relationship, phone, email, primary_contact) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(s2, 'Mark Jones', 'Father', '07700900002', 'mark.jones@email.com', 1);
}

async function start(port = 4000) {
  await seedDefaultData();
  return new Promise((resolve) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
  });
}

module.exports = { app, start, closeDb };

if (require.main === module) {
  start(4000).then(() => console.log('Server running on http://127.0.0.1:4000'));
}
