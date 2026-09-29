'use strict';
const bcrypt = require('bcryptjs');
const { getDb } = require('./database');

async function seed() {
  const db = getDb();
  const existing = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (existing.c > 0) return;

  const rounds = parseInt(process.env.BCRYPT_ROUNDS || '12');
  const adminHash   = await bcrypt.hash('Admin@1234',   rounds);
  const teacherHash = await bcrypt.hash('Teacher@1234', rounds);
  const studentHash = await bcrypt.hash('Student@1234', rounds);
  const parentHash  = await bcrypt.hash('Parent@1234',  rounds);

  const ins = db.prepare(
    'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)'
  );

  const admin    = ins.run('admin',        'admin@demo.school.uk',         adminHash,   'admin');
  const t1       = ins.run('ms_johnson',   'j.johnson@demo.school.uk',     teacherHash, 'teacher');
  const t2       = ins.run('mr_patel',     'r.patel@demo.school.uk',       teacherHash, 'teacher');
  const su1      = ins.run('emma.wilson',  'emma.wilson@demo.school.uk',   studentHash, 'student');
  const su2      = ins.run('james.chen',   'james.chen@demo.school.uk',    studentHash, 'student');
  const su3      = ins.run('sofia.rahman', 'sofia.rahman@demo.school.uk',  studentHash, 'student');
  const p1       = ins.run('p.wilson',     'p.wilson@demo.school.uk',      parentHash,  'parent');
  const p2       = ins.run('l.chen',       'l.chen@demo.school.uk',        parentHash,  'parent');

  const tfg = db.prepare(
    'INSERT INTO teacher_formgroup (teacher_user_id, form_group) VALUES (?, ?)'
  );
  tfg.run(t1.lastInsertRowid, '9A');
  tfg.run(t1.lastInsertRowid, '10A');
  tfg.run(t2.lastInsertRowid, '9B');
  tfg.run(t2.lastInsertRowid, '11B');

  const insSt = db.prepare(
    `INSERT INTO students
       (user_id, upn, first_name, last_name, dob, year_group, form_group, gender, sen_status, fsm_eligibility)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  const s1 = insSt.run(su1.lastInsertRowid, 'A123456789012', 'Emma',   'Wilson',   '2010-03-15', 9,  '9A',  'F', 'None',        0);
  const s2 = insSt.run(su2.lastInsertRowid, 'B234567890123', 'James',  'Chen',     '2009-07-22', 10, '10A', 'M', 'SEN Support', 0);
  const s3 = insSt.run(su3.lastInsertRowid, 'C345678901234', 'Sofia',  'Rahman',   '2008-11-30', 11, '11B', 'F', 'EHCP',        1);
  const s4 = insSt.run(null,                'D456789012345', 'Oliver', 'Martinez', '2010-05-10', 9,  '9A',  'M', 'None',        0);
  const s5 = insSt.run(null,                'E567890123456', 'Amelia', 'Thompson', '2010-08-20', 9,  '9B',  'F', 'None',        1);
  const s6 = insSt.run(null,                'F678901234567', 'Noah',   'Okafor',   '2009-02-14', 10, '10A', 'M', 'SEN Support', 0);
  const s7 = insSt.run(null,                'G789012345678', 'Isla',   'Bennett',  '2008-09-05', 11, '11B', 'F', 'None',        0);
  const s8 = insSt.run(null,                'H890123456789', 'Ethan',  'Kowalski', '2007-12-28', 12, '12C', 'M', 'None',        0);

  const insPS = db.prepare(
    'INSERT INTO parent_student (parent_user_id, student_id) VALUES (?, ?)'
  );
  insPS.run(p1.lastInsertRowid, s1.lastInsertRowid);
  insPS.run(p2.lastInsertRowid, s2.lastInsertRowid);

  const insEC = db.prepare(
    'INSERT INTO emergency_contacts (student_id, name, relationship, phone, email, priority) VALUES (?, ?, ?, ?, ?, ?)'
  );
  insEC.run(s1.lastInsertRowid, 'Patricia Wilson', 'Mother', '07700900001', 'p.wilson@demo.school.uk',  1);
  insEC.run(s1.lastInsertRowid, 'Robert Wilson',   'Father', '07700900002', 'r.wilson@demo.school.uk',  2);
  insEC.run(s2.lastInsertRowid, 'Li Chen',         'Mother', '07700900003', 'l.chen@demo.school.uk',    1);
  insEC.run(s3.lastInsertRowid, 'Fatima Rahman',   'Mother', '07700900004', 'f.rahman@demo.school.uk',  1);
  insEC.run(s4.lastInsertRowid, 'Carlos Martinez', 'Father', '07700900005', 'c.martinez@demo.school.uk',1);

  const insMed = db.prepare(
    `INSERT INTO medical_info (student_id, conditions, medications, allergies, doctor_name, doctor_phone)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
  insMed.run(s2.lastInsertRowid, 'Mild ADHD',             'Methylphenidate 10mg', 'Penicillin',  'Dr. Sarah Adams',   '020 7946 0001');
  insMed.run(s3.lastInsertRowid, 'Asthma, Autism Spectrum','Salbutamol inhaler',  'None known',  'Dr. Michael Brown', '020 7946 0002');
  insMed.run(s5.lastInsertRowid, 'Type 1 Diabetes',        'Insulin',             'Latex',       'Dr. Jennifer Lee',  '020 7946 0003');
}

module.exports = { seed };
