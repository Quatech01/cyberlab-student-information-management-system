'use strict';
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

let _db = null;

function getDb() {
  if (!_db) {
    const dbPath = process.env.DB_PATH || path.join(__dirname, 'cyberlab.db');
    _db = new DatabaseSync(dbPath);
    _db.exec('PRAGMA foreign_keys = ON');
    if (dbPath !== ':memory:') {
      _db.exec('PRAGMA journal_mode = WAL');
    }
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf-8');
    _db.exec(schema);
  }
  return _db;
}

function closeDb() {
  if (_db) {
    try { _db.close(); } catch {}
    _db = null;
  }
}

module.exports = { getDb, closeDb };
