'use strict';
const { DatabaseSync } = require('node:sqlite');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

let db = null;

function getDb() {
  if (!db) throw new Error('Database not initialised. Call initDb() first.');
  return db;
}

function initDb(dbPath) {
  const resolvedPath = dbPath || process.env.DB_PATH || join(__dirname, 'cyberlab.db');
  db = new DatabaseSync(resolvedPath);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA journal_mode = WAL');
  const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf-8');
  db.exec(schema);
  return db;
}

module.exports = { getDb, initDb };
