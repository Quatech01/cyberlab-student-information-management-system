'use strict';
const { randomUUID } = require('node:crypto');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const SKIP_PATHS   = new Set(['/auth/login', '/auth/register', '/auth/refresh']);

function csrfMiddleware(req, res, next) {
  if (SAFE_METHODS.has(req.method)) return next();

  const relPath = req.path.replace(/^\/api/, '');
  if (SKIP_PATHS.has(relPath)) return next();

  const cookieHeader = req.headers.cookie || '';
  const cookieToken = cookieHeader
    .split(';')
    .map(c => c.trim().split('='))
    .find(([k]) => k === 'csrf_token')?.[1];

  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

function generateCsrfToken() {
  return randomUUID();
}

module.exports = { csrfMiddleware, generateCsrfToken };
