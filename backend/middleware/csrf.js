'use strict';

function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!req.user) return next();

  const token = req.headers['x-csrf-token'];
  if (!token || token !== req.user.jti) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}

module.exports = { csrfProtect };
