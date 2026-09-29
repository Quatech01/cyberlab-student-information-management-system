'use strict';
const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('node:path');

const { initDb }          = require('./db/database');
const { seed }            = require('./db/seed');
const { csrfMiddleware }  = require('./middleware/csrf');
const authRoutes          = require('./routes/auth');
const studentRoutes       = require('./routes/students');
const adminRoutes         = require('./routes/admin');

const app = express();

initDb();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
}));

app.use(express.json({ limit: '10kb' }));

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
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);
app.use('/api',      csrfMiddleware);

app.use('/api/auth',     authRoutes);
app.use('/api/students', studentRoutes);
app.use('/api/admin',    adminRoutes);

app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

async function start(port = 3000) {
  await seed();
  return new Promise((resolve) => {
    const srv = app.listen(port, '127.0.0.1', () => resolve(srv));
  });
}

module.exports = { app, start };

if (require.main === module) {
  start(3000).then(() => console.log('Server running on http://127.0.0.1:3000'));
}
