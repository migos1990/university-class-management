# Coding Conventions

**Analysis Date:** 2026-03-12

## Naming Patterns

**Files:**
- kebab-case for multi-word JavaScript files: `smoke-test.js`, `classroom-manager.js`, `classroom-stop.js`
- camelCase also observed: `passwordHash.js`, `backupManager.js`, `seedData.js`, `rateLimiter.js`
- Single-word lowercase for most files: `auth.js`, `audit.js`, `encryption.js`
- Route files match their URL path segment: `auth.js` for `/auth`, `dashboard.js` for `/dashboard`, `classes.js` for `/classes`

**Functions:**
- camelCase for all function names: `hashPassword()`, `comparePassword()`, `requireAuth()`, `requireRole()`
- Verb-first naming for action functions: `saveCustomKey()`, `deleteCustomKey()`, `recordLoginAttempt()`, `loadDatabase()`
- Predicate functions start with `is`: `isBcryptHash()`, `isEncrypted()`, `isDatabaseSeeded()`, `isValidDatabase()`
- Middleware functions named by purpose: `languageMiddleware()`, `auditLog()`, `checkRateLimit()`, `loadSecuritySettings()`

**Variables:**
- camelCase for all variable names: `currentEncryptionKey`, `securitySettings`, `passwordValid`, `enrollments`
- UPPER_CASE for constants: `MAX_ATTEMPTS`, `WINDOW_MS`, `SALT_ROUNDS`, `DEFAULT_ENCRYPTION_KEY`, `ALGORITHM`, `REQUIRED_KEYS`
- Descriptive names preferred: `pendingMfaUserId` (not `pId`), `oldestAttempt` (not `oa`), `remainingMinutes`
- Plural forms for collections: `enrollments`, `students`, `professors`, `allUsers`, `backupFiles`

**Database Fields:**
- snake_case for all database/JSON fields: `password_is_hashed`, `mfa_secret`, `last_login`, `attempt_time`, `mfa_backup_codes`
- Boolean fields use 0/1 integers: `mfa_enabled: 0`, `password_is_hashed: 1`, `ssn_encrypted: 0`

## Code Style

**Formatting:**
- No explicit linter or prettier config detected (no `.eslintrc`, `.prettierrc`, `biome.json`)
- 2-space indentation throughout codebase
- Semicolons present on most statements
- Single quotes for string literals: `'express'`, `'login'`, `'utf8'`
- Line length varies, no hard limit enforced

**Language:**
- CommonJS modules (`require()` / `module.exports`), not ES modules
- Plain JavaScript, not TypeScript
- No JSX or frontend framework

## Import Organization

**Order:**
1. Built-in Node modules first: `require('express')`, `require('fs')`, `require('path')`, `require('crypto')`
2. Third-party packages: `require('bcrypt')`, `require('speakeasy')`, `require('express-session')`
3. Local modules: `require('../config/database')`, `require('../utils/passwordHash')`

**Path Aliases:**
- No path aliases configured
- All imports use relative paths: `'../config/database'`, `'./middleware/auth'`, `'../utils/encryption'`

**Pattern Example (from `server.js`):**
```javascript
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');

// Local modules
const { db, initializeDatabase, isDatabaseSeeded } = require('./config/database');
const { seedDatabase } = require('./utils/seedData');
const { loadSecuritySettings, getSecuritySettings } = require('./config/security');
```

**Pattern Example (from `routes/auth.js`):**
```javascript
const express = require('express');
const router = express.Router();
const { db } = require('../config/database');
const { hashPassword, comparePassword } = require('../utils/passwordHash');
const { checkRateLimit, recordLoginAttempt } = require('../middleware/rateLimiter');
const { logAuthAttempt } = require('../middleware/audit');
```

## Error Handling

**Strategy:** Try-catch with console logging and graceful degradation. Non-critical subsystems (audit logging, rate limiting) never block the main request.

**Route Handler Pattern:**
```javascript
// From routes/auth.js - catch renders user-friendly error
router.post('/login', checkRateLimit, async (req, res) => {
  try {
    // ... business logic ...
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'An error occurred during login' });
  }
});
```

**Middleware Pattern - Graceful Fallback:**
```javascript
// From middleware/rateLimiter.js - never blocks on error
try {
  const result = db.prepare(/*...*/).get(ip, windowStart);
  if (result.count >= MAX_ATTEMPTS) {
    return res.status(429).render('error', { /* rate limit message */ });
  }
  next();
} catch (error) {
  console.error('Rate limit check error:', error);
  next(); // Don't block on error
}
```

**Audit/Logging Pattern - Silent Failures:**
```javascript
// From middleware/audit.js - audit failures never reject
function logAuthAttempt(username, success, ip, reason = null) {
  return new Promise((resolve, reject) => {
    try {
      db.prepare(/*...*/).run(/*...*/);
      resolve();
    } catch (error) {
      console.error('Auth audit log error:', error);
      resolve(); // Don't reject, just log error
    }
  });
}
```

**Global Error Handler (from `server.js`):**
```javascript
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500);
  res.render('error', {
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    message: 'Page not found',
    error: { status: 404 }
  });
});
```

## Logging

**Framework:** `console` methods only (no logging library such as winston, pino, etc.)

**Methods used:**
- `console.log()` for informational messages and startup
- `console.error()` for error conditions
- `console.warn()` for warnings (invalid data, missing translations)

**Conventions:**
- Prefix error context: `console.error('Login error:', error)`
- Use checkmark for success: `console.log('✓ Database recovered from backup')`
- Use step numbers for multi-step scripts: `console.log('[1/3] Initializing database schema...')`
- Log `error.message` for expected errors, full `error` object for unexpected ones

## Comments

**When to Comment:**
- JSDoc-style block above every exported function
- Inline comments for security-related decisions and "why" explanations
- Section dividers in large files using `// ---` or `// ─────`

**JSDoc Pattern:**
```javascript
/**
 * Middleware to require specific role(s)
 * @param {string|string[]} allowedRoles - Single role or array of allowed roles
 */
function requireRole(allowedRoles) { /* ... */ }

/**
 * Hash a plaintext password
 */
async function hashPassword(password) { /* ... */ }

/**
 * Safe decrypt wrapper that returns a result object instead of throwing.
 * Use this when you want to handle decryption failures gracefully (e.g., display).
 */
function safeDecrypt(text) { /* ... */ }
```

**Inline Comments:**
```javascript
// Guard against double-encryption
if (isEncrypted(text)) {
  return text;
}

// Allow 2 time steps before/after for clock skew
token: code,
window: 2
```

## Function Design

**Size:**
- Most functions 5-40 lines
- Exception: `executeSQL()` in `config/database.js` is 900+ lines (monolithic switch-case over SQL patterns)
- Preference for smaller, focused middleware and utility functions

**Parameters:**
- Destructuring used for request body: `const { username, password } = req.body`
- Optional parameters given default values: `function auditLog(action, resourceType = null)`
- Max 3-5 parameters typical; database functions accept variadic `...params`

**Return Values:**
- Promise-based for async: `async function hashPassword(password) { return await bcrypt.hash(password, SALT_ROUNDS); }`
- Result objects for operations that can fail: `{ success: true, value: '...' }` or `{ success: false, error: '...' }`
- Middleware uses `next()` pattern
- Route handlers use `res.render()` or `res.json()`

## Module Design

**Exports:**
- Named exports via `module.exports = { fn1, fn2 }` for utility and middleware modules
- Router export for route modules: `module.exports = router`
- Some route modules export both router and helpers: `module.exports = { router: scaRoutes }`

**Pattern - Utility Module (from `utils/passwordHash.js`):**
```javascript
module.exports = {
  hashPassword,
  comparePassword,
  isBcryptHash
};
```

**Pattern - Route Module (from `routes/auth.js`):**
```javascript
module.exports = router;
```

**Pattern - Route with Named Export (from `routes/sca.js`):**
```javascript
// Imported as: const { router: scaRoutes } = require('./routes/sca');
module.exports = { router };
```

**Barrel Files:** Not used; all imports reference specific files directly.

## Route Handler Patterns

**Router Setup:**
- Each route file creates its own `express.Router()` instance
- Middleware applied per-route: `router.get('/admin', requireAuth, (req, res) => { ... })`
- Authentication and RBAC middleware chained before handler

**Request/Response Pattern:**
```javascript
router.get('/student', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const enrollments = db.prepare(`SELECT ... WHERE e.student_id = ?`).all(userId);
  res.render('student/dashboard', { enrollments });
});
```

**JSON API Pattern:**
```javascript
router.post('/set-language', (req, res) => {
  const { lang } = req.body;
  if (!lang || !['en', 'fr'].includes(lang)) {
    return res.status(400).json({ success: false, error: 'Invalid language' });
  }
  req.session.language = lang;
  res.json({ success: true, language: lang });
});
```

## Database Access Pattern

**Query Interface:** Custom SQL-like abstraction in `config/database.js` wrapping JSON-based storage.

```javascript
// SELECT single row
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

// SELECT multiple rows
const classes = db.prepare('SELECT * FROM classes').all();

// INSERT
db.prepare('INSERT INTO audit_logs (...) VALUES (?, ?, ?, ?, ?)').run(id, name, role, action, ip);

// UPDATE
db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
```

- SQL strings are written inline in route handlers (no query builder or ORM)
- Parameters passed positionally via `?` placeholders
- All mutations auto-save to `database/data.json`

## Security Context Pattern

**`req.securitySettings`** is populated by `loadSecuritySettings` middleware in `config/security.js` and available in all routes.

```javascript
// Conditional behavior based on security settings
if (req.securitySettings.rate_limiting) {
  recordLoginAttempt(ip, username, false);
}

if (req.securitySettings.audit_logging) {
  await logAuthAttempt(username, false, ip, 'User not found');
}

if (req.securitySettings.mfa_enabled && user.mfa_enabled) {
  req.session.pendingMfaUserId = user.id;
  return res.redirect('/auth/mfa-verify');
}
```

## View Rendering Pattern

**Engine:** EJS templates in `views/` directory.

**Shared Locals (from `server.js` middleware):**
- `res.locals.user` - current session user or null
- `res.locals.currentPath` - current request path
- `res.locals.formatDate(dateStr)` - date formatting helper
- `res.locals.t(key, params)` - i18n translation function
- `res.locals.currentLang` - current language code

---

*Convention analysis: 2026-03-12*
