const express = require('express');
const router = express.Router();
const { db } = require('../config/database');
const { hashPassword, comparePassword } = require('../utils/passwordHash');
const { checkRateLimit, recordLoginAttempt } = require('../middleware/rateLimiter');
const { logAuthAttempt } = require('../middleware/audit');

/**
 * POST /auth/login
 * Handle user login
 */
router.post('/login', checkRateLimit, async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  try {
    // Find user
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      // Record failed attempt
      if (req.securitySettings.rate_limiting) {
        recordLoginAttempt(ip, username, false);
      }
      if (req.securitySettings.audit_logging) {
        await logAuthAttempt(username, false, ip, 'User not found');
      }
      return res.render('login', { error: 'Invalid username or password' });
    }

    // Check password
    let passwordValid = false;
    if (user.password_is_hashed) {
      // Use bcrypt to compare
      passwordValid = await comparePassword(password, user.password_hash);
    } else {
      // Direct comparison (insecure, but demonstrative)
      passwordValid = (password === user.password);
    }

    if (!passwordValid) {
      // Record failed attempt
      if (req.securitySettings.rate_limiting) {
        recordLoginAttempt(ip, username, false);
      }
      if (req.securitySettings.audit_logging) {
        await logAuthAttempt(username, false, ip, 'Invalid password');
      }
      return res.render('login', { error: 'Invalid username or password' });
    }

    // Record successful attempt
    if (req.securitySettings.rate_limiting) {
      recordLoginAttempt(ip, username, true);
    }

    // Check if MFA is required
    if (user.role === 'admin' && req.securitySettings.mfa_enabled && user.mfa_enabled) {
      // Store pending user in session
      req.session.pendingMfaUserId = user.id;
      return res.redirect('/auth/mfa-verify');
    }

    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    // Create session
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    // Log successful login
    if (req.securitySettings.audit_logging) {
      await logAuthAttempt(username, true, ip);
    }

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'An error occurred during login' });
  }
});

/**
 * GET /auth/mfa-verify
 * Show MFA verification page
 */
router.get('/mfa-verify', (req, res) => {
  if (!req.session.pendingMfaUserId) {
    return res.redirect('/');
  }
  res.render('mfa-verify', { error: null });
});

/**
 * POST /auth/mfa-verify
 * Verify MFA code
 */
router.post('/mfa-verify', async (req, res) => {
  const { code } = req.body;

  if (!req.session.pendingMfaUserId) {
    return res.redirect('/');
  }

  try {
    const speakeasy = require('speakeasy');
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.pendingMfaUserId);

    if (!user || !user.mfa_secret) {
      return res.render('mfa-verify', { error: 'MFA not configured' });
    }

    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 time steps before/after for clock skew
    });

    if (!verified) {
      // Log failed MFA attempt
      if (req.securitySettings.audit_logging) {
        await logAuthAttempt(user.username, false, req.ip, 'Invalid MFA code');
      }
      return res.render('mfa-verify', { error: 'Invalid verification code' });
    }

    // MFA successful - create session
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    // Clear pending MFA user
    delete req.session.pendingMfaUserId;

    // Update last login
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    // Log successful login with MFA
    if (req.securitySettings.audit_logging) {
      await logAuthAttempt(user.username, true, req.ip, 'MFA verified');
    }

    res.redirect('/dashboard');
  } catch (error) {
    console.error('MFA verification error:', error);
    res.render('mfa-verify', { error: 'An error occurred during verification' });
  }
});

/**
 * GET /auth/logout
 * Logout user
 */
router.get('/logout', (req, res) => {
  if (req.session.user && req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, ip_address)
      VALUES (?, ?, ?, ?, ?)
    `).run(req.session.user.id, req.session.user.username, req.session.user.role, 'LOGOUT', req.ip);
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

/**
 * POST /auth/set-language
 * Set user's language preference
 */
router.post('/set-language', (req, res) => {
  const { lang } = req.body;

  if (!lang || !['en', 'fr'].includes(lang)) {
    return res.status(400).json({ success: false, error: 'Invalid language' });
  }

  req.session.language = lang;
  res.json({ success: true, language: lang });
});

module.exports = router;
