const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { db } = require('../config/database');
const { updateSecuritySetting } = require('../config/security');
const { hashPassword } = require('../utils/passwordHash');
const { encrypt, decrypt } = require('../utils/encryption');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

/**
 * GET /admin/security
 * Security settings panel
 */
router.get('/security', requireAuth, requireRole(['admin']), (req, res) => {
  res.render('admin/security-panel', {
    rbacBypass: req.rbacBypass
  });
});

/**
 * POST /admin/security/toggle/:feature
 * Toggle a security feature
 */
router.post('/security/toggle/:feature', requireAuth, requireRole(['admin']), async (req, res) => {
  const feature = req.params.feature;
  const currentValue = req.securitySettings[feature];
  const newValue = !currentValue;

  try {
    // Handle specific feature migrations
    if (feature === 'encryption_at_rest') {
      if (newValue) {
        // Enable: Hash all passwords
        await migratePasswordsToHashed();
      } else {
        // Disable: Revert to plaintext (for demonstration only!)
        await migratePasswordsToPlaintext();
      }
    } else if (feature === 'field_encryption') {
      if (newValue) {
        // Enable: Encrypt SSN and grades
        await encryptSensitiveFields();
      } else {
        // Disable: Decrypt SSN and grades
        await decryptSensitiveFields();
      }
    }

    // Update the setting
    updateSecuritySetting(feature, newValue);

    // Log the change
    if (req.securitySettings.audit_logging) {
      db.prepare(`
        INSERT INTO audit_logs (user_id, username, role, action, details)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        req.session.user.id,
        req.session.user.username,
        req.session.user.role,
        'TOGGLE_SECURITY',
        JSON.stringify({ feature, oldValue: currentValue, newValue })
      );
    }

    // If toggling HTTPS, restart required
    if (feature === 'https_enabled') {
      res.json({
        success: true,
        newValue,
        message: 'HTTPS setting changed. Please restart the server for changes to take effect.',
        requiresRestart: true
      });
    } else {
      res.json({ success: true, newValue });
    }
  } catch (error) {
    console.error('Toggle error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /admin/audit-logs
 * View audit logs
 */
router.get('/audit-logs', requireAuth, requireRole(['admin']), auditLog('VIEW_AUDIT_LOGS'), (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 50;
  const offset = (page - 1) * limit;

  // Get total count
  const totalCount = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get().count;
  const totalPages = Math.ceil(totalCount / limit);

  // Get logs
  const logs = db.prepare(`
    SELECT * FROM audit_logs
    ORDER BY timestamp DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);

  res.render('admin/audit-logs', {
    logs,
    currentPage: page,
    totalPages,
    rbacBypass: req.rbacBypass
  });
});

/**
 * GET /admin/mfa-setup
 * MFA setup for admin
 */
router.get('/mfa-setup', requireAuth, requireRole(['admin']), (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);

  if (user.mfa_enabled) {
    return res.render('admin/mfa-setup', {
      alreadyEnabled: true,
      rbacBypass: req.rbacBypass
    });
  }

  // Generate new secret
  const secret = speakeasy.generateSecret({
    name: `University (${user.username})`,
    length: 32
  });

  // Store secret temporarily in session
  req.session.tempMfaSecret = secret.base32;

  // Generate QR code
  qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
    if (err) {
      console.error('QR code error:', err);
      return res.status(500).render('error', { message: 'Error generating QR code', error: err });
    }

    res.render('admin/mfa-setup', {
      alreadyEnabled: false,
      qrCodeUrl: dataUrl,
      secret: secret.base32,
      rbacBypass: req.rbacBypass
    });
  });
});

/**
 * POST /admin/mfa-setup
 * Complete MFA setup
 */
router.post('/mfa-setup', requireAuth, requireRole(['admin']), async (req, res) => {
  const { code } = req.body;
  const secret = req.session.tempMfaSecret;

  if (!secret) {
    return res.status(400).json({ success: false, error: 'No MFA setup in progress' });
  }

  // Verify the code
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: code,
    window: 2
  });

  if (!verified) {
    return res.json({ success: false, error: 'Invalid code. Please try again.' });
  }

  // Save MFA secret to user
  db.prepare(`
    UPDATE users
    SET mfa_enabled = 1, mfa_secret = ?
    WHERE id = ?
  `).run(secret, req.session.user.id);

  // Clear temporary secret
  delete req.session.tempMfaSecret;

  // Log the event
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action)
      VALUES (?, ?, ?, ?)
    `).run(req.session.user.id, req.session.user.username, req.session.user.role, 'MFA_ENABLED');
  }

  res.json({ success: true });
});

/**
 * POST /admin/mfa-disable
 * Disable MFA
 */
router.post('/mfa-disable', requireAuth, requireRole(['admin']), (req, res) => {
  db.prepare(`
    UPDATE users
    SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL
    WHERE id = ?
  `).run(req.session.user.id);

  // Log the event
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action)
      VALUES (?, ?, ?, ?)
    `).run(req.session.user.id, req.session.user.username, req.session.user.role, 'MFA_DISABLED');
  }

  res.json({ success: true });
});

/**
 * Helper: Migrate passwords to hashed
 */
async function migratePasswordsToHashed() {
  const users = db.prepare('SELECT id, password FROM users WHERE password_is_hashed = 0').all();

  for (const user of users) {
    const hash = await hashPassword(user.password);
    db.prepare(`
      UPDATE users
      SET password_hash = ?, password_is_hashed = 1
      WHERE id = ?
    `).run(hash, user.id);
  }

  console.log(`Migrated ${users.length} passwords to bcrypt hashes`);
}

/**
 * Helper: Migrate passwords to plaintext
 */
async function migratePasswordsToPlaintext() {
  db.prepare(`
    UPDATE users
    SET password_is_hashed = 0, password_hash = NULL
  `).run();

  console.log('Reverted passwords to plaintext');
}

/**
 * Helper: Encrypt sensitive fields
 */
async function encryptSensitiveFields() {
  // Encrypt SSNs
  const users = db.prepare('SELECT id, ssn FROM users WHERE ssn IS NOT NULL AND ssn_encrypted = 0').all();
  for (const user of users) {
    const encrypted = encrypt(user.ssn);
    db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 1 WHERE id = ?').run(encrypted, user.id);
  }

  // Encrypt grades
  const enrollments = db.prepare('SELECT id, grade FROM enrollments WHERE grade IS NOT NULL AND grade_encrypted = 0').all();
  for (const enrollment of enrollments) {
    const encrypted = encrypt(enrollment.grade);
    db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 1 WHERE id = ?').run(encrypted, enrollment.id);
  }

  console.log(`Encrypted ${users.length} SSNs and ${enrollments.length} grades`);
}

/**
 * Helper: Decrypt sensitive fields
 */
async function decryptSensitiveFields() {
  // Decrypt SSNs
  const users = db.prepare('SELECT id, ssn FROM users WHERE ssn IS NOT NULL AND ssn_encrypted = 1').all();
  for (const user of users) {
    const decrypted = decrypt(user.ssn);
    db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 0 WHERE id = ?').run(decrypted, user.id);
  }

  // Decrypt grades
  const enrollments = db.prepare('SELECT id, grade FROM enrollments WHERE grade IS NOT NULL AND grade_encrypted = 1').all();
  for (const enrollment of enrollments) {
    const decrypted = decrypt(enrollment.grade);
    db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 0 WHERE id = ?').run(decrypted, enrollment.id);
  }

  console.log(`Decrypted ${users.length} SSNs and ${enrollments.length} grades`);
}

module.exports = router;
