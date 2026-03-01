const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { db } = require('../config/database');
const { updateSecuritySetting } = require('../config/security');
const { hashPassword } = require('../utils/passwordHash');
const { encrypt, decrypt, saveCustomKey, deleteCustomKey, getKeyInfo } = require('../utils/encryption');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const {
  createBackup,
  listBackups,
  restoreBackup,
  startBackupSchedule,
  stopBackupSchedule,
  cleanupOldBackups
} = require('../utils/backupManager');

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
    if (feature === 'mfa_enabled' && !newValue) {
      // When disabling MFA globally, clear all users' MFA secrets so they
      // start fresh if MFA is re-enabled (prevents stale secret lockout)
      const allUsers = db.prepare('SELECT * FROM users').all();
      for (const user of allUsers) {
        if (user.mfa_enabled || user.mfa_secret) {
          db.prepare(`
            UPDATE users
            SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL
            WHERE id = ?
          `).run(user.id);
        }
      }
      console.log('Cleared MFA secrets for all users');
    } else if (feature === 'encryption_at_rest') {
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
        message: req.t('security.warnings.httpsRestart'),
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
      return res.status(500).render('error', { message: req.t('mfa.errorGeneratingQR'), error: err });
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
    return res.status(400).json({ success: false, error: req.t('mfa.noSetupInProgress') });
  }

  // Verify the code
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: code,
    window: 2
  });

  if (!verified) {
    return res.json({ success: false, error: req.t('mfa.invalidCode') });
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
 * Helper: Migrate passwords to hashed (with rollback on failure)
 */
async function migratePasswordsToHashed() {
  const users = db.prepare('SELECT id, password FROM users WHERE password_is_hashed = 0').all();
  if (users.length === 0) return;

  // Phase 1: Compute all hashes before writing anything
  const updates = [];
  for (const user of users) {
    const hash = await hashPassword(user.password);
    updates.push({ id: user.id, hash });
  }

  // Phase 2: Apply all updates (all hashes succeeded)
  const applied = [];
  try {
    for (const update of updates) {
      db.prepare(`
        UPDATE users
        SET password_hash = ?, password_is_hashed = 1
        WHERE id = ?
      `).run(update.hash, update.id);
      applied.push(update.id);
    }
  } catch (error) {
    // Rollback: revert any partially applied updates
    for (const id of applied) {
      db.prepare(`
        UPDATE users
        SET password_is_hashed = 0, password_hash = NULL
        WHERE id = ?
      `).run(id);
    }
    throw new Error(`Password migration failed after ${applied.length}/${updates.length} users. Rolled back. ${error.message}`);
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
 * Helper: Encrypt sensitive fields (with rollback on failure)
 */
async function encryptSensitiveFields() {
  // Phase 1: Collect all records and compute encrypted values
  const users = db.prepare('SELECT id, ssn FROM users WHERE ssn IS NOT NULL AND ssn_encrypted = 0').all();
  const enrollments = db.prepare('SELECT id, grade FROM enrollments WHERE grade IS NOT NULL AND grade_encrypted = 0').all();

  const userUpdates = users.map(u => ({ id: u.id, original: u.ssn, encrypted: encrypt(u.ssn) }));
  const enrollmentUpdates = enrollments.map(e => ({ id: e.id, original: e.grade, encrypted: encrypt(e.grade) }));

  // Phase 2: Apply all updates
  const appliedUsers = [];
  const appliedEnrollments = [];
  try {
    for (const u of userUpdates) {
      db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 1 WHERE id = ?').run(u.encrypted, u.id);
      appliedUsers.push(u);
    }
    for (const e of enrollmentUpdates) {
      db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 1 WHERE id = ?').run(e.encrypted, e.id);
      appliedEnrollments.push(e);
    }
  } catch (error) {
    // Rollback all applied changes
    for (const u of appliedUsers) {
      db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 0 WHERE id = ?').run(u.original, u.id);
    }
    for (const e of appliedEnrollments) {
      db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 0 WHERE id = ?').run(e.original, e.id);
    }
    throw new Error(`Encryption migration failed. Rolled back. ${error.message}`);
  }

  console.log(`Encrypted ${users.length} SSNs and ${enrollments.length} grades`);
}

/**
 * Helper: Decrypt sensitive fields (with rollback on failure)
 */
async function decryptSensitiveFields() {
  // Phase 1: Collect all records and compute decrypted values (throws on failure)
  const users = db.prepare('SELECT id, ssn FROM users WHERE ssn IS NOT NULL AND ssn_encrypted = 1').all();
  const enrollments = db.prepare('SELECT id, grade FROM enrollments WHERE grade IS NOT NULL AND grade_encrypted = 1').all();

  const userUpdates = users.map(u => ({ id: u.id, original: u.ssn, decrypted: decrypt(u.ssn) }));
  const enrollmentUpdates = enrollments.map(e => ({ id: e.id, original: e.grade, decrypted: decrypt(e.grade) }));

  // Phase 2: Apply all updates
  const appliedUsers = [];
  const appliedEnrollments = [];
  try {
    for (const u of userUpdates) {
      db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 0 WHERE id = ?').run(u.decrypted, u.id);
      appliedUsers.push(u);
    }
    for (const e of enrollmentUpdates) {
      db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 0 WHERE id = ?').run(e.decrypted, e.id);
      appliedEnrollments.push(e);
    }
  } catch (error) {
    // Rollback all applied changes
    for (const u of appliedUsers) {
      db.prepare('UPDATE users SET ssn = ?, ssn_encrypted = 1 WHERE id = ?').run(u.original, u.id);
    }
    for (const e of appliedEnrollments) {
      db.prepare('UPDATE enrollments SET grade = ?, grade_encrypted = 1 WHERE id = ?').run(e.original, e.id);
    }
    throw new Error(`Decryption migration failed. Rolled back. ${error.message}`);
  }

  console.log(`Decrypted ${users.length} SSNs and ${enrollments.length} grades`);
}

/**
 * GET /admin/backups
 * Backup management page
 */
router.get('/backups', requireAuth, requireRole(['admin']), (req, res) => {
  const backups = listBackups();
  const settings = db.prepare('SELECT * FROM security_settings WHERE id = 1').get();

  res.render('admin/backups', {
    backups,
    backupSettings: {
      enabled: settings.backup_enabled || 0,
      frequency: settings.backup_frequency || 60,
      lastBackup: settings.last_backup_time
    },
    rbacBypass: req.rbacBypass
  });
});

/**
 * POST /admin/backups/create
 * Create manual backup
 */
router.post('/backups/create', requireAuth, requireRole(['admin']), (req, res) => {
  const result = createBackup();

  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'MANUAL_BACKUP',
      JSON.stringify(result),
      result.success ? 1 : 0
    );
  }

  res.json(result);
});

/**
 * POST /admin/backups/toggle
 * Enable/disable automatic backups
 */
router.post('/backups/toggle', requireAuth, requireRole(['admin']), (req, res) => {
  const currentValue = req.securitySettings.backup_enabled;
  const newValue = !currentValue;

  updateSecuritySetting('backup_enabled', newValue);

  if (newValue) {
    const frequency = req.securitySettings.backup_frequency || 60;
    startBackupSchedule(frequency);
  } else {
    stopBackupSchedule();
  }

  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'TOGGLE_BACKUPS',
      JSON.stringify({ newValue })
    );
  }

  res.json({ success: true, enabled: newValue });
});

/**
 * POST /admin/backups/set-frequency
 * Change backup frequency
 */
router.post('/backups/set-frequency', requireAuth, requireRole(['admin']), (req, res) => {
  const { frequency } = req.body;

  if (!frequency || ![5, 15, 30, 60, 360, 720, 1440].includes(parseInt(frequency))) {
    return res.status(400).json({ success: false, error: req.t('backups.invalidFrequency') });
  }

  db.prepare(`
    UPDATE security_settings
    SET backup_frequency = ?
    WHERE id = 1
  `).run(parseInt(frequency));

  // Restart schedule if backups are enabled
  if (req.securitySettings.backup_enabled) {
    startBackupSchedule(parseInt(frequency));
  }

  res.json({ success: true, frequency: parseInt(frequency) });
});

/**
 * POST /admin/backups/restore/:filename
 * Restore from backup
 */
router.post('/backups/restore/:filename', requireAuth, requireRole(['admin']), (req, res) => {
  const { filename } = req.params;
  const result = restoreBackup(filename);

  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'RESTORE_BACKUP',
      JSON.stringify({ filename, safetyBackup: result.safetyBackup }),
      result.success ? 1 : 0
    );
  }

  res.json(result);
});

/**
 * GET /admin/backups/download/:filename
 * Download backup file
 */
router.get('/backups/download/:filename', requireAuth, requireRole(['admin']), (req, res) => {
  const { filename } = req.params;
  const backups = listBackups();
  const backup = backups.find(b => b.filename === filename);

  if (!backup) {
    return res.status(404).json({ error: req.t('backups.backupNotFound') });
  }

  res.download(backup.filepath, filename);
});

/**
 * POST /admin/backups/cleanup
 * Clean up old backups
 */
router.post('/backups/cleanup', requireAuth, requireRole(['admin']), (req, res) => {
  const deletedCount = cleanupOldBackups(50);
  res.json({ success: true, deletedCount });
});

/**
 * GET /admin/byok
 * Bring Your Own Key management page
 */
router.get('/byok', requireAuth, requireRole(['admin']), (req, res) => {
  const keyInfo = getKeyInfo();
  const fieldEncryptionEnabled = req.securitySettings.field_encryption;

  res.render('admin/byok', {
    keyInfo,
    fieldEncryptionEnabled,
    rbacBypass: req.rbacBypass
  });
});

/**
 * POST /admin/byok/upload
 * Upload a custom encryption key
 */
router.post('/byok/upload', requireAuth, requireRole(['admin']), (req, res) => {
  const { keyData } = req.body;

  // Check if field encryption is enabled
  if (req.securitySettings.field_encryption) {
    return res.status(400).json({
      success: false,
      error: 'Cannot change encryption key while field encryption is enabled. Disable field encryption first to prevent data loss.'
    });
  }

  if (!keyData) {
    return res.status(400).json({
      success: false,
      error: 'Key data is required'
    });
  }

  const result = saveCustomKey(keyData);

  // Audit log
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'BYOK_UPLOAD',
      JSON.stringify({ keyLength: keyData.length }),
      result.success ? 1 : 0
    );
  }

  res.json(result);
});

/**
 * POST /admin/byok/delete
 * Delete custom key and revert to default
 */
router.post('/byok/delete', requireAuth, requireRole(['admin']), (req, res) => {
  // Check if field encryption is enabled
  if (req.securitySettings.field_encryption) {
    return res.status(400).json({
      success: false,
      error: 'Cannot delete encryption key while field encryption is enabled. Disable field encryption first to prevent data loss.'
    });
  }

  const result = deleteCustomKey();

  // Audit log
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'BYOK_DELETE',
      JSON.stringify({ revertedToDefault: true }),
      result.success ? 1 : 0
    );
  }

  res.json(result);
});

/**
 * GET /admin/deletion-requests
 * View pending and completed class deletion requests
 */
router.get('/deletion-requests', requireAuth, requireRole(['admin']), (req, res) => {
  // Get all deletion requests with class and user information
  const allRequests = db.prepare(`
    SELECT dr.*, c.code, c.name, u.username
    FROM deletion_requests dr
    LEFT JOIN classes c ON dr.class_id = c.id
    LEFT JOIN users u ON dr.requested_by = u.id
  `).all();

  // Separate pending and completed requests
  const pendingRequests = allRequests.filter(r => r.status === 'pending');
  const completedRequests = allRequests.filter(r => r.status !== 'pending')
    .sort((a, b) => new Date(b.reviewed_at) - new Date(a.reviewed_at))
    .slice(0, 20); // Show last 20 completed

  res.render('admin/deletion-requests', {
    pendingRequests,
    completedRequests,
    rbacBypass: req.rbacBypass
  });
});

/**
 * POST /admin/deletion-requests/:id/approve
 * Approve a class deletion request
 */
router.post('/deletion-requests/:id/approve', requireAuth, requireRole(['admin']), (req, res) => {
  const requestId = req.params.id;
  const adminId = req.session.user.id;

  // Get the deletion request
  const request = db.prepare('SELECT * FROM deletion_requests WHERE id = ?').get(requestId);
  if (!request) {
    return res.status(404).json({ success: false, error: req.t('errors.deletionRequestNotFound') });
  }

  if (request.status !== 'pending') {
    return res.status(400).json({ success: false, error: req.t('errors.requestAlreadyReviewed') });
  }

  // Get class information for audit log
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(request.class_id);
  if (!classData) {
    return res.status(404).json({ success: false, error: req.t('classes.notFound') });
  }

  // Update request status
  db.prepare(`
    UPDATE deletion_requests
    SET status = 'approved', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(adminId, requestId);

  // Delete the class (cascades to sessions and enrollments)
  db.prepare('DELETE FROM classes WHERE id = ?').run(request.class_id);

  // Audit log
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      adminId,
      req.session.user.username,
      req.session.user.role,
      'APPROVE_CLASS_DELETION',
      JSON.stringify({
        requestId,
        classId: request.class_id,
        classCode: classData.code,
        requestedBy: request.requested_by
      }),
      1
    );
  }

  res.json({
    success: true,
    message: req.t('sod.approvalSuccess')
  });
});

/**
 * POST /admin/deletion-requests/:id/reject
 * Reject a class deletion request
 */
router.post('/deletion-requests/:id/reject', requireAuth, requireRole(['admin']), (req, res) => {
  const requestId = req.params.id;
  const adminId = req.session.user.id;
  const { reason } = req.body;

  if (!reason || reason.trim().length === 0) {
    return res.status(400).json({ success: false, error: req.t('errors.rejectionReasonRequired') });
  }

  // Get the deletion request
  const request = db.prepare('SELECT * FROM deletion_requests WHERE id = ?').get(requestId);
  if (!request) {
    return res.status(404).json({ success: false, error: req.t('errors.deletionRequestNotFound') });
  }

  if (request.status !== 'pending') {
    return res.status(400).json({ success: false, error: req.t('errors.requestAlreadyReviewed') });
  }

  // Get class information for audit log
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(request.class_id);

  // Update request status
  db.prepare(`
    UPDATE deletion_requests
    SET status = 'rejected', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP, rejection_reason = ?
    WHERE id = ?
  `).run(adminId, reason.trim(), requestId);

  // Audit log
  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details, success)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      adminId,
      req.session.user.username,
      req.session.user.role,
      'REJECT_CLASS_DELETION',
      JSON.stringify({
        requestId,
        classId: request.class_id,
        classCode: classData?.code,
        requestedBy: request.requested_by,
        reason: reason.trim()
      }),
      1
    );
  }

  res.json({
    success: true,
    message: req.t('sod.rejectionSuccess')
  });
});

/**
 * POST /admin/rate-limit/reset
 * Clear all rate limit attempts (escape hatch if admin gets locked out)
 */
router.post('/rate-limit/reset', requireAuth, requireRole(['admin']), (req, res) => {
  db.prepare('DELETE FROM rate_limit_attempts').run();

  if (req.securitySettings.audit_logging) {
    db.prepare(`
      INSERT INTO audit_logs (user_id, username, role, action, details)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      req.session.user.id,
      req.session.user.username,
      req.session.user.role,
      'RATE_LIMIT_RESET',
      JSON.stringify({ message: 'All rate limit attempts cleared' })
    );
  }

  res.json({ success: true, message: req.t('errors.rateLimitCleared') });
});

module.exports = router;
