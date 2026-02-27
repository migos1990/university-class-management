const { db } = require('./database');

// Whitelist of valid security setting column names
const VALID_SETTINGS = [
  'mfa_enabled', 'rbac_enabled', 'encryption_at_rest', 'field_encryption',
  'https_enabled', 'audit_logging', 'rate_limiting', 'backup_enabled',
  'backup_frequency', 'last_backup_time', 'segregation_of_duties'
];

/**
 * Get current security settings from database
 */
function getSecuritySettings() {
  const settings = db.prepare('SELECT * FROM security_settings WHERE id = 1').get();
  return settings || {
    mfa_enabled: 0,
    rbac_enabled: 1,
    encryption_at_rest: 0,
    field_encryption: 0,
    https_enabled: 0,
    audit_logging: 0,
    rate_limiting: 0,
    backup_enabled: 0,
    backup_frequency: 60,
    last_backup_time: null,
    segregation_of_duties: 0
  };
}

/**
 * Update security setting (validates setting name against whitelist)
 */
function updateSecuritySetting(setting, value) {
  if (!VALID_SETTINGS.includes(setting)) {
    throw new Error(`Invalid security setting: ${setting}`);
  }
  const stmt = db.prepare(`UPDATE security_settings SET ${setting} = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`);
  stmt.run(value ? 1 : 0);
}

/**
 * Middleware to load security settings into every request
 */
function loadSecuritySettings(req, res, next) {
  const settings = getSecuritySettings();
  req.securitySettings = settings;
  res.locals.securitySettings = settings;
  next();
}

module.exports = {
  getSecuritySettings,
  updateSecuritySetting,
  loadSecuritySettings
};
