const { db } = require('../config/database');

/**
 * Create audit log middleware
 * @param {string} action - The action being performed
 * @param {string} resourceType - Type of resource (optional)
 */
function auditLog(action, resourceType = null) {
  return (req, res, next) => {
    // Only log if audit logging is enabled
    if (!req.securitySettings.audit_logging) {
      return next();
    }

    // Only log if user is authenticated
    if (!req.session || !req.session.user) {
      return next();
    }

    try {
      const user = req.session.user;

      db.prepare(`
        INSERT INTO audit_logs (
          user_id, username, role, action, resource_type, resource_id,
          ip_address, user_agent, details, success
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        user.id,
        user.username,
        user.role,
        action,
        resourceType,
        req.params.id || null,
        req.ip,
        req.get('user-agent'),
        JSON.stringify({
          method: req.method,
          path: req.path,
          query: req.query
        }),
        1
      );
    } catch (error) {
      console.error('Audit log error:', error);
      // Don't fail the request if audit logging fails
    }

    next();
  };
}

/**
 * Log authentication attempts
 */
function logAuthAttempt(username, success, ip, reason = null) {
  return new Promise((resolve, reject) => {
    try {
      db.prepare(`
        INSERT INTO audit_logs (username, action, ip_address, success, details)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        username,
        success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILURE',
        ip,
        success ? 1 : 0,
        reason ? JSON.stringify({ reason }) : null
      );
      resolve();
    } catch (error) {
      console.error('Auth audit log error:', error);
      resolve(); // Don't reject, just log error
    }
  });
}

module.exports = {
  auditLog,
  logAuthAttempt
};
