const { db } = require('../config/database');

/**
 * Middleware to require specific role(s)
 * @param {string|string[]} allowedRoles - Single role or array of allowed roles
 */
function requireRole(allowedRoles) {
  // Ensure allowedRoles is an array
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  return (req, res, next) => {
    // Check if RBAC is enabled
    if (!req.securitySettings.rbac_enabled) {
      // RBAC is disabled, allow access but show warning
      req.rbacBypass = true;
      return next();
    }

    // Check if user is authenticated
    if (!req.session || !req.session.user) {
      return res.redirect('/?error=Please login first');
    }

    // Check if user's role is in allowed roles
    if (roles.includes(req.session.user.role)) {
      return next();
    }

    // Access denied - log to audit if enabled
    if (req.securitySettings.audit_logging) {
      db.prepare(`
        INSERT INTO audit_logs (user_id, username, role, action, resource_type, ip_address, success)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.session.user.id,
        req.session.user.username,
        req.session.user.role,
        'RBAC_DENIED',
        req.path,
        req.ip,
        0
      );
    }

    // Return 403 Forbidden
    res.status(403).render('error', {
      message: 'Access Denied',
      error: {
        status: 403,
        details: `This page requires ${roles.join(' or ')} role. You are logged in as ${req.session.user.role}.`
      }
    });
  };
}

module.exports = {
  requireRole
};
