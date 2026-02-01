const { db } = require('../config/database');

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes in milliseconds

/**
 * Check if IP is rate limited for login attempts
 */
function checkRateLimit(req, res, next) {
  // Only apply rate limiting if enabled
  if (!req.securitySettings.rate_limiting) {
    return next();
  }

  const ip = req.ip;
  const windowStart = new Date(Date.now() - WINDOW_MS).toISOString();

  try {
    // Count failed attempts in the time window
    const result = db.prepare(`
      SELECT COUNT(*) as count
      FROM rate_limit_attempts
      WHERE ip_address = ?
        AND attempt_time > ?
        AND success = 0
    `).get(ip, windowStart);

    if (result.count >= MAX_ATTEMPTS) {
      // Find the oldest attempt to calculate remaining lockout time
      const oldestAttempt = db.prepare(`
        SELECT attempt_time
        FROM rate_limit_attempts
        WHERE ip_address = ?
          AND attempt_time > ?
          AND success = 0
        ORDER BY attempt_time ASC
        LIMIT 1
      `).get(ip, windowStart);

      if (oldestAttempt) {
        const oldestTime = new Date(oldestAttempt.attempt_time).getTime();
        const unlockTime = oldestTime + WINDOW_MS;
        const remainingMs = unlockTime - Date.now();
        const remainingMinutes = Math.ceil(remainingMs / 60000);

        return res.status(429).render('error', {
          message: 'Too Many Login Attempts',
          error: {
            status: 429,
            details: `You have exceeded the maximum number of login attempts (${MAX_ATTEMPTS}). Please try again in ${remainingMinutes} minute(s).`
          }
        });
      }
    }

    next();
  } catch (error) {
    console.error('Rate limit check error:', error);
    // Don't block on error
    next();
  }
}

/**
 * Record login attempt
 */
function recordLoginAttempt(ip, username, success) {
  try {
    db.prepare(`
      INSERT INTO rate_limit_attempts (ip_address, username, success)
      VALUES (?, ?, ?)
    `).run(ip, username, success ? 1 : 0);

    // Clean up old attempts (older than window)
    const windowStart = new Date(Date.now() - WINDOW_MS).toISOString();
    db.prepare(`
      DELETE FROM rate_limit_attempts
      WHERE attempt_time < ?
    `).run(windowStart);
  } catch (error) {
    console.error('Record login attempt error:', error);
  }
}

module.exports = {
  checkRateLimit,
  recordLoginAttempt
};
