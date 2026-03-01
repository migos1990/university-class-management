const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { db } = require('../config/database');

/**
 * GET /sessions/:id
 * View session content
 */
router.get('/:id', requireAuth, auditLog('VIEW_SESSION', 'session'), (req, res) => {
  const sessionId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Get session details with class info
  const session = db.prepare(`
    SELECT s.*, c.code as class_code, c.name as class_name
    FROM sessions s
    JOIN classes c ON s.class_id = c.id
    WHERE s.id = ?
  `).get(sessionId);

  if (!session) {
    return res.status(404).render('error', {
      message: req.t('sessions.notFound'),
      error: { status: 404 }
    });
  }

  // Check if student is enrolled (if user is a student)
  if (userRole === 'student') {
    const enrollment = db.prepare(`
      SELECT * FROM enrollments
      WHERE student_id = ? AND class_id = ?
    `).get(userId, session.class_id);

    if (!enrollment && req.securitySettings.rbac_enabled) {
      return res.status(403).render('error', {
        message: req.t('errors.accessDenied'),
        error: {
          status: 403,
          details: req.t('sessions.notEnrolled')
        }
      });
    }
  }

  res.render('session-view', {
    session,
    canEdit: userRole === 'professor' || userRole === 'admin'
  });
});

/**
 * GET /sessions/:id/edit
 * Edit session form (professors and admins only)
 */
router.get('/:id/edit', requireAuth, requireRole(['professor', 'admin']), (req, res) => {
  const sessionId = req.params.id;

  const session = db.prepare(`
    SELECT s.*, c.code as class_code, c.name as class_name
    FROM sessions s
    JOIN classes c ON s.class_id = c.id
    WHERE s.id = ?
  `).get(sessionId);

  if (!session) {
    return res.status(404).render('error', {
      message: req.t('sessions.notFound'),
      error: { status: 404 }
    });
  }

  res.render('professor/edit-session', {
    session,
    rbacBypass: req.rbacBypass
  });
});

/**
 * POST /sessions/:id/edit
 * Update session content
 */
router.post('/:id/edit', requireAuth, requireRole(['professor', 'admin']), auditLog('EDIT_SESSION', 'session'), (req, res) => {
  const sessionId = req.params.id;
  const { title, description, content } = req.body;

  try {
    db.prepare(`
      UPDATE sessions
      SET title = ?, description = ?, content = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(title, description, content, sessionId);

    res.redirect(`/sessions/${sessionId}`);
  } catch (error) {
    console.error('Update session error:', error);
    res.status(500).render('error', {
      message: req.t('sessions.updateError'),
      error
    });
  }
});

module.exports = router;
