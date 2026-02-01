const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { db } = require('../config/database');

/**
 * GET /classes/:id
 * View class details and sessions
 */
router.get('/:id', requireAuth, auditLog('VIEW_CLASS', 'class'), (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Get class details
  const classData = db.prepare(`
    SELECT c.*, u.username as professor_name
    FROM classes c
    LEFT JOIN users u ON c.professor_id = u.id
    WHERE c.id = ?
  `).get(classId);

  if (!classData) {
    return res.status(404).render('error', {
      message: 'Class not found',
      error: { status: 404 }
    });
  }

  // Check if student is enrolled (if user is a student)
  if (userRole === 'student') {
    const enrollment = db.prepare(`
      SELECT * FROM enrollments
      WHERE student_id = ? AND class_id = ?
    `).get(userId, classId);

    if (!enrollment && req.securitySettings.rbac_enabled) {
      return res.status(403).render('error', {
        message: 'Access Denied',
        error: {
          status: 403,
          details: 'You are not enrolled in this class'
        }
      });
    }
  }

  // Get all sessions for this class
  const sessions = db.prepare(`
    SELECT * FROM sessions
    WHERE class_id = ?
    ORDER BY session_number
  `).all(classId);

  // Get enrolled students
  const enrolledStudents = db.prepare(`
    SELECT u.id, u.username, u.email, e.grade
    FROM enrollments e
    JOIN users u ON e.student_id = u.id
    WHERE e.class_id = ?
    ORDER BY u.username
  `).all(classId);

  res.render('class-details', {
    classData,
    sessions,
    enrolledStudents,
    canEdit: userRole === 'professor' || userRole === 'admin'
  });
});

module.exports = router;
