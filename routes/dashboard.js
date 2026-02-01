const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { db } = require('../config/database');
const { decrypt } = require('../utils/encryption');

/**
 * GET /dashboard
 * Role-based dashboard redirect
 */
router.get('/', requireAuth, (req, res) => {
  const role = req.session.user.role;

  switch (role) {
    case 'student':
      return res.redirect('/dashboard/student');
    case 'professor':
      return res.redirect('/dashboard/professor');
    case 'admin':
      return res.redirect('/dashboard/admin');
    default:
      return res.redirect('/');
  }
});

/**
 * GET /dashboard/student
 * Student dashboard
 */
router.get('/student', requireAuth, (req, res) => {
  const userId = req.session.user.id;

  // Get enrolled classes with decrypted grades
  const enrollments = db.prepare(`
    SELECT
      e.id,
      e.grade,
      e.grade_encrypted,
      c.id as class_id,
      c.code,
      c.name,
      c.description,
      c.semester
    FROM enrollments e
    JOIN classes c ON e.class_id = c.id
    WHERE e.student_id = ?
    ORDER BY c.code
  `).all(userId);

  // Decrypt grades if encrypted
  enrollments.forEach(enrollment => {
    if (enrollment.grade_encrypted && enrollment.grade) {
      enrollment.grade = decrypt(enrollment.grade);
    }
  });

  res.render('student/dashboard', {
    enrollments
  });
});

/**
 * GET /dashboard/professor
 * Professor dashboard
 */
router.get('/professor', requireAuth, (req, res) => {
  const userId = req.session.user.id;

  // Get all classes (or classes assigned to this professor)
  const classes = db.prepare(`
    SELECT
      c.*,
      COUNT(DISTINCT e.student_id) as enrolled_count
    FROM classes c
    LEFT JOIN enrollments e ON c.id = e.class_id
    GROUP BY c.id
    ORDER BY c.code
  `).all();

  res.render('professor/dashboard', {
    classes
  });
});

/**
 * GET /dashboard/admin
 * Admin dashboard
 */
router.get('/admin', requireAuth, (req, res) => {
  // Get statistics
  const stats = {
    totalUsers: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
    totalStudents: db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('student').count,
    totalProfessors: db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('professor').count,
    totalClasses: db.prepare('SELECT COUNT(*) as count FROM classes').get().count,
    totalEnrollments: db.prepare('SELECT COUNT(*) as count FROM enrollments').get().count,
    recentLogins: db.prepare(`
      SELECT username, role, last_login
      FROM users
      WHERE last_login IS NOT NULL
      ORDER BY last_login DESC
      LIMIT 5
    `).all()
  };

  res.render('admin/dashboard', {
    stats
  });
});

module.exports = router;
