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
      message: req.t('classes.notFound'),
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
        message: req.t('errors.accessDenied'),
        error: {
          status: 403,
          details: req.t('sessions.notEnrolled')
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

/**
 * POST /classes/create
 * Create a new class (professor or admin only)
 */
router.post('/create', requireAuth, requireRole(['professor', 'admin']), auditLog('CREATE_CLASS', 'class'), (req, res) => {
  const { code, name, description, semester } = req.body;
  const professorId = req.session.user.id;

  // Validate required fields
  if (!code || !name || !semester) {
    return res.status(400).json({
      success: false,
      error: req.t('classes.codeNameSemesterRequired')
    });
  }

  // Check if class code already exists
  const existing = db.prepare('SELECT * FROM classes WHERE code = ?').get(code);
  if (existing) {
    return res.status(400).json({
      success: false,
      error: req.t('classes.codeAlreadyExists')
    });
  }

  // Insert new class
  const result = db.prepare(`
    INSERT INTO classes (code, name, description, semester, professor_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(code, name, description || '', semester, professorId);

  res.json({
    success: true,
    classId: result.lastID,
    message: req.t('classes.createdSuccessfully')
  });
});

/**
 * PUT /classes/:id
 * Update class details (professor or admin only)
 */
router.put('/:id', requireAuth, requireRole(['professor', 'admin']), auditLog('UPDATE_CLASS', 'class'), (req, res) => {
  const classId = req.params.id;
  const { code, name, description, semester } = req.body;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Get current class
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
  if (!classData) {
    return res.status(404).json({ success: false, error: req.t('classes.notFound') });
  }

  // Check ownership (professor can only update their own classes, admin can update any)
  if (userRole === 'professor' && classData.professor_id !== userId) {
    return res.status(403).json({
      success: false,
      error: req.t('classes.onlyUpdateOwn')
    });
  }

  // Validate required fields
  if (!code || !name || !semester) {
    return res.status(400).json({
      success: false,
      error: req.t('classes.codeNameSemesterRequired')
    });
  }

  // Check if new code conflicts with another class
  if (code !== classData.code) {
    const existing = db.prepare('SELECT * FROM classes WHERE code = ? AND id != ?').get(code, classId);
    if (existing) {
      return res.status(400).json({
        success: false,
        error: req.t('classes.codeAlreadyExists')
      });
    }
  }

  // Update class
  db.prepare(`
    UPDATE classes
    SET code = ?, name = ?, description = ?, semester = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(code, name, description || '', semester, classId);

  res.json({ success: true, message: req.t('classes.updatedSuccessfully') });
});

/**
 * DELETE /classes/:id
 * Delete a class (with Segregation of Duties check)
 */
router.delete('/:id', requireAuth, requireRole(['professor', 'admin']), auditLog('DELETE_CLASS', 'class'), (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;

  // Get current class
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
  if (!classData) {
    return res.status(404).json({ success: false, error: req.t('classes.notFound') });
  }

  // Check ownership (professor can only delete their own classes, admin can delete any)
  if (userRole === 'professor' && classData.professor_id !== userId) {
    return res.status(403).json({
      success: false,
      error: req.t('classes.onlyDeleteOwn')
    });
  }

  // Segregation of Duties check
  const sodEnabled = req.securitySettings.segregation_of_duties;

  if (sodEnabled && userRole === 'professor') {
    return res.status(403).json({
      success: false,
      error: req.t('classes.sodRequired'),
      requiresRequest: true
    });
  }

  // Perform deletion (cascades to sessions and enrollments)
  db.prepare('DELETE FROM classes WHERE id = ?').run(classId);

  res.json({
    success: true,
    message: req.t('classes.deletedSuccessfully')
  });
});

/**
 * GET /classes/:id/delete-request
 * Show deletion request form (professor only, when SoD is enabled)
 */
router.get('/:id/delete-request', requireAuth, requireRole(['professor']), (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;

  // Get class details
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
  if (!classData) {
    return res.status(404).render('error', {
      message: req.t('classes.notFound'),
      error: { status: 404 }
    });
  }

  // Check ownership
  if (classData.professor_id !== userId) {
    return res.status(403).render('error', {
      message: req.t('errors.accessDenied'),
      error: {
        status: 403,
        details: req.t('classes.onlyRequestOwnDeletion')
      }
    });
  }

  // Check if SoD is enabled
  if (!req.securitySettings.segregation_of_duties) {
    return res.redirect(`/classes/${classId}`);
  }

  // Check if there's already a pending request for this class
  const existingRequest = db.prepare(`
    SELECT * FROM deletion_requests
    WHERE class_id = ? AND status = 'pending'
  `).get(classId);

  res.render('classes/delete-request', {
    classData,
    existingRequest
  });
});

/**
 * POST /classes/:id/delete-request
 * Submit a deletion request (professor only, when SoD is enabled)
 */
router.post('/:id/delete-request', requireAuth, requireRole(['professor']), auditLog('REQUEST_CLASS_DELETION', 'class'), (req, res) => {
  const classId = req.params.id;
  const userId = req.session.user.id;

  // Get class details
  const classData = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
  if (!classData) {
    return res.status(404).json({ success: false, error: req.t('classes.notFound') });
  }

  // Check ownership
  if (classData.professor_id !== userId) {
    return res.status(403).json({
      success: false,
      error: req.t('classes.onlyRequestOwnDeletion')
    });
  }

  // Check if SoD is enabled
  if (!req.securitySettings.segregation_of_duties) {
    return res.status(400).json({
      success: false,
      error: req.t('classes.sodNotEnabled')
    });
  }

  // Check if there's already a pending request
  const existingRequest = db.prepare(`
    SELECT * FROM deletion_requests
    WHERE class_id = ? AND status = 'pending'
  `).get(classId);

  if (existingRequest) {
    return res.status(400).json({
      success: false,
      error: req.t('classes.requestAlreadyPending')
    });
  }

  // Create deletion request
  const result = db.prepare(`
    INSERT INTO deletion_requests (class_id, requested_by, status)
    VALUES (?, ?, 'pending')
  `).run(classId, userId);

  res.json({
    success: true,
    requestId: result.lastID,
    message: req.t('classes.requestSubmittedMessage')
  });
});

module.exports = router;
