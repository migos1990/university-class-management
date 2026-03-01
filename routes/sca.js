const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { db } = require('../config/database');

// Helper: import a confirmed SCA finding into the VM as a vulnerability
function importToVM(findingId, importedBy) {
  const finding = db.prepare('SELECT * FROM sca_findings WHERE id = ?').get(parseInt(findingId));
  if (!finding) return { success: false, error: 'Finding not found' };

  // Duplicate guard
  const existing = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get('sca', finding.id);
  if (existing) return { success: false, error: 'Already imported', vulnId: existing.id };

  const now = new Date().toISOString();
  const result = db.prepare(`
    INSERT INTO vulnerabilities (id, title, source, source_id, owasp_category, cwe, cvss_vector, cvss_score,
      severity, affected_component, description, status, assigned_to, priority,
      remediation_plan, remediation_deadline, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    0,  // 0 → counter-based auto-id (handled by db INSERT logic via params[0] falsy → ++counter)
    finding.title,
    'sca', finding.id,
    null, finding.cwe,
    null, null,
    finding.severity,
    finding.file_path,
    finding.description,
    'open', null, 2,
    finding.remediation, null,
    now, now
  );
  return { success: true, vulnId: result.lastID };
}

// ─── GET /sca ─── Instructor sees all findings + student review matrix
//                   Student sees their lab (findings to classify)
router.get('/', requireAuth, (req, res) => {
  const user = req.session.user;
  const findings = db.prepare('SELECT * FROM sca_findings').all();

  if (user.role === 'student') {
    const reviews = db.prepare(
      'SELECT * FROM sca_student_reviews WHERE student_id = ?'
    ).all(user.id);
    const reviewMap = {};
    reviews.forEach(r => { reviewMap[r.finding_id] = r; });
    const submitted = reviews.filter(r => r.status === 'submitted').length;
    return res.render('sca/student-lab', {
      title: req.t('labs.sca.labTitle'),
      findings,
      reviewMap,
      submitted,
      total: findings.length
    });
  }

  // Instructor / admin view
  const allReviews = db.prepare('SELECT * FROM sca_student_reviews').all();
  const students = db.prepare('SELECT * FROM users WHERE role = ?').all('student');

  // Build matrix: findingId → { studentId → review }
  const matrix = {};
  findings.forEach(f => { matrix[f.id] = {}; });
  allReviews.forEach(r => {
    if (matrix[r.finding_id]) matrix[r.finding_id][r.student_id] = r;
  });

  // Check which findings are already in VM
  const vmFindings = db.prepare(
    "SELECT * FROM vulnerabilities WHERE source = 'sca'"
  ).all();
  const importedIds = new Set(vmFindings.map(v => v.source_id));

  res.render('sca/instructor', {
    title: req.t('labs.sca.instructorTitle'),
    findings,
    students,
    matrix,
    importedIds,
    allReviews
  });
});

// ─── GET /sca/findings/:id ─── Detail view (shared)
router.get('/findings/:id', requireAuth, (req, res) => {
  const finding = db.prepare('SELECT * FROM sca_findings WHERE id = ?').get(parseInt(req.params.id));
  if (!finding) return res.status(404).render('error', { message: req.t('errors.notFound'), error: { status: 404 } });

  const user = req.session.user;
  let myReview = null;
  let allReviews = [];

  if (user.role === 'student') {
    myReview = db.prepare(
      'SELECT * FROM sca_student_reviews WHERE finding_id = ? AND student_id = ?'
    ).get(finding.id, user.id);
  } else {
    allReviews = db.prepare('SELECT * FROM sca_student_reviews WHERE finding_id = ?').all(finding.id);
  }

  const vmEntry = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get('sca', finding.id);

  res.render('sca/finding-detail', {
    title: `SCA: ${finding.title}`,
    finding,
    myReview,
    allReviews,
    vmEntry
  });
});

// ─── POST /sca/findings/:id/review ─── Student submit or update review
router.post('/findings/:id/review', requireAuth, requireRole(['student']), (req, res) => {
  const findingId = parseInt(req.params.id);
  const studentId = req.session.user.id;
  const { classification, student_notes, remediation_notes, action } = req.body;

  if (!['confirmed', 'false_positive', 'needs_investigation'].includes(classification)) {
    return res.status(400).json({ success: false, error: req.t('labs.sca.invalidClassification') });
  }

  const isSubmit = action === 'submit';
  const status = isSubmit ? 'submitted' : 'pending';
  const submittedAt = isSubmit ? new Date().toISOString() : null;

  const existing = db.prepare(
    'SELECT * FROM sca_student_reviews WHERE finding_id = ? AND student_id = ?'
  ).get(findingId, studentId);

  if (existing) {
    db.prepare(`
      UPDATE sca_student_reviews
      SET classification = ?, student_notes = ?, remediation_notes = ?, status = ?, submitted_at = ?
      WHERE id = ?
    `).run(classification, student_notes || null, remediation_notes || null, status, submittedAt, existing.id);
  } else {
    db.prepare(`
      INSERT INTO sca_student_reviews (finding_id, student_id, classification, student_notes, remediation_notes, status, submitted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(findingId, studentId, classification, student_notes || null, remediation_notes || null, status, submittedAt);
  }

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true });
  }
  res.redirect(`/sca/findings/${findingId}`);
});

// ─── GET /sca/student/:studentId ─── Instructor: view a student's reviews
router.get('/student/:studentId', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const student = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.studentId);
  if (!student) return res.status(404).render('error', { message: req.t('errors.notFound'), error: { status: 404 } });

  const findings = db.prepare('SELECT * FROM sca_findings').all();
  const reviews = db.prepare('SELECT * FROM sca_student_reviews WHERE student_id = ?').all(student.id);
  const reviewMap = {};
  reviews.forEach(r => { reviewMap[r.finding_id] = r; });

  res.render('sca/student-detail', {
    title: `SCA Reviews: ${student.username}`,
    student,
    findings,
    reviewMap,
    reviews
  });
});

// ─── POST /sca/import-to-vm/:id ─── Instructor: push to VM
router.post('/import-to-vm/:id', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const result = importToVM(req.params.id, req.session.user.id);
  res.json(result);
});

module.exports = { router, importToVM };
