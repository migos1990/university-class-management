const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { db } = require('../config/database');
const { localize, t } = require('../utils/i18n');

// In-memory activity tracker for student progress monitoring
// { [studentId]: { lastActiveAt: ISO string, currentFindingId: number|null } }
const activityTracker = {};

function trackActivity(studentId, findingId) {
  if (!activityTracker[studentId]) {
    activityTracker[studentId] = { lastActiveAt: null, currentFindingId: null };
  }
  activityTracker[studentId].lastActiveAt = new Date().toISOString();
  if (findingId !== undefined) {
    activityTracker[studentId].currentFindingId = findingId;
  }
}

const DIFFICULTY_MAP = {
  1: 'easy', 2: 'easy', 3: 'easy', 4: 'easy',
  6: 'medium', 7: 'medium', 8: 'medium',
  5: 'advanced', 9: 'advanced', 10: 'advanced',
  11: 'advanced', 12: 'advanced'
};
const DIFFICULTY_ORDER = { easy: 0, medium: 1, advanced: 2 };

// Helper: import a confirmed SCA finding into the VM as a vulnerability
function importToVM(findingId, _importedBy) {
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
    trackActivity(user.id);
    const reviews = db.prepare(
      'SELECT * FROM sca_student_reviews WHERE student_id = ?'
    ).all(user.id);
    const reviewMap = {};
    reviews.forEach(r => { reviewMap[r.finding_id] = r; });
    const submitted = reviews.filter(r => r.status === 'submitted').length;
    const lang = req.session.language || 'fr';
    const enriched = findings.map(f => ({
      ...localize(f, lang),
      difficulty: DIFFICULTY_MAP[f.id] || 'medium'
    }));
    enriched.sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty]);
    return res.render('sca/student-lab', {
      title: t(lang, 'sca.studentLab.title'),
      findings: enriched,
      reviewMap,
      submitted,
      total: findings.length
    });
  }

  // Instructor / admin view
  const lang = req.session.language || 'fr';
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

  const localizedFindings = findings.map(f => localize(f, lang));

  res.render('sca/instructor', {
    title: t(lang, 'sca.instructor.title'),
    findings: localizedFindings,
    students,
    matrix,
    importedIds,
    allReviews
  });
});

// ─── GET /sca/stats ─── Live class progress JSON for polling
router.get('/stats', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const allFindings = db.prepare('SELECT * FROM sca_findings').all();
  const totalFindings = allFindings.length;
  const allStudents = db.prepare('SELECT * FROM users WHERE role = ?').all('student');
  const totalStudents = allStudents.length;
  const allReviews = db.prepare('SELECT * FROM sca_student_reviews').all();

  // Students started: those with at least 1 review record (any status: pending or submitted)
  const startedIds = new Set(allReviews.map(r => r.student_id));
  const studentsStarted = startedIds.size;

  // Average completion: mean of (submitted / totalFindings) per student, across ALL students
  const submittedCounts = {};
  allReviews.forEach(r => {
    if (r.status === 'submitted') {
      submittedCounts[r.student_id] = (submittedCounts[r.student_id] || 0) + 1;
    }
  });
  let avgCompletion = 0;
  if (totalStudents > 0 && totalFindings > 0) {
    const totalPct = Object.values(submittedCounts).reduce((sum, cnt) => sum + (cnt / totalFindings), 0);
    avgCompletion = Math.round((totalPct / totalStudents) * 100);
  }

  // Pace: submissions in last 5 minutes (only those with a non-null submitted_at)
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const pace = allReviews.filter(
    r => r.submitted_at && r.submitted_at >= fiveMinAgo
  ).length;

  // Build per-student data for instructor dashboard
  const lang = req.session.language || 'fr';
  const findingTitleMap = {};
  allFindings.forEach(f => {
    const localized = localize(f, lang);
    findingTitleMap[f.id] = localized.title;
  });

  const studentsData = allStudents.map(s => {
    const submitted = allReviews.filter(
      r => r.student_id === s.id && r.status === 'submitted'
    ).length;
    const activity = activityTracker[s.id] || {};
    return {
      id: s.id,
      username: s.username,
      submitted,
      lastActiveAt: activity.lastActiveAt || null,
      currentFindingId: activity.currentFindingId || null,
      currentFindingTitle: activity.currentFindingId
        ? (findingTitleMap[activity.currentFindingId] || null)
        : null
    };
  });

  // Sort by completion descending (most progress first)
  studentsData.sort((a, b) => b.submitted - a.submitted);

  res.json({ studentsStarted, totalStudents, avgCompletion, pace, totalFindings, students: studentsData });
});

// ─── GET /sca/findings/:id ─── Detail view (shared)
router.get('/findings/:id', requireAuth, (req, res) => {
  const finding = db.prepare('SELECT * FROM sca_findings WHERE id = ?').get(parseInt(req.params.id));
  if (!finding) return res.status(404).render('error', { message: 'Finding not found', error: { status: 404 } });

  const user = req.session.user;
  let myReview = null;
  let allReviews = [];

  if (user.role === 'student') {
    trackActivity(user.id, finding.id);
    myReview = db.prepare(
      'SELECT * FROM sca_student_reviews WHERE finding_id = ? AND student_id = ?'
    ).get(finding.id, user.id);
  } else {
    allReviews = db.prepare('SELECT * FROM sca_student_reviews WHERE finding_id = ?').all(finding.id);
  }

  const vmEntry = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get('sca', finding.id);

  const lang = req.session.language || 'fr';
  const localizedFinding = localize(finding, lang);
  localizedFinding.difficulty = DIFFICULTY_MAP[finding.id] || 'medium';

  // Only pass answer key data for instructors (AKEY-05)
  // Students receive null -- the EJS template will not emit any answer HTML
  let answerKey = null;
  if (user.role !== 'student') {
    answerKey = {
      classification: t(lang, `sca.answerKey.${finding.id}.classification`),
      reasoning: t(lang, `sca.answerKey.${finding.id}.reasoning`),
      discussion: t(lang, `sca.answerKey.${finding.id}.discussion`)
    };
  }

  // Compute prev/next navigation using difficulty sort order (matches student-lab list)
  const allFindings = db.prepare('SELECT id FROM sca_findings').all();
  const sortedIds = allFindings
    .map(f => ({ id: f.id, difficulty: DIFFICULTY_MAP[f.id] || 'medium' }))
    .sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty])
    .map(f => f.id);
  const currentIndex = sortedIds.indexOf(finding.id);
  const prevId = currentIndex > 0 ? sortedIds[currentIndex - 1] : null;
  const nextId = currentIndex < sortedIds.length - 1 ? sortedIds[currentIndex + 1] : null;

  const users = user.role !== 'student' ? db.prepare('SELECT id, username FROM users WHERE role = ?').all('student') : null;

  res.render('sca/finding-detail', {
    title: localizedFinding.title,
    finding: localizedFinding,
    myReview,
    allReviews,
    vmEntry,
    users,
    answerKey,
    needsPrism: true,
    prevId,
    nextId
  });
});

// ─── POST /sca/findings/:id/review ─── Student submit or update review
router.post('/findings/:id/review', requireAuth, requireRole(['student']), (req, res) => {
  const findingId = parseInt(req.params.id);
  const studentId = req.session.user.id;
  trackActivity(studentId);
  const { classification, student_notes, remediation_notes, action } = req.body;

  if (!['confirmed', 'false_positive', 'needs_investigation'].includes(classification)) {
    return res.status(400).json({ success: false, error: 'Invalid classification' });
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
  if (!student) return res.status(404).render('error', { message: 'Student not found', error: { status: 404 } });

  const lang = req.session.language || 'fr';
  const findings = db.prepare('SELECT * FROM sca_findings').all();
  const reviews = db.prepare('SELECT * FROM sca_student_reviews WHERE student_id = ?').all(student.id);
  const reviewMap = {};
  reviews.forEach(r => { reviewMap[r.finding_id] = r; });

  const localizedFindings = findings.map(f => localize(f, lang));

  res.render('sca/student-detail', {
    title: t(lang, 'sca.studentDetail.reviewsTitle', { username: student.username }),
    student,
    findings: localizedFindings,
    reviewMap,
    reviews
  });
});

// ─── POST /sca/import-to-vm/:id ─── Instructor: push to VM
router.post('/import-to-vm/:id', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const result = importToVM(req.params.id, req.session.user.id);
  res.json(result);
});

// --- GET /sca/answer-key --- Instructor answer key (role-gated + RBAC-bypass hardened)
router.get('/answer-key', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  // CRITICAL: Secondary check -- answer key must NEVER be visible to students
  // even when RBAC is disabled via the security panel (see middleware/rbac.js line 13)
  if (req.session.user.role === 'student') {
    return res.status(403).render('error', {
      message: 'Access Denied',
      error: { status: 403, details: 'Answer key is restricted to instructors.' }
    });
  }

  const lang = req.session.language || 'fr';
  const findings = db.prepare('SELECT * FROM sca_findings').all();
  const localizedFindings = findings.map(f => localize(f, lang));

  // Build answer key data from i18n keys
  const answerKeyData = localizedFindings.map(f => ({
    ...f,
    expectedClassification: t(lang, `sca.answerKey.${f.id}.classification`),
    reasoning: t(lang, `sca.answerKey.${f.id}.reasoning`),
    discussion: t(lang, `sca.answerKey.${f.id}.discussion`)
  }));

  res.render('sca/answer-key', {
    title: t(lang, 'sca.answerKey.title'),
    subtitle: t(lang, 'sca.answerKey.subtitle'),
    findings: answerKeyData,
    labels: {
      expectedClassification: t(lang, 'sca.answerKey.expectedClassification'),
      reasoning: t(lang, 'sca.answerKey.reasoning'),
      discussionPrompt: t(lang, 'sca.answerKey.discussionPrompt')
    }
  });
});

module.exports = { router, importToVM };
