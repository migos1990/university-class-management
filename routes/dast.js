const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { db } = require('../config/database');

// Helper: import a DAST scenario's confirmed finding into the VM
function importToVM(scenarioId, importedBy) {
  const scenario = db.prepare('SELECT * FROM dast_scenarios WHERE id = ?').get(parseInt(scenarioId));
  if (!scenario) return { success: false, error: 'Scenario not found' };

  const existing = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get('dast', scenario.id);
  if (existing) return { success: false, error: 'Already imported', vulnId: existing.id };

  const now = new Date().toISOString();
  const result = db.prepare(`
    INSERT INTO vulnerabilities (id, title, source, source_id, owasp_category, cwe, cvss_vector, cvss_score,
      severity, affected_component, description, status, assigned_to, priority,
      remediation_plan, remediation_deadline, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    0, scenario.title, 'dast', scenario.id,
    scenario.owasp_category, null, null, scenario.cvss_base_score,
    scenario.severity, scenario.affected_file,
    scenario.expected_finding, 'open', null, 2,
    null, null, now, now
  );
  return { success: true, vulnId: result.lastID };
}

// ─── GET /dast ─── Instructor or student landing
router.get('/', requireAuth, (req, res) => {
  const user = req.session.user;
  const scenarios = db.prepare('SELECT * FROM dast_scenarios').all();

  if (user.role === 'student') {
    const myFindings = db.prepare(
      'SELECT * FROM dast_student_findings WHERE student_id = ?'
    ).all(user.id);
    const findingMap = {};
    myFindings.forEach(f => { findingMap[f.scenario_id] = f; });

    return res.render('dast/student-lab', {
      title: req.t('labs.dast.labTitle'),
      scenarios,
      findingMap,
      securitySettings: req.securitySettings
    });
  }

  // Instructor: all scenarios + submission counts
  const allFindings = db.prepare('SELECT * FROM dast_student_findings').all();
  const students = db.prepare('SELECT * FROM users WHERE role = ?').all('student');
  const countMap = {};
  scenarios.forEach(s => {
    countMap[s.id] = allFindings.filter(f => f.scenario_id === s.id);
  });

  const vmImported = db.prepare("SELECT * FROM vulnerabilities WHERE source = 'dast'").all();
  const importedIds = new Set(vmImported.map(v => v.source_id));

  res.render('dast/instructor', {
    title: req.t('labs.dast.instructorTitle'),
    scenarios,
    students,
    countMap,
    importedIds
  });
});

// ─── GET /dast/scenarios/:id ─── Detail view
router.get('/scenarios/:id', requireAuth, (req, res) => {
  const scenario = db.prepare('SELECT * FROM dast_scenarios WHERE id = ?').get(parseInt(req.params.id));
  if (!scenario) return res.status(404).render('error', { message: req.t('errors.notFound'), error: { status: 404 } });

  let steps = [];
  try { steps = JSON.parse(scenario.steps); } catch(e) { steps = []; }

  const user = req.session.user;
  let myFinding = null;
  let allFindings = [];

  if (user.role === 'student') {
    myFinding = db.prepare(
      'SELECT * FROM dast_student_findings WHERE scenario_id = ? AND student_id = ?'
    ).get(scenario.id, user.id);
  } else {
    allFindings = db.prepare('SELECT * FROM dast_student_findings WHERE scenario_id = ?').all(scenario.id);
  }

  const vmEntry = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get('dast', scenario.id);

  res.render('dast/scenario-detail', {
    title: `DAST: ${scenario.title}`,
    scenario,
    steps,
    myFinding,
    allFindings,
    vmEntry
  });
});

// ─── GET /dast/scenarios/:id/precondition ─── JSON live check
router.get('/scenarios/:id/precondition', requireAuth, (req, res) => {
  const scenario = db.prepare('SELECT * FROM dast_scenarios WHERE id = ?').get(parseInt(req.params.id));
  if (!scenario) return res.json({ met: false, message: req.t('errors.notFound') });

  const settings = req.securitySettings;
  const pre = scenario.precondition;

  if (pre === 'none') {
    return res.json({ met: true, message: req.t('labs.dast.noPrecondition') });
  }
  if (pre === 'rbac_disabled') {
    const met = !settings.rbac_enabled;
    return res.json({
      met,
      message: met
        ? req.t('labs.dast.rbacOff')
        : req.t('labs.dast.rbacRequired')
    });
  }
  if (pre === 'rate_limit_disabled') {
    const met = !settings.rate_limiting;
    return res.json({
      met,
      message: met
        ? req.t('labs.dast.rateLimitOff')
        : req.t('labs.dast.rateLimitRequired')
    });
  }

  res.json({ met: false, message: req.t('labs.dast.unknownPrecondition') });
});

// ─── POST /dast/scenarios/:id/findings ─── Student submit finding
router.post('/scenarios/:id/findings', requireAuth, requireRole(['student']), (req, res) => {
  const scenarioId = parseInt(req.params.id);
  const studentId = req.session.user.id;
  const { triggered, trigger_evidence, impact_assessment, reproduction_steps, recommendation, severity_rating, action } = req.body;

  const isSubmit = action === 'submit';
  const submittedAt = isSubmit ? new Date().toISOString() : null;

  const existing = db.prepare(
    'SELECT * FROM dast_student_findings WHERE scenario_id = ? AND student_id = ?'
  ).get(scenarioId, studentId);

  if (existing) {
    db.prepare(`
      UPDATE dast_student_findings
      SET triggered = ?, trigger_evidence = ?, impact_assessment = ?,
          reproduction_steps = ?, recommendation = ?, severity_rating = ?, submitted_at = ?
      WHERE id = ?
    `).run(
      triggered ? 1 : 0, trigger_evidence || null, impact_assessment || null,
      reproduction_steps || null, recommendation || null, severity_rating || null,
      submittedAt, existing.id
    );
  } else {
    db.prepare(`
      INSERT INTO dast_student_findings (scenario_id, student_id, triggered, trigger_evidence, impact_assessment, reproduction_steps, recommendation, severity_rating, submitted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      scenarioId, studentId, triggered ? 1 : 0,
      trigger_evidence || null, impact_assessment || null,
      reproduction_steps || null, recommendation || null,
      severity_rating || null, submittedAt
    );
  }

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true });
  }
  res.redirect(`/dast/scenarios/${scenarioId}`);
});

// ─── PUT /dast/findings/:id ─── Student update own finding
router.post('/findings/:id/update', requireAuth, requireRole(['student']), (req, res) => {
  const findingId = parseInt(req.params.id);
  const studentId = req.session.user.id;
  const finding = db.prepare('SELECT * FROM dast_student_findings WHERE id = ?').get(findingId);

  if (!finding || finding.student_id !== studentId) {
    return res.status(403).json({ success: false, error: req.t('errors.forbidden') });
  }

  const { triggered, trigger_evidence, impact_assessment, reproduction_steps, recommendation, severity_rating, action } = req.body;
  const isSubmit = action === 'submit';
  const submittedAt = isSubmit ? new Date().toISOString() : finding.submitted_at;

  db.prepare(`
    UPDATE dast_student_findings
    SET triggered = ?, trigger_evidence = ?, impact_assessment = ?,
        reproduction_steps = ?, recommendation = ?, severity_rating = ?, submitted_at = ?
    WHERE id = ?
  `).run(
    triggered ? 1 : 0, trigger_evidence || null, impact_assessment || null,
    reproduction_steps || null, recommendation || null, severity_rating || null,
    submittedAt, findingId
  );

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true });
  }
  res.redirect(`/dast/scenarios/${finding.scenario_id}`);
});

// ─── POST /dast/findings/:id/feedback ─── Instructor feedback + grade
router.post('/findings/:id/feedback', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const findingId = parseInt(req.params.id);
  const finding = db.prepare('SELECT * FROM dast_student_findings WHERE id = ?').get(findingId);
  if (!finding) return res.status(404).json({ success: false, error: req.t('errors.notFound') });

  const { instructor_feedback, grade } = req.body;
  db.prepare(`
    UPDATE dast_student_findings
    SET instructor_feedback = ?, grade = ?
    WHERE id = ?
  `).run(instructor_feedback || null, grade || null, findingId);

  res.json({ success: true });
});

// ─── POST /dast/import-to-vm/:scenarioId ─── Instructor: push to VM
router.post('/import-to-vm/:scenarioId', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const result = importToVM(req.params.scenarioId, req.session.user.id);
  res.json(result);
});

module.exports = { router, importToVM };
