const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { db } = require('../config/database');

// Status transition rules:
//   open → in_progress          (professor / admin)
//   open → wont_fix             (admin only)
//   in_progress → resolved      (professor / admin, requires resolution_notes)
//   in_progress|resolved → open (any professor / admin — regression)
const VALID_TRANSITIONS = {
  open:        ['in_progress', 'wont_fix'],
  in_progress: ['resolved', 'open'],
  resolved:    ['open'],
  wont_fix:    ['open']
};

// Helper used by SCA/DAST/Pentest routes
function importToVM(source, sourceId, fields) {
  const existing = db.prepare(
    'SELECT * FROM vulnerabilities WHERE source = ? AND source_id = ?'
  ).get(source, sourceId);
  if (existing) return { success: false, error: 'Already imported', vulnId: existing.id };

  const now = new Date().toISOString();
  const result = db.prepare(`
    INSERT INTO vulnerabilities (id, title, source, source_id, owasp_category, cwe, cvss_vector, cvss_score,
      severity, affected_component, description, status, assigned_to, priority,
      remediation_plan, remediation_deadline, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    0, fields.title, source, sourceId,
    fields.owasp_category || null, fields.cwe || null,
    fields.cvss_vector || null, fields.cvss_score || null,
    fields.severity || 'Medium',
    fields.affected_component || null,
    fields.description || '',
    'open', null, fields.priority || 3,
    fields.remediation_plan || null, null,
    now, now
  );
  return { success: true, vulnId: result.lastID };
}

// ─── GET /vm ─── Registry
router.get('/', requireAuth, (req, res) => {
  const user = req.session.user;
  const vulns = db.prepare('SELECT * FROM vulnerabilities').all();
  const statusOrder = { open: 0, in_progress: 1, resolved: 2, wont_fix: 3 };
  vulns.sort((a, b) => {
    const so = (statusOrder[a.status] || 0) - (statusOrder[b.status] || 0);
    return so !== 0 ? so : (a.priority || 3) - (b.priority || 3);
  });

  const stats = {
    total: vulns.length,
    open: vulns.filter(v => v.status === 'open').length,
    in_progress: vulns.filter(v => v.status === 'in_progress').length,
    resolved: vulns.filter(v => v.status === 'resolved').length,
    critical: vulns.filter(v => v.severity === 'Critical').length,
    high: vulns.filter(v => v.severity === 'High').length
  };

  if (user.role === 'student') {
    return res.render('vm/student-lab', { title: req.t('labs.vm.managerTitle'), vulns, stats });
  }

  res.render('vm/instructor', { title: req.t('labs.vm.managerTitle'), vulns, stats });
});

// ─── GET /vm/stats ─── JSON counters
router.get('/stats', requireAuth, (req, res) => {
  const vulns = db.prepare('SELECT * FROM vulnerabilities').all();
  res.json({
    total: vulns.length,
    open: vulns.filter(v => v.status === 'open').length,
    in_progress: vulns.filter(v => v.status === 'in_progress').length,
    resolved: vulns.filter(v => v.status === 'resolved').length,
    wont_fix: vulns.filter(v => v.status === 'wont_fix').length,
    critical: vulns.filter(v => v.severity === 'Critical').length,
    high: vulns.filter(v => v.severity === 'High').length,
    medium: vulns.filter(v => v.severity === 'Medium').length,
    low: vulns.filter(v => v.severity === 'Low').length
  });
});

// ─── GET /vm/vulns/:id ─── Detail
router.get('/vulns/:id', requireAuth, (req, res) => {
  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(parseInt(req.params.id));
  if (!vuln) return res.status(404).render('error', { message: req.t('errors.notFound'), error: { status: 404 } });

  const history = db.prepare('SELECT * FROM vm_status_history WHERE vuln_id = ?').all(vuln.id);
  const comments = db.prepare('SELECT * FROM vm_comments WHERE vuln_id = ?').all(vuln.id);
  const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const STATUSES = ['open', 'in_progress', 'resolved', 'wont_fix'];

  res.render('vm/vuln-detail', {
    title: `VM: ${vuln.title}`,
    vuln, history, comments,
    SEVERITIES, STATUSES,
    validNext: VALID_TRANSITIONS[vuln.status] || []
  });
});

// ─── POST /vm/vulns ─── Manual create (instructor+)
router.post('/vulns', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const { title, severity, owasp_category, cwe, affected_component, description, priority } = req.body;
  if (!title || !severity) return res.status(400).json({ success: false, error: req.t('labs.vm.titleSeverityRequired') });

  const now = new Date().toISOString();
  const result = db.prepare(`
    INSERT INTO vulnerabilities (id, title, source, source_id, owasp_category, cwe, cvss_vector, cvss_score,
      severity, affected_component, description, status, assigned_to, priority,
      remediation_plan, remediation_deadline, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(0, title, 'manual', null, owasp_category || null, cwe || null, null, null,
    severity, affected_component || null, description || '', 'open', null,
    parseInt(priority) || 3, null, null, now, now);

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true, vulnId: result.lastID });
  }
  res.redirect(`/vm/vulns/${result.lastID}`);
});

// ─── PUT /vm/vulns/:id ─── Update fields (instructor+)
router.post('/vulns/:id/update', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const vulnId = parseInt(req.params.id);
  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId);
  if (!vuln) return res.status(404).json({ success: false, error: req.t('errors.notFound') });

  const { title, severity, priority, owasp_category, affected_component, description, remediation_plan, remediation_deadline, assigned_to } = req.body;
  db.prepare(`
    UPDATE vulnerabilities
    SET title = ?, severity = ?, priority = ?, owasp_category = ?, affected_component = ?,
        description = ?, remediation_plan = ?, remediation_deadline = ?, assigned_to = ?, updated_at = ?
    WHERE id = ?
  `).run(
    title || vuln.title, severity || vuln.severity, parseInt(priority) || vuln.priority,
    owasp_category || vuln.owasp_category, affected_component || vuln.affected_component,
    description || vuln.description, remediation_plan || null, remediation_deadline || null,
    assigned_to || null, new Date().toISOString(), vulnId
  );

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true });
  }
  res.redirect(`/vm/vulns/${vulnId}`);
});

// ─── POST /vm/vulns/:id/status ─── Status transition (instructor+)
router.post('/vulns/:id/status', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const vulnId = parseInt(req.params.id);
  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId);
  if (!vuln) return res.status(404).json({ success: false, error: req.t('errors.notFound') });

  const { newStatus, note, resolution_notes } = req.body;
  const user = req.session.user;

  // Validate transition
  const allowed = VALID_TRANSITIONS[vuln.status] || [];
  if (!allowed.includes(newStatus)) {
    return res.status(400).json({ success: false, error: req.t('labs.vm.invalidTransition') });
  }

  // Admin-only for wont_fix
  if (newStatus === 'wont_fix' && user.role !== 'admin') {
    return res.status(403).json({ success: false, error: req.t('labs.vm.adminOnlyWontFix') });
  }

  // Resolve requires resolution notes
  if (newStatus === 'resolved' && !resolution_notes) {
    return res.status(400).json({ success: false, error: req.t('labs.vm.resolutionNotesRequired') });
  }

  const now = new Date().toISOString();

  // Record history
  db.prepare(`
    INSERT INTO vm_status_history (vuln_id, changed_by, old_status, new_status, note, changed_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(vulnId, user.id, vuln.status, newStatus, note || null, now);

  // Update vuln
  if (newStatus === 'resolved') {
    db.prepare(`UPDATE vulnerabilities SET status = ? WHERE id = ?`).run(newStatus, vulnId);
    db.prepare(`UPDATE vulnerabilities SET title = ? WHERE id = ?`).run(vuln.title, vulnId); // force updated_at
    // Manual set resolved fields
    const v = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId);
    v.resolved_at = now;
    v.resolved_by = user.id;
    v.resolution_notes = resolution_notes;
    // Use a targeted update
    db.prepare(`
      UPDATE vulnerabilities SET status = ?, description = ?, updated_at = ?
      WHERE id = ?
    `).run(newStatus, v.description, now, vulnId);
    // Store resolved metadata via comment approach - store in history note
    db.prepare(`
      INSERT INTO vm_status_history (vuln_id, changed_by, old_status, new_status, note, changed_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(vulnId, user.id, newStatus, newStatus, `Resolution: ${resolution_notes}`, now);
  } else {
    db.prepare(`UPDATE vulnerabilities SET status = ?, updated_at = ? WHERE id = ?`).run(newStatus, now, vulnId);
  }

  res.json({ success: true, oldStatus: vuln.status, newStatus });
});

// ─── DELETE /vm/vulns/:id ─── Hard delete (admin only)
router.post('/vulns/:id/delete', requireAuth, requireRole(['admin']), (req, res) => {
  const vulnId = parseInt(req.params.id);
  const result = db.prepare('DELETE FROM vulnerabilities WHERE id = ?').run(vulnId);
  if (result.changes === 0) return res.status(404).json({ success: false, error: req.t('errors.notFound') });
  res.json({ success: true });
});

// ─── POST /vm/vulns/:id/comments ─── Add comment (all roles)
router.post('/vulns/:id/comments', requireAuth, (req, res) => {
  const vulnId = parseInt(req.params.id);
  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnId);
  if (!vuln) return res.status(404).json({ success: false, error: req.t('errors.notFound') });

  const { body } = req.body;
  if (!body || !body.trim()) return res.status(400).json({ success: false, error: req.t('labs.vm.commentBodyRequired') });

  const user = req.session.user;
  db.prepare(`
    INSERT INTO vm_comments (vuln_id, user_id, username, body, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(vulnId, user.id, user.username, body.trim(), new Date().toISOString());

  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    return res.json({ success: true });
  }
  res.redirect(`/vm/vulns/${vulnId}`);
});

module.exports = { router, importToVM };
