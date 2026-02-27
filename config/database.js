const path = require('path');
const fs = require('fs');

const dbDir = process.env.DATA_DIR || path.join(__dirname, '..', 'database');
const dbPath = path.join(dbDir, 'data.json');
const dbTmpPath = path.join(dbDir, 'data.json.tmp');

// Ensure database directory exists
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// In-memory database structure
let db = {
  users: [],
  classes: [],
  sessions: [],
  enrollments: [],
  security_settings: [{ id: 1, mfa_enabled: 0, rbac_enabled: 1, encryption_at_rest: 0, field_encryption: 0, https_enabled: 0, audit_logging: 0, rate_limiting: 0, backup_enabled: 0, backup_frequency: 60, last_backup_time: null, segregation_of_duties: 0 }],
  audit_logs: [],
  rate_limit_attempts: [],
  deletion_requests: [],
  // Security curriculum collections
  sca_findings: [],
  sca_student_reviews: [],
  dast_scenarios: [],
  dast_student_findings: [],
  vulnerabilities: [],
  vm_status_history: [],
  vm_comments: [],
  pentest_engagements: [],
  pentest_findings: [],
  pentest_phase_notes: [],
  _counters: {
    users: 0, classes: 0, sessions: 0, enrollments: 0,
    audit_logs: 0, rate_limit_attempts: 0, deletion_requests: 0,
    sca_student_reviews: 0,
    dast_student_findings: 0,
    vulnerabilities: 0,
    vm_status_history: 0,
    vm_comments: 0,
    pentest_engagements: 0,
    pentest_findings: 0,
    pentest_phase_notes: 0
  }
};

// Required top-level keys for a valid database
const REQUIRED_KEYS = ['users', 'classes', 'sessions', 'enrollments', 'security_settings'];

// Validate that parsed data has the expected structure
function isValidDatabase(data) {
  if (!data || typeof data !== 'object') return false;
  return REQUIRED_KEYS.every(key => Array.isArray(data[key]) || (key === '_counters' && typeof data[key] === 'object'));
}

// Attempt to recover database from the most recent backup
function attemptRecoveryFromBackup() {
  const backupDir = path.join(__dirname, '..', 'backups');
  if (!fs.existsSync(backupDir)) return false;

  try {
    const backupFiles = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('backup-') && f.endsWith('.json'))
      .sort()
      .reverse(); // Most recent first

    for (const file of backupFiles) {
      try {
        const backupData = fs.readFileSync(path.join(backupDir, file), 'utf8');
        const parsed = JSON.parse(backupData);
        if (isValidDatabase(parsed)) {
          db = parsed;
          // Write recovered data as the new main database
          fs.writeFileSync(dbPath, backupData, 'utf8');
          console.log(`✓ Database recovered from backup: ${file}`);
          return true;
        }
      } catch (e) {
        // Skip invalid backup files
      }
    }
  } catch (error) {
    console.error('Backup recovery scan failed:', error.message);
  }
  return false;
}

// Load database from file if exists
function loadDatabase() {
  if (fs.existsSync(dbPath)) {
    try {
      const data = fs.readFileSync(dbPath, 'utf8');
      const parsed = JSON.parse(data);

      if (isValidDatabase(parsed)) {
        db = parsed;
        console.log('Database loaded from file');
        return;
      }

      // Parsed OK but invalid structure — try backups
      console.warn('Warning: Database file has invalid structure, attempting recovery...');
      if (!attemptRecoveryFromBackup()) {
        console.warn('Warning: No valid backup found. Database will be re-initialized.');
      }
    } catch (error) {
      console.error('Error loading database:', error.message);
      // JSON parse failed — try recovery from temp file
      if (fs.existsSync(dbTmpPath)) {
        try {
          const tmpData = fs.readFileSync(dbTmpPath, 'utf8');
          const parsed = JSON.parse(tmpData);
          if (isValidDatabase(parsed)) {
            db = parsed;
            fs.renameSync(dbTmpPath, dbPath);
            console.log('✓ Database recovered from temp file');
            return;
          }
        } catch (tmpError) {
          // Temp file also corrupt
        }
      }
      // Try backups as last resort
      if (!attemptRecoveryFromBackup()) {
        console.warn('Warning: All recovery attempts failed. Database will be re-initialized.');
      }
    }
  }
}

// Save database to file using atomic write (write temp, then rename)
function saveDatabase() {
  try {
    const data = JSON.stringify(db, null, 2);
    fs.writeFileSync(dbTmpPath, data, 'utf8');
    fs.renameSync(dbTmpPath, dbPath);
  } catch (error) {
    console.error('Error saving database:', error.message);
  }
}

// Simple query interface to mimic SQL
const dbInterface = {
  prepare: (sql) => ({
    run: (...params) => {
      const result = executeSQL(sql, params);
      saveDatabase();
      return result;
    },
    get: (...params) => executeSQL(sql, params),
    all: (...params) => executeSQL(sql, params)
  }),
  exec: (sql) => {
    // For schema creation, just ignore (we use JSON structure)
    return;
  }
};

function executeSQL(sql, params = []) {
  sql = sql.trim();

  // SELECT queries
  if (sql.startsWith('SELECT')) {
    if (sql.includes('FROM users')) {
      if (sql.includes('WHERE username')) {
        return db.users.find(u => u.username === params[0]) || null;
      }
      if (sql.includes('WHERE id')) {
        return db.users.find(u => u.id === params[0]) || null;
      }
      if (sql.includes('WHERE role')) {
        return db.users.filter(u => u.role === params[0]);
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.users.length };
      }
      if (sql.includes('last_login')) {
        return db.users.filter(u => u.last_login).sort((a, b) => new Date(b.last_login) - new Date(a.last_login)).slice(0, 5);
      }
      return db.users;
    }

    if (sql.includes('FROM classes')) {
      if (sql.includes('WHERE id')) {
        const cls = db.classes.find(c => c.id === parseInt(params[0]));
        if (cls && sql.includes('u.username')) {
          const prof = db.users.find(u => u.id === cls.professor_id);
          return { ...cls, professor_name: prof ? prof.username : null };
        }
        return cls || null;
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.classes.length };
      }
      if (sql.includes('enrolled_count')) {
        return db.classes.map(c => ({
          ...c,
          enrolled_count: db.enrollments.filter(e => e.class_id === c.id).length
        }));
      }
      if (sql.includes('WHERE code')) {
        return db.classes.find(c => c.code === params[0]) || null;
      }
      return db.classes;
    }

    if (sql.includes('FROM sessions')) {
      if (sql.includes('WHERE id')) {
        const session = db.sessions.find(s => s.id === parseInt(params[0]));
        if (session && sql.includes('c.code')) {
          const cls = db.classes.find(c => c.id === session.class_id);
          return { ...session, class_code: cls?.code, class_name: cls?.name };
        }
        return session || null;
      }
      if (sql.includes('WHERE class_id')) {
        return db.sessions.filter(s => s.class_id === parseInt(params[0])).sort((a, b) => a.session_number - b.session_number);
      }
      return db.sessions;
    }

    if (sql.includes('FROM enrollments')) {
      if (sql.includes('WHERE student_id') && sql.includes('AND class_id')) {
        return db.enrollments.find(e => e.student_id === params[0] && e.class_id === params[1]) || null;
      }
      if (sql.includes('WHERE student_id')) {
        const studentId = params[0];
        return db.enrollments.filter(e => e.student_id === studentId).map(e => {
          const cls = db.classes.find(c => c.id === e.class_id);
          return { ...e, ...cls };
        });
      }
      if (sql.includes('WHERE class_id')) {
        const classId = params[0];
        return db.enrollments.filter(e => e.class_id === classId).map(e => {
          const user = db.users.find(u => u.id === e.student_id);
          return { ...e, ...user };
        });
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.enrollments.length };
      }
      return db.enrollments;
    }

    if (sql.includes('FROM security_settings')) {
      return db.security_settings[0] || null;
    }

    if (sql.includes('FROM audit_logs')) {
      if (sql.includes('LIMIT') && sql.includes('OFFSET')) {
        const limit = parseInt(params[0]);
        const offset = parseInt(params[1]);
        return db.audit_logs.slice().reverse().slice(offset, offset + limit);
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.audit_logs.length };
      }
      return db.audit_logs.slice().reverse();
    }

    if (sql.includes('FROM rate_limit_attempts')) {
      if (sql.includes('COUNT(*)') && sql.includes('WHERE')) {
        const ip = params[0];
        const since = params[1];
        return { count: db.rate_limit_attempts.filter(a => a.ip_address === ip && a.attempt_time > since && a.success === 0).length };
      }
      if (sql.includes('ORDER BY attempt_time')) {
        const ip = params[0];
        const since = params[1];
        const attempt = db.rate_limit_attempts.filter(a => a.ip_address === ip && a.attempt_time > since && a.success === 0)[0];
        return attempt || null;
      }
    }

    if (sql.includes('FROM deletion_requests')) {
      if (sql.includes('WHERE id')) {
        return db.deletion_requests.find(dr => dr.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE class_id')) {
        return db.deletion_requests.find(dr => dr.class_id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE status')) {
        const status = params[0];
        if (sql.includes('AND requested_by')) {
          const requestedBy = params[1];
          return db.deletion_requests.filter(dr => dr.status === status && dr.requested_by === requestedBy);
        }
        return db.deletion_requests.filter(dr => dr.status === status);
      }
      if (sql.includes('WHERE requested_by')) {
        return db.deletion_requests.filter(dr => dr.requested_by === params[0]);
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.deletion_requests.length };
      }
      if (sql.includes('c.code') && sql.includes('u.username')) {
        return db.deletion_requests.map(dr => {
          const cls = db.classes.find(c => c.id === dr.class_id);
          const requester = db.users.find(u => u.id === dr.requested_by);
          const reviewer = dr.reviewed_by ? db.users.find(u => u.id === dr.reviewed_by) : null;
          return {
            ...dr,
            class_code: cls?.code,
            class_name: cls?.name,
            requester_name: requester?.username,
            reviewer_name: reviewer?.username
          };
        });
      }
      return db.deletion_requests;
    }

    // --- SCA ---
    if (sql.includes('FROM sca_findings')) {
      if (!db.sca_findings) db.sca_findings = [];
      if (sql.includes('WHERE id')) {
        return db.sca_findings.find(f => f.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE severity')) {
        return db.sca_findings.filter(f => f.severity === params[0]);
      }
      return db.sca_findings;
    }

    if (sql.includes('FROM sca_student_reviews')) {
      if (!db.sca_student_reviews) db.sca_student_reviews = [];
      if (sql.includes('WHERE finding_id') && sql.includes('AND student_id')) {
        return db.sca_student_reviews.find(r => r.finding_id === parseInt(params[0]) && r.student_id === params[1]) || null;
      }
      if (sql.includes('WHERE finding_id')) {
        return db.sca_student_reviews.filter(r => r.finding_id === parseInt(params[0]));
      }
      if (sql.includes('WHERE student_id')) {
        return db.sca_student_reviews.filter(r => r.student_id === params[0]);
      }
      return db.sca_student_reviews;
    }

    // --- DAST ---
    if (sql.includes('FROM dast_scenarios')) {
      if (!db.dast_scenarios) db.dast_scenarios = [];
      if (sql.includes('WHERE id')) {
        return db.dast_scenarios.find(s => s.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE active')) {
        return db.dast_scenarios.filter(s => s.active === 1);
      }
      return db.dast_scenarios;
    }

    if (sql.includes('FROM dast_student_findings')) {
      if (!db.dast_student_findings) db.dast_student_findings = [];
      if (sql.includes('WHERE id')) {
        return db.dast_student_findings.find(f => f.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE scenario_id') && sql.includes('AND student_id')) {
        return db.dast_student_findings.find(f => f.scenario_id === parseInt(params[0]) && f.student_id === params[1]) || null;
      }
      if (sql.includes('WHERE scenario_id')) {
        return db.dast_student_findings.filter(f => f.scenario_id === parseInt(params[0]));
      }
      if (sql.includes('WHERE student_id')) {
        return db.dast_student_findings.filter(f => f.student_id === params[0]);
      }
      return db.dast_student_findings;
    }

    // --- VM ---
    if (sql.includes('FROM vulnerabilities')) {
      if (!db.vulnerabilities) db.vulnerabilities = [];
      if (sql.includes('WHERE id')) {
        return db.vulnerabilities.find(v => v.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE source') && sql.includes('AND source_id')) {
        return db.vulnerabilities.find(v => v.source === params[0] && v.source_id === params[1]) || null;
      }
      if (sql.includes('WHERE severity')) {
        return db.vulnerabilities.filter(v => v.severity === params[0]);
      }
      if (sql.includes('WHERE status')) {
        return db.vulnerabilities.filter(v => v.status === params[0]);
      }
      if (sql.includes('WHERE assigned_to')) {
        return db.vulnerabilities.filter(v => v.assigned_to === params[0]);
      }
      if (sql.includes('COUNT(*)') && sql.includes('WHERE severity')) {
        const sev = params[0];
        return { count: db.vulnerabilities.filter(v => v.severity === sev).length };
      }
      if (sql.includes('COUNT(*)') && sql.includes('WHERE status')) {
        const st = params[0];
        return { count: db.vulnerabilities.filter(v => v.status === st).length };
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.vulnerabilities.length };
      }
      return db.vulnerabilities.slice().sort((a, b) => b.id - a.id);
    }

    if (sql.includes('FROM vm_status_history')) {
      if (!db.vm_status_history) db.vm_status_history = [];
      if (sql.includes('WHERE vuln_id')) {
        return db.vm_status_history.filter(h => h.vuln_id === parseInt(params[0])).sort((a, b) => new Date(b.changed_at) - new Date(a.changed_at));
      }
      return db.vm_status_history;
    }

    if (sql.includes('FROM vm_comments')) {
      if (!db.vm_comments) db.vm_comments = [];
      if (sql.includes('WHERE vuln_id')) {
        return db.vm_comments.filter(c => c.vuln_id === parseInt(params[0])).sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      }
      return db.vm_comments;
    }

    // --- Pentest ---
    if (sql.includes('FROM pentest_engagements')) {
      if (!db.pentest_engagements) db.pentest_engagements = [];
      if (sql.includes('WHERE id')) {
        return db.pentest_engagements.find(e => e.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE student_id')) {
        return db.pentest_engagements.find(e => e.student_id === params[0]) || null;
      }
      return db.pentest_engagements.slice().sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
    }

    if (sql.includes('FROM pentest_findings')) {
      if (!db.pentest_findings) db.pentest_findings = [];
      if (sql.includes('WHERE id')) {
        return db.pentest_findings.find(f => f.id === parseInt(params[0])) || null;
      }
      if (sql.includes('WHERE engagement_id') && sql.includes('AND phase')) {
        return db.pentest_findings.filter(f => f.engagement_id === parseInt(params[0]) && f.phase === params[1]);
      }
      if (sql.includes('WHERE engagement_id')) {
        return db.pentest_findings.filter(f => f.engagement_id === parseInt(params[0]));
      }
      return db.pentest_findings;
    }

    if (sql.includes('FROM pentest_phase_notes')) {
      if (!db.pentest_phase_notes) db.pentest_phase_notes = [];
      if (sql.includes('WHERE engagement_id') && sql.includes('AND phase')) {
        return db.pentest_phase_notes.find(n => n.engagement_id === parseInt(params[0]) && n.phase === params[1]) || null;
      }
      if (sql.includes('WHERE engagement_id')) {
        return db.pentest_phase_notes.filter(n => n.engagement_id === parseInt(params[0]));
      }
      return db.pentest_phase_notes;
    }
  }

  // INSERT queries
  if (sql.startsWith('INSERT INTO')) {
    if (sql.includes('INTO users')) {
      const user = {
        id: ++db._counters.users,
        username: params[0],
        email: params[1],
        password: params[2],
        password_hash: null,
        password_is_hashed: 0,
        role: params[3],
        ssn: params[4] || null,
        ssn_encrypted: 0,
        mfa_enabled: 0,
        mfa_secret: null,
        mfa_backup_codes: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_login: null
      };
      db.users.push(user);
      return { lastID: user.id, changes: 1 };
    }

    if (sql.includes('INTO classes')) {
      const cls = {
        id: ++db._counters.classes,
        code: params[0],
        name: params[1],
        description: params[2],
        semester: params[3],
        professor_id: params[4],
        created_at: new Date().toISOString()
      };
      db.classes.push(cls);
      return { lastID: cls.id, changes: 1 };
    }

    if (sql.includes('INTO sessions')) {
      const session = {
        id: ++db._counters.sessions,
        class_id: params[0],
        session_number: params[1],
        title: params[2],
        description: params[3],
        content: params[4],
        date: params[5],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      db.sessions.push(session);
      return { lastID: session.id, changes: 1 };
    }

    if (sql.includes('INTO enrollments')) {
      const enrollment = {
        id: ++db._counters.enrollments,
        student_id: params[0],
        class_id: params[1],
        grade: params[2] || null,
        grade_encrypted: 0,
        enrolled_date: new Date().toISOString()
      };
      db.enrollments.push(enrollment);
      return { lastID: enrollment.id, changes: 1 };
    }

    if (sql.includes('INTO audit_logs')) {
      const log = {
        id: ++db._counters.audit_logs,
        user_id: params[0],
        username: params[1],
        role: params[2],
        action: params[3],
        resource_type: params[4] || null,
        resource_id: params[5] || null,
        ip_address: params[6] || null,
        user_agent: params[7] || null,
        details: params[8] || null,
        success: params[9] !== undefined ? params[9] : 1,
        timestamp: new Date().toISOString()
      };
      db.audit_logs.push(log);

      // Auto-prune: keep only the most recent 1000 entries
      const MAX_AUDIT_ENTRIES = 1000;
      if (db.audit_logs.length > MAX_AUDIT_ENTRIES) {
        db.audit_logs = db.audit_logs.slice(-MAX_AUDIT_ENTRIES);
      }

      return { lastID: log.id, changes: 1 };
    }

    if (sql.includes('INTO rate_limit_attempts')) {
      const attempt = {
        id: ++db._counters.rate_limit_attempts,
        ip_address: params[0],
        username: params[1],
        attempt_time: new Date().toISOString(),
        success: params[2] || 0
      };
      db.rate_limit_attempts.push(attempt);
      return { lastID: attempt.id, changes: 1 };
    }

    if (sql.includes('INTO deletion_requests')) {
      const request = {
        id: ++db._counters.deletion_requests,
        class_id: params[0],
        requested_by: params[1],
        requested_at: new Date().toISOString(),
        status: params[2] || 'pending',
        reviewed_by: null,
        reviewed_at: null,
        rejection_reason: null
      };
      db.deletion_requests.push(request);
      return { lastID: request.id, changes: 1 };
    }

    // --- SCA ---
    if (sql.includes('INTO sca_findings')) {
      if (!db.sca_findings) db.sca_findings = [];
      const finding = {
        id: params[0],  // pre-assigned id from seed
        title: params[1],
        file_path: params[2],
        line_number: params[3],
        code_snippet: params[4],
        category: params[5],
        cwe: params[6],
        severity: params[7],
        description: params[8],
        tool: params[9],
        remediation: params[10],
        false_positive_reason: params[11] || null,
        created_at: new Date().toISOString()
      };
      db.sca_findings.push(finding);
      return { lastID: finding.id, changes: 1 };
    }

    if (sql.includes('INTO sca_student_reviews')) {
      if (!db.sca_student_reviews) db.sca_student_reviews = [];
      if (!db._counters.sca_student_reviews) db._counters.sca_student_reviews = 0;
      const review = {
        id: ++db._counters.sca_student_reviews,
        finding_id: params[0],
        student_id: params[1],
        classification: params[2],
        student_notes: params[3] || null,
        remediation_notes: params[4] || null,
        status: params[5] || 'pending',
        submitted_at: params[6] || null,
        created_at: new Date().toISOString()
      };
      db.sca_student_reviews.push(review);
      return { lastID: review.id, changes: 1 };
    }

    // --- DAST ---
    if (sql.includes('INTO dast_scenarios')) {
      if (!db.dast_scenarios) db.dast_scenarios = [];
      const scenario = {
        id: params[0],
        title: params[1],
        vulnerability_type: params[2],
        owasp_category: params[3],
        severity: params[4],
        description: params[5],
        precondition: params[6] || 'none',
        steps: params[7],
        exploit_url: params[8] || null,
        expected_finding: params[9],
        affected_file: params[10],
        affected_lines: params[11] || null,
        cvss_base_score: params[12] || null,
        active: params[13] !== undefined ? params[13] : 1
      };
      db.dast_scenarios.push(scenario);
      return { lastID: scenario.id, changes: 1 };
    }

    if (sql.includes('INTO dast_student_findings')) {
      if (!db.dast_student_findings) db.dast_student_findings = [];
      if (!db._counters.dast_student_findings) db._counters.dast_student_findings = 0;
      const finding = {
        id: ++db._counters.dast_student_findings,
        scenario_id: params[0],
        student_id: params[1],
        triggered: params[2] || 0,
        trigger_evidence: params[3] || null,
        impact_assessment: params[4] || null,
        reproduction_steps: params[5] || null,
        recommendation: params[6] || null,
        severity_rating: params[7] || null,
        submitted_at: params[8] || null,
        instructor_feedback: null,
        grade: null,
        created_at: new Date().toISOString()
      };
      db.dast_student_findings.push(finding);
      return { lastID: finding.id, changes: 1 };
    }

    // --- VM ---
    if (sql.includes('INTO vulnerabilities')) {
      if (!db.vulnerabilities) db.vulnerabilities = [];
      if (!db._counters.vulnerabilities) db._counters.vulnerabilities = 0;
      const vuln = {
        id: params[0] || ++db._counters.vulnerabilities,
        title: params[1],
        source: params[2],
        source_id: params[3] || null,
        owasp_category: params[4] || null,
        cwe: params[5] || null,
        cvss_vector: params[6] || null,
        cvss_score: params[7] || null,
        severity: params[8],
        affected_component: params[9] || null,
        description: params[10],
        status: params[11] || 'open',
        assigned_to: params[12] || null,
        priority: params[13] || 3,
        remediation_plan: params[14] || null,
        remediation_deadline: params[15] || null,
        created_at: params[16] || new Date().toISOString(),
        updated_at: params[17] || new Date().toISOString(),
        resolved_at: null,
        resolved_by: null,
        resolution_notes: null
      };
      db.vulnerabilities.push(vuln);
      if (vuln.id > db._counters.vulnerabilities) db._counters.vulnerabilities = vuln.id;
      return { lastID: vuln.id, changes: 1 };
    }

    if (sql.includes('INTO vm_status_history')) {
      if (!db.vm_status_history) db.vm_status_history = [];
      if (!db._counters.vm_status_history) db._counters.vm_status_history = 0;
      const entry = {
        id: ++db._counters.vm_status_history,
        vuln_id: params[0],
        changed_by: params[1],
        old_status: params[2],
        new_status: params[3],
        note: params[4] || null,
        changed_at: new Date().toISOString()
      };
      db.vm_status_history.push(entry);
      return { lastID: entry.id, changes: 1 };
    }

    if (sql.includes('INTO vm_comments')) {
      if (!db.vm_comments) db.vm_comments = [];
      if (!db._counters.vm_comments) db._counters.vm_comments = 0;
      const comment = {
        id: ++db._counters.vm_comments,
        vuln_id: params[0],
        user_id: params[1],
        username: params[2],
        body: params[3],
        created_at: new Date().toISOString()
      };
      db.vm_comments.push(comment);
      return { lastID: comment.id, changes: 1 };
    }

    // --- Pentest ---
    if (sql.includes('INTO pentest_engagements')) {
      if (!db.pentest_engagements) db.pentest_engagements = [];
      if (!db._counters.pentest_engagements) db._counters.pentest_engagements = 0;
      const engagement = {
        id: ++db._counters.pentest_engagements,
        student_id: params[0],
        title: params[1],
        status: params[2] || 'in_progress',
        phase_current: params[3] || 'recon',
        started_at: new Date().toISOString(),
        submitted_at: null,
        instructor_grade: null,
        instructor_feedback: null
      };
      db.pentest_engagements.push(engagement);
      return { lastID: engagement.id, changes: 1 };
    }

    if (sql.includes('INTO pentest_findings')) {
      if (!db.pentest_findings) db.pentest_findings = [];
      if (!db._counters.pentest_findings) db._counters.pentest_findings = 0;
      const finding = {
        id: ++db._counters.pentest_findings,
        engagement_id: params[0],
        phase: params[1],
        title: params[2],
        severity: params[3],
        cvss_score: params[4] || null,
        description: params[5],
        affected_url: params[6] || null,
        evidence: params[7] || null,
        recommendation: params[8] || null,
        created_at: new Date().toISOString()
      };
      db.pentest_findings.push(finding);
      return { lastID: finding.id, changes: 1 };
    }

    if (sql.includes('INTO pentest_phase_notes')) {
      if (!db.pentest_phase_notes) db.pentest_phase_notes = [];
      if (!db._counters.pentest_phase_notes) db._counters.pentest_phase_notes = 0;
      const notes = {
        id: ++db._counters.pentest_phase_notes,
        engagement_id: params[0],
        phase: params[1],
        notes: params[2] || '',
        tools_used: params[3] || '',
        updated_at: new Date().toISOString()
      };
      db.pentest_phase_notes.push(notes);
      return { lastID: notes.id, changes: 1 };
    }
  }

  // UPDATE queries
  if (sql.startsWith('UPDATE')) {
    if (sql.includes('UPDATE users')) {
      const userId = params[params.length - 1];
      const user = db.users.find(u => u.id === userId);
      if (user) {
        if (sql.includes('password_hash')) {
          user.password_hash = params[0];
          user.password_is_hashed = params[1];
        }
        if (sql.includes('password_is_hashed')) {
          user.password_is_hashed = params[0];
          user.password_hash = null;
        }
        if (sql.includes('ssn =')) {
          user.ssn = params[0];
          user.ssn_encrypted = params[1];
        }
        if (sql.includes('mfa_enabled')) {
          if (sql.includes('mfa_secret')) {
            user.mfa_enabled = params[0];
            user.mfa_secret = params[1];
          } else {
            user.mfa_enabled = 0;
            user.mfa_secret = null;
            user.mfa_backup_codes = null;
          }
        }
        if (sql.includes('last_login')) {
          user.last_login = new Date().toISOString();
        }
        user.updated_at = new Date().toISOString();
      }
      return { changes: user ? 1 : 0 };
    }

    if (sql.includes('UPDATE sessions')) {
      const sessionId = params[params.length - 1];
      const session = db.sessions.find(s => s.id === sessionId);
      if (session) {
        session.title = params[0];
        session.description = params[1];
        session.content = params[2];
        session.updated_at = new Date().toISOString();
      }
      return { changes: session ? 1 : 0 };
    }

    if (sql.includes('UPDATE enrollments')) {
      const enrollmentId = params[params.length - 1];
      const enrollment = db.enrollments.find(e => e.id === enrollmentId);
      if (enrollment) {
        enrollment.grade = params[0];
        enrollment.grade_encrypted = params[1];
      }
      return { changes: enrollment ? 1 : 0 };
    }

    if (sql.includes('UPDATE security_settings')) {
      const settings = db.security_settings[0];
      if (sql.includes('mfa_enabled')) settings.mfa_enabled = params[0];
      if (sql.includes('rbac_enabled')) settings.rbac_enabled = params[0];
      if (sql.includes('encryption_at_rest')) settings.encryption_at_rest = params[0];
      if (sql.includes('field_encryption')) settings.field_encryption = params[0];
      if (sql.includes('https_enabled')) settings.https_enabled = params[0];
      if (sql.includes('audit_logging')) settings.audit_logging = params[0];
      if (sql.includes('rate_limiting')) settings.rate_limiting = params[0];
      if (sql.includes('backup_enabled')) settings.backup_enabled = params[0];
      if (sql.includes('backup_frequency')) settings.backup_frequency = params[0];
      if (sql.includes('last_backup_time')) settings.last_backup_time = params[0];
      if (sql.includes('segregation_of_duties')) settings.segregation_of_duties = params[0];
      settings.updated_at = new Date().toISOString();
      return { changes: 1 };
    }

    if (sql.includes('UPDATE deletion_requests')) {
      const requestId = params[params.length - 1];
      const request = db.deletion_requests.find(dr => dr.id === requestId);
      if (request) {
        if (sql.includes('status')) {
          request.status = params[0];
          request.reviewed_by = params[1];
          request.reviewed_at = new Date().toISOString();
          if (params[2]) {
            request.rejection_reason = params[2];
          }
        }
      }
      return { changes: request ? 1 : 0 };
    }

    // --- SCA ---
    if (sql.includes('UPDATE sca_student_reviews')) {
      if (!db.sca_student_reviews) db.sca_student_reviews = [];
      const reviewId = params[params.length - 1];
      const review = db.sca_student_reviews.find(r => r.id === reviewId);
      if (review) {
        if (sql.includes('classification')) review.classification = params[0];
        if (sql.includes('student_notes')) review.student_notes = params[1] !== undefined ? params[1] : review.student_notes;
        if (sql.includes('remediation_notes')) review.remediation_notes = params[2] !== undefined ? params[2] : review.remediation_notes;
        if (sql.includes('status')) review.status = params[3] !== undefined ? params[3] : review.status;
        if (sql.includes('submitted_at')) review.submitted_at = params[4] !== undefined ? params[4] : review.submitted_at;
        review.updated_at = new Date().toISOString();
      }
      return { changes: review ? 1 : 0 };
    }

    // --- DAST ---
    if (sql.includes('UPDATE dast_student_findings')) {
      if (!db.dast_student_findings) db.dast_student_findings = [];
      const findingId = params[params.length - 1];
      const finding = db.dast_student_findings.find(f => f.id === findingId);
      if (finding) {
        if (sql.includes('instructor_feedback')) {
          finding.instructor_feedback = params[0];
          finding.grade = params[1];
        } else {
          if (params[0] !== undefined) finding.triggered = params[0];
          if (params[1] !== undefined) finding.trigger_evidence = params[1];
          if (params[2] !== undefined) finding.impact_assessment = params[2];
          if (params[3] !== undefined) finding.reproduction_steps = params[3];
          if (params[4] !== undefined) finding.recommendation = params[4];
          if (params[5] !== undefined) finding.severity_rating = params[5];
          if (params[6] !== undefined) finding.submitted_at = params[6];
        }
        finding.updated_at = new Date().toISOString();
      }
      return { changes: finding ? 1 : 0 };
    }

    // --- VM ---
    if (sql.includes('UPDATE vulnerabilities')) {
      if (!db.vulnerabilities) db.vulnerabilities = [];
      const vulnId = params[params.length - 1];
      const vuln = db.vulnerabilities.find(v => v.id === parseInt(vulnId));
      if (vuln) {
        if (sql.includes('status')) {
          vuln.status = params[0];
          if (params[0] === 'resolved') {
            vuln.resolved_at = new Date().toISOString();
            vuln.resolved_by = params[1] || null;
            vuln.resolution_notes = params[2] || null;
          }
        }
        if (sql.includes('title')) vuln.title = params[0];
        if (sql.includes('description') && !sql.includes('status')) vuln.description = params[0];
        if (sql.includes('severity') && !sql.includes('status')) vuln.severity = sql.includes('title') ? params[4] : params[0];
        if (sql.includes('assigned_to')) vuln.assigned_to = sql.includes('title') ? params[5] : params[0];
        if (sql.includes('priority')) vuln.priority = sql.includes('title') ? params[6] : params[0];
        if (sql.includes('remediation_plan')) vuln.remediation_plan = sql.includes('title') ? params[7] : params[0];
        if (sql.includes('remediation_deadline')) vuln.remediation_deadline = sql.includes('title') ? params[8] : params[0];
        vuln.updated_at = new Date().toISOString();
      }
      return { changes: vuln ? 1 : 0 };
    }

    // --- Pentest ---
    if (sql.includes('UPDATE pentest_engagements')) {
      if (!db.pentest_engagements) db.pentest_engagements = [];
      const engId = params[params.length - 1];
      const eng = db.pentest_engagements.find(e => e.id === parseInt(engId));
      if (eng) {
        if (sql.includes('phase_current')) eng.phase_current = params[0];
        if (sql.includes('status') && !sql.includes('phase_current')) eng.status = params[0];
        if (sql.includes('submitted_at')) eng.submitted_at = params[0] || new Date().toISOString();
        if (sql.includes('instructor_grade')) {
          eng.instructor_grade = params[0];
          eng.instructor_feedback = params[1];
          eng.status = 'graded';
        }
        eng.updated_at = new Date().toISOString();
      }
      return { changes: eng ? 1 : 0 };
    }

    if (sql.includes('UPDATE pentest_findings')) {
      if (!db.pentest_findings) db.pentest_findings = [];
      const findId = params[params.length - 1];
      const find = db.pentest_findings.find(f => f.id === parseInt(findId));
      if (find) {
        if (params[0] !== undefined) find.title = params[0];
        if (params[1] !== undefined) find.severity = params[1];
        if (params[2] !== undefined) find.cvss_score = params[2];
        if (params[3] !== undefined) find.description = params[3];
        if (params[4] !== undefined) find.affected_url = params[4];
        if (params[5] !== undefined) find.evidence = params[5];
        if (params[6] !== undefined) find.recommendation = params[6];
        find.updated_at = new Date().toISOString();
      }
      return { changes: find ? 1 : 0 };
    }

    if (sql.includes('UPDATE pentest_phase_notes')) {
      if (!db.pentest_phase_notes) db.pentest_phase_notes = [];
      // WHERE engagement_id = ? AND phase = ? → params are [...fields, engId, phase]
      const phase = params[params.length - 1];
      const engId = params[params.length - 2];
      const note = db.pentest_phase_notes.find(n => n.engagement_id === parseInt(engId) && n.phase === phase);
      if (note) {
        note.notes = params[0];
        note.tools_used = params[1] || note.tools_used;
        note.updated_at = new Date().toISOString();
      }
      return { changes: note ? 1 : 0 };
    }
  }

  // DELETE queries
  if (sql.startsWith('DELETE FROM')) {
    if (sql.includes('FROM users')) {
      db.users = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM classes')) {
      if (sql.includes('WHERE id')) {
        const classId = params[0];
        const before = db.classes.length;
        db.classes = db.classes.filter(c => c.id !== classId);
        db.sessions = db.sessions.filter(s => s.class_id !== classId);
        db.enrollments = db.enrollments.filter(e => e.class_id !== classId);
        return { changes: before - db.classes.length };
      }
      db.classes = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM sessions')) {
      if (sql.includes('WHERE class_id')) {
        const classId = params[0];
        const before = db.sessions.length;
        db.sessions = db.sessions.filter(s => s.class_id !== classId);
        return { changes: before - db.sessions.length };
      }
      db.sessions = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM enrollments')) {
      if (sql.includes('WHERE class_id')) {
        const classId = params[0];
        const before = db.enrollments.length;
        db.enrollments = db.enrollments.filter(e => e.class_id !== classId);
        return { changes: before - db.enrollments.length };
      }
      db.enrollments = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM audit_logs')) {
      db.audit_logs = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM rate_limit_attempts')) {
      if (sql.includes('WHERE')) {
        const before = db.rate_limit_attempts.length;
        const since = params[0];
        db.rate_limit_attempts = db.rate_limit_attempts.filter(a => a.attempt_time >= since);
        return { changes: before - db.rate_limit_attempts.length };
      }
      db.rate_limit_attempts = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM deletion_requests')) {
      if (sql.includes('WHERE id')) {
        const requestId = params[0];
        const before = db.deletion_requests.length;
        db.deletion_requests = db.deletion_requests.filter(dr => dr.id !== requestId);
        return { changes: before - db.deletion_requests.length };
      }
      db.deletion_requests = [];
      return { changes: 1 };
    }

    // --- VM ---
    if (sql.includes('FROM vulnerabilities')) {
      if (sql.includes('WHERE id')) {
        if (!db.vulnerabilities) db.vulnerabilities = [];
        const vulnId = parseInt(params[0]);
        const before = db.vulnerabilities.length;
        db.vulnerabilities = db.vulnerabilities.filter(v => v.id !== vulnId);
        return { changes: before - db.vulnerabilities.length };
      }
      db.vulnerabilities = [];
      return { changes: 1 };
    }

    // --- Pentest ---
    if (sql.includes('FROM pentest_findings')) {
      if (sql.includes('WHERE id')) {
        if (!db.pentest_findings) db.pentest_findings = [];
        const findId = parseInt(params[0]);
        const before = db.pentest_findings.length;
        db.pentest_findings = db.pentest_findings.filter(f => f.id !== findId);
        return { changes: before - db.pentest_findings.length };
      }
    }
  }

  return null;
}

// Load database on startup
loadDatabase();

// Initialize database schema
function initializeDatabase() {
  if (!db.security_settings || db.security_settings.length === 0) {
    db.security_settings = [{
      id: 1,
      mfa_enabled: 0,
      rbac_enabled: 1,
      encryption_at_rest: 0,
      field_encryption: 0,
      https_enabled: 0,
      audit_logging: 0,
      rate_limiting: 0,
      updated_at: new Date().toISOString()
    }];
  }
  // Ensure new curriculum collections exist
  const newCollections = [
    'sca_findings', 'sca_student_reviews',
    'dast_scenarios', 'dast_student_findings',
    'vulnerabilities', 'vm_status_history', 'vm_comments',
    'pentest_engagements', 'pentest_findings', 'pentest_phase_notes'
  ];
  newCollections.forEach(col => {
    if (!db[col]) db[col] = [];
  });
  // Ensure new counter keys exist
  const newCounters = [
    'sca_student_reviews', 'dast_student_findings',
    'vulnerabilities', 'vm_status_history', 'vm_comments',
    'pentest_engagements', 'pentest_findings', 'pentest_phase_notes'
  ];
  newCounters.forEach(key => {
    if (!db._counters[key]) db._counters[key] = 0;
  });
  saveDatabase();
  console.log('Database initialized successfully');
}

// Check if database has been seeded
function isDatabaseSeeded() {
  return db.users.length > 0;
}

module.exports = {
  db: dbInterface,
  initializeDatabase,
  isDatabaseSeeded,
  loadDatabase
};
