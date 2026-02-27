const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');

// Initialize database
const { db, initializeDatabase, isDatabaseSeeded } = require('./config/database');
const { seedDatabase } = require('./utils/seedData');
const { loadSecuritySettings, getSecuritySettings } = require('./config/security');
const { languageMiddleware } = require('./utils/i18n');
const { initializeBackupSystem } = require('./utils/backupManager');

// Initialize app
const app = express();

// Auto-initialize database on first run
console.log('Initializing database...');
initializeDatabase();

if (!isDatabaseSeeded()) {
  console.log('Database is empty. Seeding with sample data...');
  seedDatabase();
}

// Initialize backup system
console.log('Initializing backup system...');
initializeBackupSystem();

// View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration — set secure cookie at startup if HTTPS is enabled
const startupSecuritySettings = getSecuritySettings();
app.use(session({
  secret: 'university-class-management-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    secure: !!startupSecuritySettings.https_enabled
  }
}));

// Load security settings into all requests
app.use(loadSecuritySettings);

// Load language preferences and translation function
app.use(languageMiddleware);

// Make user, current path, and helpers available in all views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.currentPath = req.path;
  res.locals.formatDate = (dateStr) => {
    if (!dateStr) return 'Never';
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? 'Invalid date' : d.toLocaleString();
  };
  next();
});

// Routes
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const classRoutes = require('./routes/classes');
const sessionRoutes = require('./routes/sessions');
const adminRoutes = require('./routes/admin');
const { router: scaRoutes } = require('./routes/sca');
const { router: dastRoutes } = require('./routes/dast');
const { router: vmRoutes } = require('./routes/vm');
const { router: pentestRoutes } = require('./routes/pentest');

app.use('/auth', authRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/classes', classRoutes);
app.use('/sessions', sessionRoutes);
app.use('/admin', adminRoutes);
app.use('/sca', scaRoutes);
app.use('/dast', dastRoutes);
app.use('/vm', vmRoutes);
app.use('/pentest', pentestRoutes);

// Health check endpoint (used by classroom manager)
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    team: process.env.TEAM_NAME || 'default',
    port: process.env.PORT || 3000,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// CLASSROOM INTERNAL ENDPOINTS
// NOTE: No authentication — accessible only on the isolated classroom network
//       (localhost ports 3001-3012). Do not expose these ports publicly.
// ─────────────────────────────────────────────────────────────────────────────

// In-memory broadcast message store (ephemeral; resets on restart)
let _instructorMessage = null;

// GET /api/instructor-message — student browsers poll this for instructor toasts
app.get('/api/instructor-message', (req, res) => {
  res.json({ message: _instructorMessage });
});

// POST /api/instructor-message — called by classroom-manager broadcast fan-out
app.post('/api/instructor-message', (req, res) => {
  _instructorMessage = req.body.message || null;
  res.json({ success: true });
});

// GET /api/summary — full classroom-visible snapshot of this instance
app.get('/api/summary', (req, res) => {
  try {
    // Security config
    const settings = db.prepare('SELECT * FROM security_settings').get();
    const security = {
      mfa_enabled:         !!(settings && settings.mfa_enabled),
      rbac_enabled:        !!(settings && settings.rbac_enabled),
      encryption_at_rest:  !!(settings && settings.encryption_at_rest),
      field_encryption:    !!(settings && settings.field_encryption),
      https_enabled:       !!(settings && settings.https_enabled),
      audit_logging:       !!(settings && settings.audit_logging),
      rate_limiting:       !!(settings && settings.rate_limiting)
    };

    // User counts
    const allUsers   = db.prepare('SELECT * FROM users').all();
    const students   = (allUsers || []).filter(u => u.role === 'student');
    const professors = (allUsers || []).filter(u => u.role === 'professor');
    const users = {
      total:      (allUsers || []).length,
      students:   students.length,
      professors: professors.length
    };

    // VM stats
    const vulns = db.prepare('SELECT * FROM vulnerabilities').all() || [];
    const vm = {
      total:       vulns.length,
      open:        vulns.filter(v => v.status === 'open').length,
      in_progress: vulns.filter(v => v.status === 'in_progress').length,
      resolved:    vulns.filter(v => v.status === 'resolved').length,
      wont_fix:    vulns.filter(v => v.status === 'wont_fix').length,
      critical:    vulns.filter(v => v.severity === 'Critical').length,
      high:        vulns.filter(v => v.severity === 'High').length,
      medium:      vulns.filter(v => v.severity === 'Medium').length,
      low:         vulns.filter(v => v.severity === 'Low').length
    };

    // SCA progress
    const scaFindings = db.prepare('SELECT * FROM sca_findings').all() || [];
    const scaReviews  = db.prepare('SELECT * FROM sca_student_reviews').all() || [];
    const scaTotal    = scaFindings.length;
    const scaPerStudent = students.map(s => ({
      username:        s.username,
      submitted_count: scaReviews.filter(r => r.student_id === s.id && r.status === 'submitted').length
    }));
    const scaAvgPct = scaTotal === 0 || students.length === 0 ? 0 : Math.round(
      scaPerStudent.reduce((a, s) => a + s.submitted_count, 0) / (students.length * scaTotal) * 100
    );
    const sca = { total_findings: scaTotal, avg_completion_pct: scaAvgPct, per_student: scaPerStudent };

    // DAST progress
    const dastScenarios = db.prepare('SELECT * FROM dast_scenarios').all() || [];
    const dastFindings  = db.prepare('SELECT * FROM dast_student_findings').all() || [];
    const dastTotal     = dastScenarios.length;
    const dastPerStudent = students.map(s => {
      const mine = dastFindings.filter(f => f.student_id === s.id);
      return {
        username:  s.username,
        submitted: mine.filter(f => f.submitted_at !== null).length,
        triggered: mine.filter(f => f.triggered === 1).length
      };
    });
    const dastAvgPct = dastTotal === 0 || students.length === 0 ? 0 : Math.round(
      dastPerStudent.reduce((a, s) => a + s.submitted, 0) / (students.length * dastTotal) * 100
    );
    const dast = { total_scenarios: dastTotal, avg_completion_pct: dastAvgPct, per_student: dastPerStudent };

    // Pentest progress
    const engagements = db.prepare('SELECT * FROM pentest_engagements').all() || [];
    const PHASES = ['recon', 'enumeration', 'vuln_id', 'exploitation', 'reporting'];
    const phaseDist = {};
    PHASES.forEach(p => { phaseDist[p] = 0; });
    engagements.forEach(e => { if (phaseDist[e.phase_current] !== undefined) phaseDist[e.phase_current]++; });
    const pentest = {
      total_students: students.length,
      in_progress:    engagements.filter(e => e.status === 'in_progress').length,
      submitted:      engagements.filter(e => e.status === 'submitted').length,
      graded:         engagements.filter(e => e.status === 'graded').length,
      phase_distribution: phaseDist
    };

    res.json({
      team:      process.env.TEAM_NAME || 'default',
      port:      process.env.PORT || 3000,
      uptime:    process.uptime(),
      security,
      users,
      vm,
      sca,
      dast,
      pentest,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('[/api/summary] Error:', err);
    res.status(500).json({ error: 'Summary unavailable', detail: err.message });
  }
});

// Home page route
app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500);
  res.render('error', {
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', {
    message: 'Page not found',
    error: { status: 404 }
  });
});

// Port configuration
const HTTP_PORT = process.env.PORT || 3000;
const HTTPS_PORT = 3443;

/**
 * Start server based on security settings
 */
function startServer() {
  const securitySettings = getSecuritySettings();

  if (securitySettings.https_enabled) {
    // Start HTTPS server
    const sslDir = process.env.SSL_DIR || path.join(__dirname, 'ssl');
    const sslOptions = {
      key: fs.readFileSync(path.join(sslDir, 'server-key.pem')),
      cert: fs.readFileSync(path.join(sslDir, 'server-cert.pem'))
    };

    https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
      console.log('');
      console.log('='.repeat(60));
      console.log('🔒 University Class Management System');
      console.log('='.repeat(60));
      console.log('');
      console.log(`HTTPS Server running on: https://localhost:${HTTPS_PORT}`);
      console.log('');
      console.log('Security Status:');
      console.log('  ✓ HTTPS: ENABLED');
      console.log('  ✓ Secure cookies: ENABLED');
      console.log('');
      console.log('Default login:');
      console.log('  Admin:     admin / admin123');
      console.log('  Professor: prof_jones / prof123');
      console.log('  Student:   alice_student / student123');
      console.log('');
      console.log('='.repeat(60));
      console.log('');
    });

    // Also start HTTP server to redirect to HTTPS
    http.createServer((req, res) => {
      res.writeHead(301, {
        Location: `https://${req.headers.host.replace(HTTP_PORT, HTTPS_PORT)}${req.url}`
      });
      res.end();
    }).listen(HTTP_PORT, () => {
      console.log(`HTTP redirect server running on: http://localhost:${HTTP_PORT}`);
      console.log(`(All HTTP requests will be redirected to HTTPS)`);
      console.log('');
    });

  } else {
    // Start HTTP server only
    http.createServer(app).listen(HTTP_PORT, () => {
      console.log('');
      console.log('='.repeat(60));
      console.log('🎓 University Class Management System');
      console.log('='.repeat(60));
      console.log('');
      console.log(`HTTP Server running on: http://localhost:${HTTP_PORT}`);
      console.log('');
      console.log('⚠️  Security Status:');
      console.log('  ✗ HTTPS: DISABLED (running on HTTP)');
      console.log('');
      console.log('Default login:');
      console.log('  Admin:     admin / admin123');
      console.log('  Professor: prof_jones / prof123');
      console.log('  Student:   alice_student / student123');
      console.log('');
      console.log('💡 Tip: Login as admin to toggle security features');
      console.log('');
      console.log('='.repeat(60));
      console.log('');
    });
  }
}

// Start the server
startServer();

module.exports = app;
