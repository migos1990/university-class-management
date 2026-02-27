const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');

// Initialize database
const { initializeDatabase, isDatabaseSeeded } = require('./config/database');
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

// Session configuration
app.use(session({
  secret: 'university-class-management-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    secure: false // Will be set to true when HTTPS is enabled
  }
}));

// Load security settings into all requests
app.use(loadSecuritySettings);

// Load language preferences and translation function
app.use(languageMiddleware);

// Make user and current path available in all views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.currentPath = req.path;
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

    // Update session cookie to be secure
    app.use((req, res, next) => {
      req.sessionOptions.cookie.secure = true;
      next();
    });

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
