# Codebase Structure

**Analysis Date:** 2026-03-12

## Directory Layout

```
university-class-management/
├── config/                    # Configuration and database abstraction
│   ├── database.js            # JSON-based SQL-like database emulation
│   ├── security.js            # Security settings management
│   └── translations/          # Language files for i18n
├── middleware/                 # Express middleware for cross-cutting concerns
│   ├── auth.js                # Authentication checks (session-based)
│   ├── rbac.js                # Role-based access control enforcement
│   ├── audit.js               # Audit logging middleware
│   └── rateLimiter.js         # Login attempt rate limiting
├── routes/                    # Express route handlers by feature domain
│   ├── auth.js                # Login, logout, MFA verification
│   ├── dashboard.js           # Role-based dashboard routing
│   ├── classes.js             # Class enrollment and management
│   ├── sessions.js            # Session management
│   ├── admin.js               # Admin panel (security, backups, encryption keys)
│   ├── sca.js                 # Static code analysis lab
│   ├── dast.js                # Dynamic application security testing lab
│   ├── vm.js                  # Vulnerability manager registry
│   └── pentest.js             # Penetration testing engagement lab
├── views/                     # EJS templates organized by role/feature
│   ├── login.ejs              # Login form
│   ├── error.ejs              # Error page
│   ├── class-details.ejs      # Class details view
│   ├── classes/               # Class management templates
│   │   └── delete-request.ejs
│   ├── student/               # Student-only views
│   │   └── dashboard.ejs
│   ├── professor/             # Professor-only views
│   │   └── dashboard.ejs
│   ├── admin/                 # Admin-only views
│   │   ├── dashboard.ejs
│   │   ├── security-panel.ejs
│   │   ├── mfa-setup.ejs
│   │   ├── byok.ejs
│   │   ├── backups.ejs
│   │   ├── audit-logs.ejs
│   │   └── deletion-requests.ejs
│   ├── sca/                   # SCA lab templates
│   │   ├── student-lab.ejs
│   │   ├── instructor.ejs
│   │   ├── student-detail.ejs
│   │   └── finding-detail.ejs
│   ├── dast/                  # DAST lab templates
│   │   └── (student-lab, instructor, scenario-detail)
│   ├── pentest/               # Pentest lab templates
│   │   ├── student-lab.ejs
│   │   ├── instructor.ejs
│   │   ├── engagement-detail.ejs
│   │   └── report-builder.ejs
│   ├── vm/                    # Vulnerability manager views
│   │   └── (student-lab, instructor)
│   └── partials/              # Shared template components
├── utils/                     # Reusable business logic
│   ├── passwordHash.js        # bcrypt password hashing
│   ├── encryption.js          # AES-256-CBC encryption (field and at-rest)
│   ├── i18n.js                # Internationalization helper
│   ├── seedData.js            # Database seeding with sample data
│   └── backupManager.js       # Backup creation, listing, restore
├── scripts/                   # CLI scripts
│   ├── classroom-manager.js   # Multi-instance orchestrator (npm start entry)
│   ├── classroom-stop.js      # Stop all running instances
│   ├── setup.js               # One-time database initialization
│   └── smoke-test.js          # Health check for running instances
├── public/                    # Static assets served to browser
│   └── images/
│       ├── hec-logo.svg
│       └── hec-logo-white.svg
├── database/                  # Data storage (created at runtime, gitignored)
│   └── data.json              # Main database file (JSON)
├── backups/                   # Automated backups (created at runtime, gitignored)
│   └── backup-*.json          # Timestamped backups
├── instances/                 # Classroom mode (created at runtime)
│   └── .pids.json             # Running process IDs
├── keys/                      # Encryption keys (created at runtime, gitignored)
│   └── custom-key.txt         # Custom encryption key if BYOK enabled
├── ssl/                       # SSL certificates (created at runtime)
│   ├── server-key.pem         # Private key
│   └── server-cert.pem        # Certificate
├── .devcontainer/             # GitHub Codespaces configuration
│   └── devcontainer.json      # Dev environment setup
├── .planning/                 # Planning and analysis documents
│   └── codebase/              # Architecture/structure analysis
├── server.js                  # Main Express application entry point
├── classroom.config.json      # Classroom orchestration configuration
├── package.json               # Node.js dependencies and scripts
├── README.md                  # Project overview
└── SOLUTION-GUIDE.md          # Module solutions reference
```

## Directory Purposes

**config/**
- Purpose: Centralized configuration and data layer
- Contains: Database abstraction, security settings CRUD, language translation files
- Key files: `config/database.js` (SQL-like JSON DB), `config/security.js` (toggle management)
- Access pattern: Imported by `server.js` and all route modules via `require('../config/database')`

**middleware/**
- Purpose: Reusable request processing logic (cross-cutting concerns)
- Contains: Authentication checks, authorization (RBAC), audit logging, rate limiting
- Key files: `middleware/auth.js` (requireAuth), `middleware/rbac.js` (requireRole), `middleware/audit.js` (auditLog), `middleware/rateLimiter.js` (checkRateLimit)
- Access pattern: Attached to routes as middleware functions, e.g. `router.get('/security', requireAuth, requireRole(['admin']), handler)`

**routes/**
- Purpose: HTTP request handlers organized by feature domain
- Contains: Route handlers for 9 feature areas totaling ~2471 lines of code
- Key files: `routes/admin.js` (security panel + toggles), `routes/auth.js` (login/MFA), `routes/vm.js` (vulnerability lifecycle), `routes/sca.js` (code analysis lab)
- Access pattern: Imported and mounted in `server.js` at specific URL prefixes:
  - `app.use('/auth', authRoutes)` - `routes/auth.js`
  - `app.use('/dashboard', dashboardRoutes)` - `routes/dashboard.js`
  - `app.use('/classes', classRoutes)` - `routes/classes.js`
  - `app.use('/sessions', sessionRoutes)` - `routes/sessions.js`
  - `app.use('/admin', adminRoutes)` - `routes/admin.js`
  - `app.use('/sca', scaRoutes)` - `routes/sca.js`
  - `app.use('/dast', dastRoutes)` - `routes/dast.js`
  - `app.use('/vm', vmRoutes)` - `routes/vm.js`
  - `app.use('/pentest', pentestRoutes)` - `routes/pentest.js`

**views/**
- Purpose: Server-side rendered HTML templates (EJS)
- Contains: Login form, role-specific dashboards, feature-specific labs
- Key files: Organized in subdirectories by role (`student/`, `professor/`, `admin/`) and feature (`sca/`, `dast/`, `vm/`, `pentest/`)
- Access pattern: Rendered by route handlers via `res.render('path/to/template', data)`

**utils/**
- Purpose: Reusable business logic and helpers
- Contains: Password hashing, encryption, i18n, data seeding, backups
- Key files: `utils/encryption.js` (field + at-rest encryption), `utils/passwordHash.js` (bcrypt), `utils/backupManager.js` (backup/restore), `utils/seedData.js` (sample data)
- Access pattern: Imported by routes and middleware via `require('../utils/...')`

**scripts/**
- Purpose: CLI tools for setup, orchestration, testing
- Contains: Classroom manager (multi-instance), setup script, stop script, health check
- Key files: `scripts/classroom-manager.js` (main npm start entry point), `scripts/setup.js` (initialization)
- Access pattern: Invoked via npm scripts defined in `package.json`

**public/**
- Purpose: Static assets served directly to client browsers
- Contains: Logo images (SVG)
- Access pattern: Served by `express.static()` middleware, available at root URL path (e.g., `/images/hec-logo.svg`)

## Key File Locations

**Entry Points:**
- `server.js`: Main Express app (http/https server, middleware setup, route mounting)
- `scripts/classroom-manager.js`: Multi-team orchestrator (spawns N server.js instances, serves instructor dashboard on port 3000)

**Configuration:**
- `classroom.config.json`: Classroom setup (teams array, ports, auto-reset behavior)
- `config/database.js`: Database emulation with SQL-like interface and recovery logic
- `config/security.js`: Security settings CRUD with VALID_SETTINGS whitelist
- `.devcontainer/devcontainer.json`: GitHub Codespaces dev environment config

**Core Logic:**
- `routes/auth.js`: Login, logout, MFA verification (POST /auth/login, GET /auth/mfa-verify)
- `routes/admin.js`: Security settings panel and toggles (POST /admin/security/toggle/:feature)
- `routes/vm.js`: Vulnerability lifecycle management with state machine (VALID_TRANSITIONS)
- `routes/sca.js`: SCA student lab and instructor review matrix with VM import
- `routes/dast.js`: DAST scenario management and student findings
- `routes/pentest.js`: Pentesting engagement workflow with phased progression

**Security:**
- `middleware/rbac.js`: Role enforcement via `requireRole()` factory
- `middleware/auth.js`: Session check via `requireAuth` and `redirectIfAuthenticated`
- `middleware/audit.js`: Action logging via `auditLog()` factory and `logAuthAttempt()` function
- `middleware/rateLimiter.js`: Login attempt limiting via `checkRateLimit` and `recordLoginAttempt`
- `utils/encryption.js`: AES-256-CBC cipher with BYOK support
- `utils/passwordHash.js`: bcrypt hashing with 10 salt rounds

**Testing:**
- `scripts/smoke-test.js`: HTTP health check against all team instance endpoints

## Naming Conventions

**Files:**
- Route modules: camelCase `.js` (e.g., `auth.js`, `dashboard.js`, `rateLimiter.js`)
- Utility modules: camelCase `.js` (e.g., `passwordHash.js`, `backupManager.js`, `seedData.js`)
- Template files: kebab-case `.ejs` (e.g., `security-panel.ejs`, `student-lab.ejs`, `finding-detail.ejs`)
- Config files: kebab-case `.json` or `.js` (e.g., `classroom.config.json`, `database.js`)

**Directories:**
- Feature subdirectories in views: lowercase singular or plural matching the route prefix (e.g., `views/sca/`, `views/dast/`, `views/vm/`, `views/pentest/`, `views/student/`, `views/professor/`, `views/admin/`)
- Infrastructure directories: lowercase plural (e.g., `routes/`, `utils/`, `middleware/`, `config/`, `scripts/`)

**Database Collections:**
- Table names: snake_case (e.g., `sca_findings`, `sca_student_reviews`, `vm_status_history`, `pentest_engagements`, `audit_logs`)
- Column names: snake_case (e.g., `finding_id`, `student_id`, `phase_current`, `created_at`, `updated_at`)

**Functions and Variables:**
- Functions: camelCase verbs (e.g., `requireAuth()`, `requireRole()`, `auditLog()`, `importToVM()`, `hashPassword()`)
- Middleware factories: camelCase returning function (e.g., `requireRole(['admin'])` returns `(req, res, next) => ...`)
- Constants: UPPER_SNAKE_CASE (e.g., `VALID_TRANSITIONS`, `SALT_ROUNDS`, `ALGORITHM`, `REQUIRED_KEYS`)

**Route Paths:**
- kebab-case for multi-word paths (e.g., `/auth/mfa-verify`, `/admin/security`, `/api/instructor-message`)
- Plural resource names (e.g., `/classes`, `/sessions`)
- Parameterized routes use `:id` or `:feature` (e.g., `/admin/security/toggle/:feature`, `/vm/:id`)

## Where to Add New Code

**New Security Lab (e.g., a new assessment module):**
- Route handler: Create `routes/[feature].js` following the pattern in `routes/sca.js`
- Views: Create `views/[feature]/` directory with `student-lab.ejs` and `instructor.ejs`
- Mount in `server.js`: Add `const { router: featureRoutes } = require('./routes/[feature]')` and `app.use('/[feature]', featureRoutes)`
- Database collections: Add new arrays to the `db` object in `config/database.js` and corresponding `executeSQL` handlers

**New Admin Setting (e.g., new security toggle):**
- Add setting name to `VALID_SETTINGS` whitelist in `config/security.js`
- Add default value to `security_settings` array in `config/database.js` initial structure
- Add migration logic (if needed) in `routes/admin.js` POST `/security/toggle/:feature`
- Add UI toggle control in `views/admin/security-panel.ejs`
- Reference in request handlers via `req.securitySettings.[setting_name]`

**New Middleware:**
- Create file in `middleware/[name].js`
- Export function (simple middleware) or factory function (parameterized middleware)
- Import and attach in `server.js` via `app.use()` for global middleware, or in specific route files for route-level middleware
- Follow pattern from `middleware/rbac.js` (factory) or `middleware/auth.js` (simple function)

**Database Schema Changes:**
- Edit in-memory structure in `config/database.js` under `let db = { ... }`
- Add new collection as empty array and add counter entry to `_counters`
- Update `REQUIRED_KEYS` constant if the new table is required for valid database
- Add `executeSQL()` handler block for new table queries (SELECT, INSERT, UPDATE, DELETE)
- Update `utils/seedData.js` to populate initial sample data for new collections

**New View Template:**
- Create in `views/[feature]/[template-name].ejs` following existing naming pattern
- Include shared partials via `<%- include('../partials/[name]') %>`
- Render from route handler via `res.render('[feature]/[template-name]', { data })`
- Access `user`, `currentPath`, `formatDate`, and `t` (translation function) from `res.locals`

**New Utility Function:**
- Create in `utils/[name].js` or add to existing utility module
- Export via `module.exports = { functionName }`
- Import in routes or middleware via `const { functionName } = require('../utils/[name]')`

## Special Directories

**database/**
- Purpose: Persistent JSON database storage
- Generated: First run of `server.js` via `initializeDatabase()` in `config/database.js`
- Committed: No (gitignored) - each environment has its own `data.json`
- Files: `data.json` (main), `data.json.tmp` (atomic write temp file)

**backups/**
- Purpose: Automatic and manual database backups
- Generated: On server startup (if backup_enabled) and via admin UI in `routes/admin.js`
- Committed: No (gitignored)
- Files: `backup-YYYY-MM-DD-HH-mm-ss.json` (timestamped snapshots)
- Cleanup: Automatic via `cleanupOldBackups()` in `utils/backupManager.js`

**instances/**
- Purpose: Process ID tracking for classroom mode (multi-team orchestration)
- Generated: By `scripts/classroom-manager.js` on startup
- Committed: No
- Files: `.pids.json` (JSON array of child process PIDs for graceful shutdown)

**keys/**
- Purpose: Custom encryption key storage (Bring Your Own Key feature)
- Generated: Created by admin via BYOK UI (`routes/admin.js` and `views/admin/byok.ejs`)
- Committed: No (gitignored) - never commit encryption keys
- Files: `custom-key.txt` (base64-encoded or raw key, normalized to 32 bytes by `utils/encryption.js`)

**ssl/**
- Purpose: Self-signed HTTPS certificates for HTTPS mode
- Generated: Via setup script or selfsigned package
- Committed: No (certificates are secrets)
- Files: `server-key.pem` (private key), `server-cert.pem` (certificate)

**config/translations/**
- Purpose: Language files for internationalization
- Generated: No (manually authored)
- Committed: Yes
- Used by: `utils/i18n.js` language middleware

---

*Structure analysis: 2026-03-12*
