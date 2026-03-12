# Architecture

**Analysis Date:** 2026-03-12

## Pattern Overview

**Overall:** MVC (Model-View-Controller) with security demonstration layer

**Key Characteristics:**
- **Server-side rendering** - EJS templates for all UI
- **Role-based access control (RBAC)** - Three roles: student, professor, admin
- **Modular routing** - Feature domains (auth, classes, SCA, DAST, VM, pentest)
- **Middleware-driven security** - Authentication, RBAC, audit logging, rate limiting
- **JSON-based persistence** - File-based database simulation (not SQLite despite SQL-like interface)
- **Security capability toggles** - Nine configurable security features for educational demonstration

## Layers

**Presentation Layer:**
- Purpose: Render role-specific views and handle HTTP responses
- Location: `views/` directory with EJS templates
- Contains: Login, dashboard, feature-specific labs (SCA, DAST, Pentest, VM)
- Depends on: Session data (user/securitySettings in res.locals), route handlers
- Used by: Express.js route handlers

**Route Layer:**
- Purpose: Handle HTTP requests, orchestrate business logic, call database
- Location: `routes/*.js` (auth.js, dashboard.js, classes.js, sca.js, dast.js, vm.js, pentest.js, admin.js, sessions.js)
- Contains: Express route handlers, request validation, response formatting
- Depends on: Database, middleware, utilities
- Used by: Express app mounted in `server.js`

**Middleware Layer:**
- Purpose: Cross-cutting concerns (authentication, authorization, logging, rate limiting)
- Location: `middleware/` directory
- Contains:
  - `middleware/auth.js` - Session-based authentication check
  - `middleware/rbac.js` - Role-based access control enforcement
  - `middleware/audit.js` - Audit logging for security events
  - `middleware/rateLimiter.js` - Login attempt rate limiting
- Depends on: Database, security settings, session
- Used by: Route handlers via Express routing

**Configuration Layer:**
- Purpose: Centralized security settings and database initialization
- Location: `config/` directory
- Contains:
  - `config/database.js` - JSON-based database emulation with SQL-like interface
  - `config/security.js` - Security settings CRUD (MFA, RBAC, encryption, audit, etc.)
- Depends on: File system (database.json, backups/)
- Used by: Server initialization, route handlers, middleware

**Utilities Layer:**
- Purpose: Reusable business logic and helpers
- Location: `utils/` directory
- Contains:
  - `utils/passwordHash.js` - bcrypt password hashing and comparison
  - `utils/encryption.js` - AES-256-CBC field-level and at-rest encryption
  - `utils/i18n.js` - Internationalization/language middleware
  - `utils/seedData.js` - Sample data generator for initial setup
  - `utils/backupManager.js` - Database backup and restore functionality
- Depends on: Crypto, bcrypt, file system
- Used by: Routes, middleware, server initialization

## Data Flow

**Authentication Flow:**

1. User submits login form to `POST /auth/login`
2. Rate limit check (`middleware/rateLimiter.js`) runs if rate_limiting enabled
3. Query database for user by username via `db.prepare('SELECT * FROM users WHERE username = ?')`
4. Compare plaintext or bcrypt hash (depending on encryption_at_rest setting) via `utils/passwordHash.js`
5. If user is admin and MFA enabled, redirect to `GET /auth/mfa-verify`
6. If successful, create session object in `req.session.user` (stores id, username, email, role)
7. Session cookie set with secure flag based on https_enabled setting
8. Redirect to `/dashboard`, which routes by role in `routes/dashboard.js`

**Authorization Flow (RBAC):**

1. Route handler calls `requireRole(['admin'])` or similar middleware from `middleware/rbac.js`
2. Middleware checks `req.securitySettings.rbac_enabled` flag
3. If disabled, set `req.rbacBypass = true` and proceed (demonstrating vulnerability)
4. If enabled and user role in allowed list, proceed
5. If denied, log to audit_logs (if enabled) with RBAC_DENIED action and return 403

**Security Setting Toggle Flow:**

1. Admin visits `GET /admin/security` (protected by `requireRole(['admin'])`)
2. Admin clicks toggle for feature (e.g., "Enable MFA")
3. POST to `/admin/security/toggle/:feature` in `routes/admin.js`
4. Specific migration logic executed (e.g., hash all passwords if encryption_at_rest enabled)
5. `updateSecuritySetting(feature, newValue)` in `config/security.js` updates database
6. Audit log created if audit_logging enabled
7. If HTTPS toggle, message to admin that server restart required
8. All subsequent requests see new setting via `loadSecuritySettings` middleware

**Security Assessment Submission Flow (SCA example):**

1. Student visits `GET /sca` in `routes/sca.js`
2. Renders all code findings for classification via `views/sca/student-lab.ejs`
3. Student classifies finding severity, POST to route with review data
4. Route validates student_id matches session and inserts/updates sca_student_reviews
5. Instructor visits same `GET /sca` endpoint
6. Renders heatmap of student responses per finding via `views/sca/instructor.ejs`
7. Instructor can import confirmed finding via POST `/sca/import/:finding_id`
8. Route calls `importToVM(findingId)` which creates vulnerability in VM registry
9. Prevents duplicate imports via source/source_id check

**Vulnerability Lifecycle (VM):**

1. Vulnerabilities created by: Manual professor entry, SCA/DAST/Pentest imports
2. Status transitions: open -> in_progress (professor/admin) -> resolved (with notes) or wont_fix (admin only)
3. Regression possible: in_progress/resolved -> open
4. Each transition validates against VALID_TRANSITIONS whitelist in `routes/vm.js`
5. All transitions logged to audit_logs (if enabled)

**State Management:**

- **Session State:** User identity stored in `req.session.user` (created by express-session middleware)
- **Security State:** Read from database into `req.securitySettings` via `loadSecuritySettings` middleware on every request
- **View State:** Database queries executed per-request (no caching), results rendered directly
- **Ephemeral Broadcast State:** `_instructorMessage` in-memory variable in `server.js` for instructor-to-student notifications

## Key Abstractions

**Database Abstraction:**
- Purpose: Provide SQL-like interface over JSON file storage for educational consistency
- Examples: `db.prepare('SELECT * FROM users').all()`, `db.prepare('INSERT INTO ...').run(...)`
- Pattern: Implements executeSQL parser with support for SELECT, INSERT, UPDATE, DELETE, basic WHERE/JOIN clauses
- Location: `config/database.js`
- Behavior: Reads/writes to `database/data.json` with atomic writes (write to temp file, then rename)

**Security Settings Registry:**
- Purpose: Feature flags for security demonstrations (MFA, RBAC, encryption, audit, etc.)
- Examples: Nine boolean settings + backup config in security_settings table
- Pattern: Single-row table (id=1), updated via `updateSecuritySetting(setting, value)` with whitelist validation
- Location: `config/security.js`
- Loaded into every request via `loadSecuritySettings` middleware

**Backup/Recovery System:**
- Purpose: Automated database backup and recovery from corruption
- Location: `utils/backupManager.js`
- Behavior:
  - Atomic writes to `data.json.tmp` then rename (prevents corruption mid-write)
  - Automatic recovery from most recent valid backup if main database corrupted
  - Admin can trigger manual backup, list backups, restore to specific backup
  - Scheduled backups if backup_enabled and backup_frequency set

**Encryption Abstraction:**
- Purpose: Support field-level (SSN, grades) and at-rest (password) encryption
- Location: `utils/encryption.js`
- Pattern:
  - Default key: 32-char string hardcoded in source
  - Custom key: Loaded from `keys/custom-key.txt` if exists (BYOK feature)
  - AES-256-CBC algorithm with random IV per encryption
  - Functions: `encrypt(plaintext)`, `decrypt(ciphertext)`, `saveCustomKey()`, `deleteCustomKey()`

**Role-Based Access Control (RBAC):**
- Purpose: Enforce endpoint access by user role (student, professor, admin)
- Location: `middleware/rbac.js`
- Pattern: `requireRole(['admin', 'professor'])` middleware factory
- Fallback: RBAC bypass (allows access with warning) when rbac_enabled = 0
- Audit: Failed access logged to audit_logs with RBAC_DENIED action

## Entry Points

**Web Server:**
- Location: `server.js`
- Triggers: Direct `node server.js` or spawned by classroom-manager
- Responsibilities:
  - Initialize database (load from file or seed if empty)
  - Set up EJS view engine
  - Register session middleware with secure cookie flags
  - Load security settings and language middleware
  - Mount route handlers for auth, dashboard, classes, SCA, DAST, VM, pentest, admin
  - Provide health check endpoint (`GET /health`) and internal summary API (`GET /api/summary`)
  - Start HTTP or HTTPS server based on security settings
  - Handle 404 and error responses

**Classroom Manager Orchestrator:**
- Location: `scripts/classroom-manager.js`
- Triggers: `npm start` (this is the default start script)
- Responsibilities:
  - Read `classroom.config.json` (basePort, instanceCount, teams)
  - Spawn N child processes of `server.js` each with unique PORT and TEAM_NAME env vars
  - Monitor child process health via `/health` endpoint polling
  - Serve instructor dashboard on separate port (`dashboardPort`: 3000) showing all teams
  - Detect Codespaces environment and generate external URLs
  - Handle graceful shutdown: kill all child processes on SIGINT/SIGTERM
  - Manage `instances/.pids.json` to track running instances

**Database Setup:**
- Location: `scripts/setup.js`
- Triggers: `npm run setup` (called by classroom-manager on first run)
- Responsibilities:
  - Initialize `database/data.json` if not exists
  - Create default admin/professor/student users
  - Insert default security settings
  - Create all required tables (collections) in JSON structure

**Health Check:**
- Location: `scripts/smoke-test.js`
- Triggers: `npm test`
- Responsibilities:
  - Poll all team instances' `/health` endpoints
  - Verify response structure and uptime
  - Report pass/fail to stdout

## Error Handling

**Strategy:** Graceful degradation with feature-specific fallbacks

**Patterns:**

- **Missing Database:** Auto-initialize from template schema or recover from backups (`config/database.js` loadDatabase function)
- **Audit Log Failure:** Log to console but don't fail request (`middleware/audit.js` wraps in try/catch)
- **MFA/Encryption Disabled:** Fall back to plaintext passwords or no MFA (intentional educational vulnerability)
- **Rate Limit Bypass:** Only enforced if rate_limiting enabled; otherwise skipped silently
- **Session Timeout:** Redirect to login with error message via `middleware/auth.js` requireAuth
- **Database Corruption:** Detect via `isValidDatabase()` check, auto-recover from most recent valid backup in `backups/`
- **Route Not Found:** 404 handler in `server.js` renders `views/error.ejs` template with status code
- **Unhandled Exception:** Global error handler middleware in `server.js` captures, logs, renders `views/error.ejs` with stack if NODE_ENV=development

## Cross-Cutting Concerns

**Logging:**
- Console logging in `server.js` initialization and error handlers
- Audit logging to database table audit_logs (only if `req.securitySettings.audit_logging` is truthy)
- Audit log fields: user_id, username, role, action, resource_type, resource_id, ip_address, user_agent, details (JSON), success flag
- Actions logged: RBAC_DENIED, TOGGLE_SECURITY, auth attempts, login/logout

**Validation:**
- Client-side: HTML form validation attributes (type, required, pattern)
- Server-side:
  - Username/password presence check in `routes/auth.js` login handler
  - MFA code format validation (6-digit) in `routes/auth.js` mfa-verify handler
  - RBAC whitelist check (VALID_SETTINGS in `config/security.js`, VALID_TRANSITIONS in `routes/vm.js`)
  - SQL injection prevention via parameter binding (db.prepare uses positional params)

**Authentication:**
- Session-based via express-session middleware with signed cookies
- Secure cookie flags set based on https_enabled setting (httpOnly always true)
- Session secret hardcoded in `server.js`
- MFA enforcement only for admin role (if mfa_enabled and user.mfa_enabled)
- MFA implementation via speakeasy (TOTP) + qrcode (QR generation) in `routes/auth.js` and `routes/admin.js`

**Security Features (Toggleable):**
1. `mfa_enabled` - Multi-factor authentication for admins via TOTP
2. `rbac_enabled` - Role-based access control enforcement
3. `encryption_at_rest` - Password hashing via bcrypt (vs plaintext)
4. `field_encryption` - AES-256-CBC encryption for SSN and grades
5. `https_enabled` - HTTPS server with self-signed cert (requires restart)
6. `audit_logging` - Log all security-relevant actions to database
7. `rate_limiting` - Limit login attempts per IP/username
8. `backup_enabled` - Automatic backup scheduling
9. `segregation_of_duties` - Placeholder for future implementation

---

*Architecture analysis: 2026-03-12*
