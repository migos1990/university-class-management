# External Integrations

**Analysis Date:** 2026-03-12

## APIs & External Services

**Third-party APIs:**
- Not detected - Application is self-contained with no external API integrations

## Data Storage

**Databases:**
- JSON file-based persistence (no external database required)
  - Connection: Local filesystem via `database/data.json`
  - Client: Custom in-memory model with file I/O
  - Access: `config/database.js` provides SQL-like interface

**File Storage:**
- Local filesystem only
  - Database: `database/data.json`
  - Backups: `backups/` directory (automatic periodic backups)
  - SSL certificates: `ssl/` directory (self-signed, generated on setup)
  - Encryption keys: `keys/` directory (BYOK - bring-your-own-key support)

**Caching:**
- None - Application uses in-memory session store (`express-session`)
- Sessions stored in-memory, not persistent across restarts

## Authentication & Identity

**Auth Provider:**
- Custom implementation
  - Username/password authentication via `routes/auth.js`
  - Session-based state management via `express-session`
  - Multi-factor authentication (TOTP) via `speakeasy` library
  - Password hashing via `bcrypt`

**MFA:**
- TOTP (Time-based One-Time Password) for admin users
- QR code generation for authenticator app setup via `qrcode` library
- Implemented in `routes/auth.js` and `routes/admin.js`

**Authorization:**
- Role-based access control (RBAC)
  - Roles: `student`, `professor`, `admin`
  - Middleware: `middleware/rbac.js`
  - Enforced on all protected routes

## Monitoring & Observability

**Error Tracking:**
- None - Application uses console logging only

**Logs:**
- Audit logging (optional, configurable via security settings)
  - Middleware: `middleware/audit.js`
  - Records: User actions, authentication attempts, security changes
  - Storage: In-memory and persisted to database (`audit_logs` table)
  - Retention: Auto-pruned to 1000 most recent entries
- Console logging for server events and errors

## CI/CD & Deployment

**Hosting:**
- GitHub Codespaces (primary)
- Local development environment

**CI Pipeline:**
- None detected - No automated CI/CD pipeline

**Deployment:**
- Manual via `npm start` command
- Classroom-only mode with 12 isolated team instances
- Health check endpoint: `GET /health` (returns team, port, uptime, timestamp)
- Summary endpoint: `GET /api/summary` (returns classroom-visible metrics)

## Environment Configuration

**Required env vars:**
- `NODE_ENV` - Set to "development" (required for Codespaces)
- `PORT` - HTTP server port (default: 3000)
- `DATA_DIR` - Database directory (default: `database/`)
- `BACKUP_DIR` - Backup directory (default: `backups/`)
- `SSL_DIR` - SSL certificate directory (default: `ssl/`)
- `TEAM_NAME` - Team identifier (set by classroom manager for instances)

**Secrets location:**
- Encryption keys: `keys/custom-key.txt` (optional, BYOK)
- SSL private key: `ssl/server-key.pem` (generated on setup)
- Session secret: Hardcoded in `server.js` (should be environment variable)

## Webhooks & Callbacks

**Incoming:**
- None - Application receives only HTTP requests from browsers

**Outgoing:**
- None - Application makes no outgoing HTTP requests

## Security Features (Configurable)

**Runtime toggles** (via `config/security.js`):
- MFA enabled - Require TOTP for admin login
- RBAC enabled - Enforce role-based access control (default: on)
- Encryption at rest - Hash all passwords with bcrypt
- Field encryption - Encrypt sensitive fields (SSN, grades) with AES-256-CBC
- HTTPS enabled - Enforce HTTPS with self-signed certificates
- Audit logging - Log all user actions and security events
- Rate limiting - Limit login attempts per IP (configurable threshold)
- Backup enabled - Automatic periodic database backups
- Backup frequency - Minutes between backups (default: 60)
- Segregation of duties - RBAC enforcement level

## Classroom Management (Internal)

**Instructor broadcast system:**
- Endpoint: `POST /api/instructor-message` - Set message from dashboard
- Endpoint: `GET /api/instructor-message` - Student poll for new messages
- Storage: In-memory (ephemeral, resets on restart)

**Team instance coordination:**
- Base network: `0.0.0.0` (isolated classroom network)
- Management: `scripts/classroom-manager.js` coordinates 12 instances
- Health checks: Each instance reports via `/health` endpoint
- Configuration: `classroom.config.json` defines team names and ports

---

*Integration audit: 2026-03-12*
