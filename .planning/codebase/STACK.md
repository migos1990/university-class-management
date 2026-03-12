# Technology Stack

**Analysis Date:** 2026-03-12

## Languages

**Primary:**
- JavaScript (Node.js) - Main application runtime, all server-side code, backend logic, and scripting

## Runtime

**Environment:**
- Node.js 22 (as specified in `.devcontainer/devcontainer.json`)
- Deployed in GitHub Codespaces (devcontainer setup)

**Package Manager:**
- npm - Dependency management
- Lockfile: `package-lock.json` (tracked in `.gitignore`)

## Frameworks

**Core:**
- Express.js 4.18.2 - Web framework, HTTP server, routing, middleware
- EJS 3.1.9 - Template engine for server-side HTML rendering

**Security & Authentication:**
- bcrypt 5.1.1 - Password hashing with configurable salt rounds (10 rounds)
- express-session 1.17.3 - Session management, user authentication state
- cookie-parser 1.4.6 - HTTP cookie parsing and handling
- speakeasy 2.0.0 - TOTP MFA implementation (generates, validates OTP codes)
- qrcode 1.5.3 - QR code generation for MFA setup

**Cryptography & SSL:**
- Node.js native `crypto` module - AES-256-CBC encryption for sensitive fields
- selfsigned 2.4.1 - Self-signed SSL certificate generation for HTTPS
- Node.js native `https` module - HTTPS server support

## Key Dependencies

**Critical:**
- express - HTTP server framework
- express-session - Authentication session management
- bcrypt - Password hashing security layer
- speakeasy - Multi-factor authentication (TOTP)

**Infrastructure:**
- cookie-parser - Session cookie handling
- qrcode - MFA QR code generation
- selfsigned - SSL certificate generation
- ejs - Server-side template rendering

## Configuration

**Environment:**
- `NODE_ENV` - Set to "development" in `.devcontainer/remoteEnv`
- `PORT` - HTTP server port (default 3000 for dashboard, 3001-3012 for team instances)
- `HTTPS_PORT` - HTTPS port (3443)
- `DATA_DIR` - Database file location (defaults to `database/` directory)
- `BACKUP_DIR` - Backup storage location (defaults to `backups/` directory)
- `SSL_DIR` - SSL certificate directory (defaults to `ssl/` directory)
- `TEAM_NAME` - Team identifier for classroom instances (set at runtime)

**Build:**
- `.devcontainer/devcontainer.json` - Codespaces configuration
  - Base image: `mcr.microsoft.com/devcontainers/javascript-node:22`
  - Post-create: `npm install && node scripts/setup.js`
  - Post-start: `npm start`
  - Forwarded ports: 3000 (dashboard), 3001-3012 (team instances)

## Database

**Type:**
- JSON file-based (in-memory model with file persistence)
- Location: `database/data.json` (generated on first run)
- Backup system: `backups/` directory with timestamp-based backups

**Access Layer:**
- Custom SQL-like query interface (`config/database.js`)
- Simulates prepared statements with `db.prepare(sql).run/get/all()`
- Auto-recovery from corrupted state via backup files

## Platform Requirements

**Development:**
- GitHub Codespaces (primary deployment target)
- Node.js 22
- npm package manager

**Production:**
- GitHub Codespaces (classroom-only mode)
- Docker (via devcontainer)
- Ports 3000-3012 must be accessible on host network

**Storage:**
- Local filesystem for database, backups, SSL certificates, and encryption keys
- All data persisted to disk via JSON files

## Scripts

**Available npm commands** (in `package.json`):
- `npm start` - Run classroom manager with all team instances
- `npm run setup` - Initialize database and SSL certificates
- `npm run test` - Run smoke test suite
- `npm run test:open` - Run smoke test and open report in browser
- `npm run stop` - Stop all running instances

---

*Stack analysis: 2026-03-12*
