# Deployment Audit — HEC Montreal Application Security Platform

**Date:** 2026-03-22

---

## Summary: 3 Critical, 3 High, 2 Medium gaps

---

## Current State

| Aspect | Status |
|--------|--------|
| **Runtime** | Node.js/Express |
| **Database** | In-memory/file-based (data.json) |
| **Deployment target** | GitHub Codespaces (`.devcontainer/`) |
| **CI/CD** | None — no GitHub Actions workflows |
| **Environment files** | None — no .env |
| **Docker** | None — no Dockerfile |
| **Deploy config** | None — no Procfile/railway.json/render.yaml/fly.toml |
| **Monitoring** | None — no error tracking |
| **Backups** | `utils/backupManager.js` exists, `backups/` directory present |

---

## Findings

### CRITICAL

**DEP-C01: No environment separation**
- No .env file, no environment variables, no staging/production config
- Session secret hardcoded in server.js
- Everything runs as "development" implicitly
- **Fix:** Create .env with SESSION_SECRET, PORT, NODE_ENV. Add dotenv. Create .env.example.
> **Resolved.** .env.example created with PORT/NODE_ENV, .env added to .gitignore, server.js loads .env via process.loadEnvFile(). Note: SESSION_SECRET remains hardcoded as intentional teaching vulnerability #1.

**DEP-C02: No CI/CD pipeline**
- No `.github/workflows/` directory
- No automated testing on PR or push
- Tests exist (`npm test`, `npm run test:integration`) but only run manually
- **Fix:** Add GitHub Actions workflow: lint → format check → integration tests on PR.

**DEP-C03: In-memory/file-based database**
- `database/data.json` appears to be the data store
- No persistence guarantees — server restart may lose data
- No migration system, no backup automation
- **Fix:** For classroom use this may be acceptable (data resets each session). For any persistent deployment, migrate to SQLite file or Postgres.

### HIGH

**DEP-H01: No Dockerfile or container config**
- App can only run via `npm start` on a machine with Node.js
- Codespaces config exists (`.devcontainer/`) but no standalone container
- **Fix:** Add Dockerfile for reproducible deployments.

**DEP-H02: No health check endpoint**
- No `/health` route for monitoring
- **Fix:** Add simple health check route returning `{ status: "ok" }`.
> **Resolved.** Health check endpoint already exists at /health (server.js:112-120), returning JSON with status, team, port, uptime, and timestamp.

**DEP-H03: Classroom manager scripts are the only deployment mechanism**
- `scripts/classroom-manager.js` starts the app
- `scripts/classroom-stop.js` stops it
- No process manager (pm2, systemd) for auto-restart
- **Fix:** Add pm2 config or systemd unit file for production use.

### MEDIUM

**DEP-M01: No HTTPS configuration**
- Relies on Codespaces proxy or reverse proxy for TLS
- No explicit HTTPS redirect in app code
- Acceptable for classroom Codespaces, not for standalone deployment

**DEP-M02: Backup manager exists but no automated schedule**
- `utils/backupManager.js` provides backup functionality
- No cron or scheduled automation
- Manual-only backup process

---

## What's Working Well
- Codespaces devcontainer provides reproducible dev environment
- Port forwarding configured in `.devcontainer/set-ports-public.sh`
- Lint and format scripts in package.json
- Test suite exists (smoke + integration)
- Setup script (`npm run setup`) for initial configuration

---

## Recommendation

This is primarily a **classroom teaching tool** running in GitHub Codespaces, not a production SaaS. The deployment gaps are appropriate for its use case. Priority fixes:

1. **Add CI/CD** (GitHub Actions) — prevents broken code from being deployed to Codespaces
2. **Add .env** — separates config from code, especially the session secret
3. **Add health check** — basic monitoring capability
