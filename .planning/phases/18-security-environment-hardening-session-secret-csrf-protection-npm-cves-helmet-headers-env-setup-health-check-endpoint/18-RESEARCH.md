# Phase 18: Security & Environment Hardening - Research

**Researched:** 2026-03-22
**Domain:** Express.js security hardening, environment configuration, npm dependency management
**Confidence:** HIGH

## Summary

This phase addresses real infrastructure-level security findings from the SECURITY-AUDIT.md and DEPLOYMENT-AUDIT.md. However, there is a **critical constraint**: 5 of the 7 security audit findings overlap directly with the 12 intentional teaching vulnerabilities that students discover in the SCA lab, DAST lab, and CTF pentest lab. These MUST NOT be fixed -- they are the core pedagogical content.

After careful analysis, the safely addressable items are: (1) adding a `.env` file with `dotenv` for environment variable management (SEC-M01/DEP-C01), (2) upgrading bcrypt from 5.1.1 to 6.0.0 to resolve the tar/node-pre-gyp vulnerability chain (SEC-H01), and (3) verifying the existing health check endpoint already satisfies DEP-H02. The session secret hardcoding (#1), CSRF absence (#7), missing Helmet headers (#9), rate limiter coverage (#8), and npm audit findings related to express-session (#11) are all intentional vulnerabilities and must remain untouched.

**Primary recommendation:** Create a `.env` + `.env.example` setup using Node.js 20's native `--env-file` support (zero new dependencies), upgrade bcrypt to v6, and document why the remaining audit findings are intentionally preserved. Do NOT add Helmet, CSRF middleware, or change the session secret source.

<phase_requirements>
## Phase Requirements

The security audit findings serve as implicit requirements for this phase:

| ID | Description | Research Support |
|----|-------------|-----------------|
| SEC-C01 | Hardcoded session secret in server.js | BLOCKED: This is intentional vulnerability #1 (SCA finding). MUST NOT fix. Document as accepted. |
| SEC-C02 | No CSRF protection on any route | BLOCKED: This is intentional vulnerability #7 (SCA finding) + DAST Scenario 3 + CTF Challenge 6. MUST NOT fix. Document as accepted. |
| SEC-H01 | 3 high-severity npm vulnerabilities (bcrypt/tar) | ACTIONABLE: Upgrade bcrypt 5.1.1 to 6.0.0. Resolves tar chain. API unchanged. |
| SEC-H02 | No security headers (Helmet) | BLOCKED: This is intentional vulnerability #9 (SCA finding). MUST NOT add Helmet. Document as accepted. |
| SEC-M01 | No .env file -- all config hardcoded | ACTIONABLE: Create .env/.env.example with dotenv or Node.js 20 --env-file. Extract PORT, NODE_ENV, DATA_DIR. |
| SEC-M02 | Rate limiter coverage unclear | BLOCKED: Rate limiting only on login is intentional vulnerability #8 (SCA finding). Verify it works on login; do not expand. |
| DEP-C01 | No environment separation | ACTIONABLE: Same as SEC-M01. Create .env with environment-specific config. |
| DEP-H02 | No health check endpoint | ALREADY DONE: /health endpoint exists at server.js:112-120. Verify and close. |
</phase_requirements>

## CRITICAL: Intentional Vulnerability Overlap

This is the most important finding of this research. The security audit findings overlap with **5 of the 12 intentional teaching vulnerabilities** documented in SECURITY-BOUNDARY.md:

| Audit Finding | Intentional Vuln | SCA Finding | DAST/CTF | Status |
|--------------|-----------------|-------------|----------|--------|
| SEC-C01: Hardcoded session secret | #1 Hardcoded Session Secret | SCA #1 (Easy) | CTF Challenge 1 (FLAG{session-secret-exposed}) | DO NOT FIX |
| SEC-C02: No CSRF protection | #7 No CSRF Protection | SCA #7 (Medium) | DAST Scenario 3 + CTF Challenge 6 (FLAG{csrf-no-token-required}) | DO NOT FIX |
| SEC-H01: npm CVEs (bcrypt/tar) | #11 Outdated express-session | SCA #11 (Advanced) | -- | PARTIAL: Fix bcrypt/tar (not the same as #11). Finding #11 is about express-session, not bcrypt. |
| SEC-H02: No Helmet headers | #9 No HTTP Security Headers | SCA #9 (Advanced) | -- | DO NOT FIX |
| SEC-M02: Rate limiter coverage | #8 Rate Limiting Only Login | SCA #8 (Medium) | CTF Challenge 8 (FLAG{no-mfa-rate-limit}) | DO NOT FIX |

**Why the session secret CANNOT move to .env:** SCA Finding #1 explicitly teaches students to "recognize hardcoded secrets in source code." The code snippet shown to students is from `server.js` showing the literal secret string. If we move it to `process.env.SESSION_SECRET`, the finding stops being discoverable as a hardcoded secret -- destroying the exercise. The secret MUST remain hardcoded in server.js.

**Why CSRF middleware CANNOT be added:** SCA Finding #7, DAST Scenario 3, and CTF Challenge 6 all depend on the complete absence of CSRF protection. Adding any CSRF middleware (csurf, csrf-csrf, csrf-sync) would break 3 teaching exercises simultaneously.

**Why Helmet CANNOT be added:** SCA Finding #9 teaches students to identify missing security headers. Adding Helmet would eliminate this finding from the exercise.

## Standard Stack

### Core (Changes)
| Library | Version | Purpose | Why |
|---------|---------|---------|-----|
| bcrypt | 6.0.0 (upgrade from 5.1.1) | Password hashing | Resolves 3 high-severity tar vulnerabilities. Drops @mapbox/node-pre-gyp dependency entirely. Ships prebuildify binaries. |
| dotenv | 16.x (or Node.js 20 native) | .env file loading | Zero-dependency module for environment variable management |

### Already Present (No Changes)
| Library | Version | Purpose | Note |
|---------|---------|---------|------|
| express | 4.22.1 | Web framework | No change |
| express-session | 1.19.0 | Session management | No change (intentional vuln #11) |
| cookie-parser | 1.4.6 | Cookie parsing | No change |

### NOT Adding (Intentional)
| Library | Why Not Adding |
|---------|---------------|
| helmet | SCA Finding #9 depends on missing security headers |
| csurf / csrf-csrf / csrf-sync | SCA Finding #7, DAST Scenario 3, CTF Challenge 6 depend on no CSRF |
| express-rate-limit | SCA Finding #8 depends on limited rate-limiter coverage |

### .env Strategy: Node.js 20 Native vs dotenv

The project runs Node.js v20.20.0, which supports `--env-file=.env` natively (since v20.6.0). Two options:

**Option A: Node.js 20 native `--env-file` (RECOMMENDED)**
- Zero new dependencies (aligns with project philosophy: "no new dependencies" from Phase 8)
- Usage: `node --env-file=.env server.js`
- Also: `process.loadEnvFile('.env')` can be called from scripts
- Requires updating start scripts in package.json and classroom-manager.js

**Option B: dotenv package**
- Well-known, 107M weekly downloads
- Usage: `require('dotenv').config()` at top of server.js
- Adds a dependency (lightweight, zero transitive deps)

**Recommendation: Option A** -- Node.js 20 native. The project has a strong "no new dependencies" convention (Phase 8 decision). The native approach works identically with zero package additions. The `--env-file` flag is stable in Node.js 20.

**Installation:**
```bash
npm install bcrypt@6
```

That is the only dependency change needed. No new packages required.

## Architecture Patterns

### .env File Structure
```
# .env.example (committed to git)
# Copy to .env and customize

# Server
PORT=3000
NODE_ENV=development

# Data directories (used by classroom-manager child processes)
# DATA_DIR=./database
# BACKUP_DIR=./backups
# SSL_DIR=./ssl
```

**Note: SESSION_SECRET is deliberately NOT in .env.** The hardcoded session secret in server.js is intentional vulnerability #1. Moving it to .env would break the SCA lab exercise.

### server.js Changes (Minimal)
```javascript
// At the very top of server.js, before any other code:
// Load .env if it exists (optional -- env vars may come from parent process)
const fs = require('fs');
const path = require('path');
if (fs.existsSync(path.join(__dirname, '.env'))) {
  process.loadEnvFile(path.join(__dirname, '.env'));
}
```

Alternatively, modify the start command:
```json
{
  "scripts": {
    "start": "node --env-file=.env scripts/classroom-manager.js"
  }
}
```

### Health Check Endpoint (Already Exists)

The health check endpoint already exists at `server.js:112-120`:
```javascript
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    team: process.env.TEAM_NAME || 'default',
    port: process.env.PORT || 3000,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});
```

DEP-H02 is already resolved. No work needed.

### Files That Already Use process.env

These files already read environment variables and will benefit from .env:

| File | Variables Used |
|------|---------------|
| `server.js` | PORT, TEAM_NAME, NODE_ENV, SSL_DIR |
| `config/database.js` | DATA_DIR |
| `utils/backupManager.js` | BACKUP_DIR, DATA_DIR |
| `scripts/classroom-manager.js` | TEAM_COUNT, CODESPACE_NAME, GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN, NODE_ENV |
| `test/helpers.js` | TEST_URL |

### .gitignore Update
Currently `.gitignore` does NOT include `.env`. Must add:
```
# Environment variables
.env
.env.local
.env.*.local
```

### devcontainer.json Integration
The `.devcontainer/devcontainer.json` already sets `remoteEnv.NODE_ENV = "development"`. The .env file will complement this -- environment variables from devcontainer.json take precedence over .env in Codespaces.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| .env parsing | Custom file parser | Node.js 20 `process.loadEnvFile()` or `--env-file` | Native, zero deps, handles edge cases (quoting, multiline) |
| bcrypt upgrade | Manual dependency resolution | `npm install bcrypt@6` | Direct upgrade, no manual tar patching |
| Health check | New endpoint | Existing `/health` route | Already implemented and working |

## Common Pitfalls

### Pitfall 1: Breaking Teaching Vulnerabilities
**What goes wrong:** Developer reads security audit, "fixes" everything, breaks 5 of 12 SCA findings + DAST Scenario 3 + CTF Challenge 6.
**Why it happens:** Audit findings and intentional vulnerabilities are the same code patterns. Natural instinct is to fix all audit findings.
**How to avoid:** Cross-reference EVERY change against SECURITY-BOUNDARY.md's 12 intentional vulnerabilities. If the code being changed IS the vulnerability, stop.
**Warning signs:** `npm test` or `npm run test:integration` fails after changes; CTF flags become unreachable; SCA code snippets no longer match source.

### Pitfall 2: Moving Session Secret to .env
**What goes wrong:** Moving `secret: 'university-class-management-secret-key-change-in-production'` to `secret: process.env.SESSION_SECRET` breaks SCA Finding #1 and CTF Challenge 1.
**Why it happens:** SEC-C01 audit says "move to environment variable." But this is intentional vuln #1.
**How to avoid:** Leave the session secret hardcoded in server.js. Only extract NON-SECURITY config (PORT, NODE_ENV, DATA_DIR) to .env.
**Warning signs:** SCA finding #1's code snippet no longer shows a literal secret string.

### Pitfall 3: bcrypt v6 Binary Compilation Issues
**What goes wrong:** bcrypt v6 ships prebuilt binaries via prebuildify, but some platforms may not have a prebuilt binary available.
**Why it happens:** bcrypt v6 dropped node-pre-gyp (which compiled on install). Prebuildify ships platform-specific binaries in the npm package.
**How to avoid:** Test `npm install bcrypt@6` on the target platform (macOS for local dev, Linux for Codespaces). The devcontainer image (`mcr.microsoft.com/devcontainers/javascript-node:22`) should have prebuilt binaries.
**Warning signs:** `npm install` fails with native addon compilation errors.

### Pitfall 4: .env File in Git
**What goes wrong:** .env file committed to repository, defeating the purpose of environment separation.
**Why it happens:** .gitignore doesn't include .env (currently missing).
**How to avoid:** Add `.env` to `.gitignore` BEFORE creating the .env file. Commit `.env.example` (with placeholder values) instead.
**Warning signs:** `git status` shows `.env` as untracked or staged.

### Pitfall 5: classroom-manager.js Environment Inheritance
**What goes wrong:** Child processes spawned by classroom-manager don't inherit .env variables because the parent process didn't load them.
**Why it happens:** `classroom-manager.js` uses `spawn()` with `env: { ...process.env, PORT, ... }`. If .env isn't loaded before the manager runs, child processes won't have those vars.
**How to avoid:** Load .env at the start of classroom-manager.js or use `--env-file=.env` in the npm start command.
**Warning signs:** Child instances start but use fallback defaults for PORT, DATA_DIR, etc.

### Pitfall 6: NODE_ENV in Production vs Teaching Context
**What goes wrong:** Setting NODE_ENV=production enables Express production mode, which changes error handling (server.js:275 shows error details only in development mode).
**Why it happens:** .env template might default to NODE_ENV=production.
**How to avoid:** Default to NODE_ENV=development in .env.example. The app is a classroom tool, not a production SaaS.
**Warning signs:** Error pages show "An error occurred" with no details, making debugging impossible for the instructor.

## Code Examples

### bcrypt Upgrade Verification
```bash
# Upgrade bcrypt
npm install bcrypt@6

# Verify no vulnerabilities remain in bcrypt chain
npm audit

# Verify bcrypt still works
node -e "const bcrypt = require('bcrypt'); bcrypt.hash('test', 10).then(h => bcrypt.compare('test', h)).then(r => console.log('bcrypt works:', r))"

# Run existing tests to verify nothing broke
npm test
npm run test:integration
```

### .env.example Template
```bash
# HEC Montreal Application Security Platform
# Copy this file to .env and customize as needed

# Server configuration
PORT=3000
NODE_ENV=development

# NOTE: SESSION_SECRET is deliberately hardcoded in server.js.
# This is intentional vulnerability #1 for the SCA teaching exercise.
# Do NOT add SESSION_SECRET here.
```

### Loading .env in server.js (if using process.loadEnvFile)
```javascript
// server.js -- at the very top, before other requires
const path = require('path');
const fs = require('fs');

// Load .env if present (not required -- env vars may come from parent process)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  process.loadEnvFile(envPath);
}
```

### Updated .gitignore Entry
```gitignore
# Environment variables (never commit actual .env)
.env
.env.local
.env.*.local
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| dotenv package | Node.js 20 `--env-file` / `process.loadEnvFile()` | Node.js 20.6.0 (Aug 2023) | Zero dependency .env loading |
| bcrypt 5.x + node-pre-gyp + tar | bcrypt 6.x + prebuildify | bcrypt 6.0.0 | Eliminates 3 high-severity tar vulns |
| csurf middleware | csrf-csrf or csrf-sync | 2022+ (csurf deprecated) | NOT APPLICABLE -- CSRF must remain absent for teaching |

**Deprecated/outdated:**
- `csurf`: Deprecated in 2022. Modern alternatives are csrf-csrf or csrf-sync. But we are NOT adding any CSRF middleware (intentional vulnerability).
- `node-pre-gyp` (@mapbox): Replaced by `prebuildify` in bcrypt 6. This is the root cause of the tar vulnerability chain.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Node.js built-in test runner (node:test + node:assert) |
| Config file | None (uses node --test) |
| Quick run command | `npm test` (smoke test) |
| Full suite command | `npm run test:integration` |

### Phase Requirements Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-H01 | bcrypt upgrade resolves npm audit | smoke | `npm audit --audit-level=high 2>&1 \| grep -c "0 vulnerabilities"` | N/A (CLI check) |
| SEC-M01 | .env.example exists with correct vars | smoke | `test -f .env.example && grep PORT .env.example` | N/A (file check) |
| DEP-C01 | Environment variables loaded from .env | integration | `npm run test:integration` (existing tests still pass) | Wave 0 |
| DEP-H02 | Health check endpoint works | smoke | `npm test` (existing smoke test) | Existing |
| VULN-PRESERVE | All 12 intentional vulnerabilities intact | integration | `npm run test:integration` | Existing (5 test files) |

### Sampling Rate
- **Per task commit:** `npm test` (smoke tests verify intentional vulnerabilities still work)
- **Per wave merge:** `npm run test:integration` (full integration suite)
- **Phase gate:** Full suite green + `npm audit --audit-level=high` reports 0 high vulnerabilities

### Wave 0 Gaps
- [ ] `test/env-config.test.js` -- covers SEC-M01/DEP-C01: verifies .env.example exists, .env in .gitignore, process.env vars used correctly
- [ ] Manual verification: SCA findings 1, 7, 8, 9, 11 code snippets still match source after bcrypt upgrade

## Open Questions

1. **Should .env be loaded via --env-file flag or process.loadEnvFile()?**
   - What we know: Both work on Node.js 20.20.0. `--env-file` requires modifying npm scripts. `process.loadEnvFile()` can be called conditionally in code.
   - What's unclear: The classroom-manager.js spawns child processes with `spawn(process.execPath, [SERVER_JS])` -- the `--env-file` flag would need to be passed explicitly to children, whereas `process.loadEnvFile()` in server.js would auto-apply to each child.
   - Recommendation: Use `process.loadEnvFile()` in server.js (conditional on file existence). This way each child process loads its own .env automatically without modifying spawn arguments. Also load in classroom-manager.js for the parent process.

2. **Should we document why audit findings are intentionally unresolved?**
   - What we know: SECURITY-BOUNDARY.md already documents all 12 intentional vulnerabilities. SECURITY-AUDIT.md lists them as findings.
   - What's unclear: Whether SECURITY-AUDIT.md should be updated with "accepted risk" notations.
   - Recommendation: Add an "Accepted Risk -- Teaching Vulnerability" annotation to each overlapping finding in SECURITY-AUDIT.md, cross-referencing SECURITY-BOUNDARY.md.

3. **express-session version and SCA Finding #11**
   - What we know: express-session is at 1.19.0. SCA Finding #11 is about "Outdated express-session with Known Vulnerabilities" (CWE-1035). This is an intentional vulnerability.
   - What's unclear: Whether bcrypt upgrade + npm audit will flag express-session separately.
   - Recommendation: Do NOT upgrade express-session. It is intentional vulnerability #11. If npm audit flags it separately, document as accepted risk.

## Sources

### Primary (HIGH confidence)
- `SECURITY-BOUNDARY.md` -- All 12 intentional vulnerabilities documented with DO NOT FIX markers
- `SOLUTION-GUIDE.md:1123` -- "No CSRF protection: All forms lack CSRF tokens. This is intentional"
- `SOLUTION-GUIDE.md:1125` -- "Hardcoded keys in source code: Session secret and AES key are hardcoded. This is intentional"
- `.planning/SECURITY-AUDIT.md` -- 7 security findings (SEC-C01, SEC-C02, SEC-H01, SEC-H02, SEC-M01, SEC-M02, SEC-M03)
- `.planning/DEPLOYMENT-AUDIT.md` -- 8 deployment findings (DEP-C01 through DEP-M02)
- `server.js` -- Current Express app configuration, health check already present
- `package.json` -- Current dependencies (bcrypt 5.1.1, express-session 1.17.3)
- `npm audit` output -- 3 high-severity vulnerabilities in tar via bcrypt/node-pre-gyp chain

### Secondary (MEDIUM confidence)
- [bcrypt CHANGELOG.md](https://github.com/kelektiv/node.bcrypt.js/blob/master/CHANGELOG.md) -- v6.0.0 breaking changes: dropped Node.js <= 16 support, replaced node-pre-gyp with prebuildify
- [Node.js native .env support](https://pawelgrzybek.com/node-js-with-native-support-for-env-files-you-may-not-need-dotenv-anymore/) -- process.loadEnvFile() and --env-file flag in Node.js 20.6.0+
- [Helmet npm](https://www.npmjs.com/package/helmet) -- Latest v8.1.0, default CSP includes 'unsafe-inline' for styles

### Tertiary (LOW confidence)
- None -- all findings verified against primary sources

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- bcrypt upgrade path verified via npm audit dry-run and CHANGELOG; .env strategy verified against Node.js version
- Architecture: HIGH -- health check confirmed existing; .env pattern is well-established
- Pitfalls: HIGH -- intentional vulnerability overlap verified against SECURITY-BOUNDARY.md, SOLUTION-GUIDE.md, and seed data
- Intentional vulnerability preservation: HIGH -- cross-referenced across SECURITY-BOUNDARY.md, seedData.js, SOLUTION-GUIDE.md, and CTF challenge definitions

**Research date:** 2026-03-22
**Valid until:** 2026-04-22 (stable domain -- Express security patterns don't change rapidly)
