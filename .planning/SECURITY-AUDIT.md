# Security Audit — HEC Montreal Application Security Platform

**Date:** 2026-03-22
**Scope:** Real application security (excluding 12 intentional teaching vulnerabilities)

---

## Summary: 2 Critical (accepted risk), 1 High (resolved), 1 High (accepted risk), 3 Medium (1 resolved, 2 accepted risk)

---

### CRITICAL

**SEC-C01: Hardcoded session secret in server.js**
- **File:** `server.js:60`
- **Issue:** Session secret is `'university-class-management-secret-key-change-in-production'` — hardcoded in source code. Anyone with repo access can forge session cookies.
- **Fix:** Move to environment variable. Add `.env` file with `SESSION_SECRET` and load via `process.env`.
> **Accepted Risk -- Teaching Vulnerability #1.** This is intentional SCA Finding #1 and CTF Challenge 1. Students must discover the hardcoded secret in source code. See SECURITY-BOUNDARY.md. DO NOT FIX.

**SEC-C02: No CSRF protection on any route**
- **Issue:** No `csurf` or equivalent middleware. All POST/PUT/DELETE routes are vulnerable to cross-site request forgery. A malicious page could submit reviews, reset CTF progress, or trigger admin actions on behalf of a logged-in user.
- **Fix:** Add CSRF middleware to all state-changing routes.
> **Accepted Risk -- Teaching Vulnerability #7.** This is intentional SCA Finding #7, DAST Scenario 3, and CTF Challenge 6. See SECURITY-BOUNDARY.md. DO NOT FIX.

### HIGH

**SEC-H01: 3 high-severity npm vulnerabilities**
- **Packages:** bcrypt (via @mapbox/node-pre-gyp → tar)
- **Issue:** Known path traversal in tar dependency
- **Fix:** `npm audit fix --force` (may require bcrypt update)
> **Resolved.** bcrypt upgraded from 5.1.1 to 6.0.0, eliminating the tar/node-pre-gyp vulnerability chain.

**SEC-H02: No security headers (Helmet)**
- **Issue:** No `helmet` middleware. Missing Content-Security-Policy, X-Frame-Options, HSTS, X-Content-Type-Options.
- **Fix:** `npm install helmet` and add `app.use(helmet())` in server.js
> **Accepted Risk -- Teaching Vulnerability #9.** This is intentional SCA Finding #9. Students must identify missing security headers. See SECURITY-BOUNDARY.md. DO NOT FIX.

### MEDIUM

**SEC-M01: No .env file — all config is hardcoded or in-memory**
- **Issue:** Database path, session secret, and port are all in source code. No environment separation.
- **Fix:** Create `.env` file with environment-specific config, add `dotenv` package.
> **Resolved.** .env.example created, .env added to .gitignore, server.js loads .env via process.loadEnvFile() when present.

**SEC-M02: Rate limiter exists but coverage unclear**
- **File:** `middleware/rateLimiter.js`
- **Issue:** Rate limiter middleware exists but needs verification that it's applied to auth routes (login, CTF flag submission) to prevent brute force.
- **Fix:** Verify rate limiter is on `/auth/login` and `/pentest/challenges/:id/submit`.
> **Accepted Risk -- Teaching Vulnerability #8.** Rate limiting only on login is intentional SCA Finding #8 and CTF Challenge 8. See SECURITY-BOUNDARY.md. DO NOT FIX.

**SEC-M03: No HTTPS enforcement**
- **Issue:** No redirect from HTTP to HTTPS. In a classroom setting this is low risk, but for any public deployment it's critical.
- **Fix:** Add HTTPS redirect middleware for production.

---

## What's Working Well
- bcrypt password hashing (`utils/passwordHash.js`)
- RBAC middleware (`middleware/rbac.js`) for role-based access control
- Audit logging middleware (`middleware/audit.js`)
- MFA setup capability (`views/admin/mfa-setup.ejs`)
- Rate limiter exists
- No secrets in git history (no .env file to leak)
