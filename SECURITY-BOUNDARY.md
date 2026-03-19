# Security Boundary

This project contains intentional security vulnerabilities for educational purposes.

This document maps every known security issue in the codebase, distinguishes deliberate teaching tools from real findings, and serves as the single source of truth for contributors and reviewers.

---

## Definitions

**Intentional Vulnerability** -- A security flaw planted in the codebase for the SCA lab teaching exercise. Students discover, classify, and assess these findings as part of the course. **DO NOT FIX.**

**Accepted Risk** -- A real limitation that has been assessed and accepted for the classroom context. These are not teaching tools; they are known trade-offs documented for transparency.

---

## Intentional Vulnerabilities

### #1 Hardcoded Session Secret

| Field | Value |
|-------|-------|
| SCA Finding ID | #1 |
| CWE | CWE-798 (Hardcoded Credentials) |
| OWASP 2021 | A02:2021 - Cryptographic Failures |
| Severity | Critical |
| Difficulty | Easy |
| Location | `server.js:45` |
| Learning Objective | Recognize hardcoded secrets in source code and understand how exposed session secrets enable authentication bypass through forged session cookies |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #2 Hardcoded AES Encryption Key

| Field | Value |
|-------|-------|
| SCA Finding ID | #2 |
| CWE | CWE-321 (Hardcoded Cryptographic Key) |
| OWASP 2021 | A02:2021 - Cryptographic Failures |
| Severity | Critical |
| Difficulty | Easy |
| Location | `utils/encryption.js:6` |
| Learning Objective | Identify hardcoded cryptographic keys and understand how key compromise exposes all encrypted PII (SSNs, grades) in the database |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #3 Plaintext Credentials Logged to Console

| Field | Value |
|-------|-------|
| SCA Finding ID | #3 |
| CWE | CWE-312 (Cleartext Storage of Sensitive Information) |
| OWASP 2021 | A09:2021 - Security Logging and Monitoring Failures |
| Severity | High |
| Difficulty | Easy |
| Location | `server.js:141` |
| Learning Objective | Recognize when sensitive data (passwords) is written to logs and understand how log aggregation systems expose credentials at scale |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #4 Plaintext Password Comparison

| Field | Value |
|-------|-------|
| SCA Finding ID | #4 |
| CWE | CWE-256 (Plaintext Storage of a Password) |
| OWASP 2021 | A07:2021 - Identification and Authentication Failures |
| Severity | Critical |
| Difficulty | Easy |
| Location | `routes/auth.js:38` |
| Learning Objective | Identify plaintext password storage and comparison, and understand why hashing with bcrypt/argon2 is required to protect credentials after a database breach |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #5 Audit Logging Defaults to OFF

| Field | Value |
|-------|-------|
| SCA Finding ID | #5 |
| CWE | CWE-778 (Insufficient Logging) |
| OWASP 2021 | A09:2021 - Security Logging and Monitoring Failures |
| Severity | High |
| Difficulty | Advanced |
| Location | `config/database.js:19` |
| Learning Objective | Understand the risk of disabled audit logging: security events (logins, privilege changes, data access) go unrecorded, preventing incident detection and forensics |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #6 IDOR: No Ownership Check on Enrollment Access

| Field | Value |
|-------|-------|
| SCA Finding ID | #6 |
| CWE | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| OWASP 2021 | A01:2021 - Broken Access Control |
| Severity | High |
| Difficulty | Medium |
| Location | `routes/classes.js:39` |
| Learning Objective | Recognize Insecure Direct Object Reference (IDOR) patterns where the endpoint uses a user-supplied ID instead of the authenticated session, allowing students to read other students' enrollment records |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #7 No CSRF Protection on State-Changing Requests

| Field | Value |
|-------|-------|
| SCA Finding ID | #7 |
| CWE | CWE-352 (Cross-Site Request Forgery) |
| OWASP 2021 | A01:2021 - Broken Access Control |
| Severity | High |
| Difficulty | Medium |
| Location | `server.js:1` |
| Learning Objective | Identify the absence of CSRF token validation on POST/PUT/DELETE routes and understand how an attacker can craft a malicious page to trigger authenticated actions on behalf of a logged-in user |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #8 Rate Limiting Only on Login Route

| Field | Value |
|-------|-------|
| SCA Finding ID | #8 |
| CWE | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| OWASP 2021 | A07:2021 - Identification and Authentication Failures |
| Severity | Medium |
| Difficulty | Medium |
| Location | `middleware/rateLimiter.js:9` |
| Learning Objective | Recognize incomplete rate limiting coverage: password reset, MFA verification, and API endpoints remain vulnerable to automated brute-force attacks |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #9 No HTTP Security Headers

| Field | Value |
|-------|-------|
| SCA Finding ID | #9 |
| CWE | CWE-693 (Protection Mechanism Failure) |
| OWASP 2021 | A05:2021 - Security Misconfiguration |
| Severity | Medium |
| Difficulty | Advanced |
| Location | `server.js:17` |
| Learning Objective | Identify missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) and understand how their absence enables clickjacking, MIME-sniffing, and XSS amplification |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #10 Path Traversal in Backup Download

| Field | Value |
|-------|-------|
| SCA Finding ID | #10 |
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| OWASP 2021 | A01:2021 - Broken Access Control |
| Severity | High |
| Difficulty | Advanced |
| Location | `routes/admin.js:509` |
| Learning Objective | Recognize path traversal vulnerabilities where unsanitized user input in filenames allows arbitrary file reads (e.g., `../../etc/passwd`) from the server |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #11 Outdated express-session with Known Vulnerabilities

| Field | Value |
|-------|-------|
| SCA Finding ID | #11 |
| CWE | CWE-1035 (Using a Third-Party Component with a Known Vulnerability) |
| OWASP 2021 | A06:2021 - Vulnerable and Outdated Components |
| Severity | Medium |
| Difficulty | Advanced |
| Location | `package.json:24` |
| Learning Objective | Identify outdated dependencies with known CVEs using tools like npm audit, and understand the importance of keeping dependencies current |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

### #12 Session Cookie Missing secure Flag

| Field | Value |
|-------|-------|
| SCA Finding ID | #12 |
| CWE | CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) |
| OWASP 2021 | A02:2021 - Cryptographic Failures |
| Severity | Medium |
| Difficulty | Advanced |
| Location | `server.js:51` |
| Learning Objective | Identify missing cookie security attributes and understand how session tokens transmitted over HTTP without the secure flag can be intercepted by a network attacker |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.

---

## Deliberately Weakened Controls

These security toggles default to OFF in the teaching environment, creating intentional weak postures for students to observe. They are distinct from the code-level vulnerabilities above -- they are configuration choices managed through the Security Panel.

| Control | Default | Config Source | Teaching Purpose |
|---------|---------|---------------|------------------|
| audit_logging | OFF | `config/database.js` (security_settings) | Students observe the absence of security event recording and understand why audit trails matter |
| rate_limiting | OFF | `config/database.js` (security_settings) | Students test brute-force attacks without throttling to see the impact of missing rate limits |
| mfa_enabled | OFF | `config/database.js` (security_settings) | Students see authentication without a second factor and understand the risk of single-factor auth |
| field_encryption | OFF | `config/database.js` (security_settings) | Students observe PII (SSNs, grades) stored in cleartext in the database |
| https_enabled | OFF | `config/database.js` (security_settings) | Students observe HTTP traffic without TLS and understand the risk of unencrypted communication |

---

## Real Security Findings

These are actual tech debt items from the v1.0 milestone audit. They are not teaching tools.

| # | Description | Status |
|---|-------------|--------|
| 1 | 2 hardcoded French strings in `finding-detail.ejs` lines 61, 64 bypass i18n | Accepted Risk |
| 2 | `GET /sca/findings/:id` missing users query (instructor sees student IDs not usernames) | Open |
| 3 | HTML comment in `instructor.ejs` contains English (non-visible to users) | Accepted Risk |
| 4 | `/auth/set-language` endpoint is dead code (no UI calls it) | Accepted Risk |

---

## Adding a New Teaching Vulnerability

To add a new intentional vulnerability to the codebase:

1. **Add the vulnerability** to the target source file.
2. **Add the finding entry** in `utils/seedData.js` inside the `scaFindings` array, including: CWE, severity, file path, line number, description, remediation, and code snippet.
3. **Add the OWASP mapping** in the `vmVulns` array in `utils/seedData.js` (vulnerabilities table), with the correct OWASP 2021 category.
4. **Add the difficulty mapping** in `DIFFICULTY_MAP` in `routes/sca.js`.
5. **Add an entry** to this `SECURITY-BOUNDARY.md` document following the format above.
6. **Update the finding count** references in documentation (README, CONTEXT, etc.).

---

Last verified: v1.1, 2026-03-19
