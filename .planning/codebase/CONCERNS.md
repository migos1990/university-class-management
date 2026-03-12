# Codebase Concerns

**Analysis Date:** 2026-03-12

## Tech Debt

**Hardcoded Encryption Key:**
- Issue: Default encryption key `'university-app-secret-key-32!'` embedded in source code
- Files: `utils/encryption.js` (line 6)
- Impact: Any attacker with code access can decrypt all encrypted SSNs and grades
- Fix approach: Load encryption key from environment variable at startup. Use secure key derivation (PBKDF2/Argon2) if key comes from passphrase. Rotate key and re-encrypt all data before deploying to production.

**Hardcoded Session Secret:**
- Issue: Session secret `'university-class-management-secret-key-change-in-production'` is hardcoded in server config
- Files: `server.js` (line 45)
- Impact: Session cookies can be forged; attackers can impersonate any user
- Fix approach: Load SESSION_SECRET from environment variable. Generate 64-byte cryptographically random value for production. Cycle secret on production deployment.

**In-Memory JSON Database with Limited Crash Protection:**
- Issue: Custom JSON-based database in `config/database.js` lacks transaction support and ACID guarantees
- Files: `config/database.js` (lines 133-141)
- Impact: Concurrent writes can corrupt data; partial saves on crash leave db.json in invalid state
- Fix approach: Implement proper locking for concurrent writes. Consider migration to SQLite or embedded PostgreSQL for educational use. Add transaction-like batching with retry logic.

**Large Monolithic Database Handler (1128 lines):**
- Issue: All SQL emulation logic crammed into single `executeSQL()` function with string matching
- Files: `config/database.js` (lines 160-1074)
- Impact: Hard to maintain; missing features; inconsistent parameter handling; prone to subtle bugs when adding new queries
- Fix approach: Refactor into query-specific handler functions or use query builder pattern. Add comprehensive test coverage for each query type.

**No Rate Limiting on Critical Endpoints:**
- Issue: Rate limiter middleware exists but is opt-in; many endpoints don't use it (e.g., `/auth/login` logs attempts but doesn't block)
- Files: `middleware/rateLimiter.js`, routes using it inconsistently
- Impact: Brute force attacks on login/password reset possible
- Fix approach: Make rate limiting middleware mandatory on all auth endpoints. Configure stricter limits for failed attempts.

**Insufficient Input Validation:**
- Issue: User input like class codes, student IDs validated inconsistently; some routes use `parseInt()` without fallback
- Files: `routes/classes.js` (line 91 -- only checks existence), `routes/sca.js` (line 158 -- casts `req.params.studentId` without validation)
- Impact: Invalid IDs can cause silent failures or incorrect database queries
- Fix approach: Create validation helper module. Validate all user inputs against schema (type, range, format). Return 400 on invalid input.

**No Query Result Validation:**
- Issue: Database queries return null without distinguishing "not found" from "query error"
- Files: `config/database.js` (line 1074 -- `return null` for unmatched queries)
- Impact: Silent data loss; difficult debugging
- Fix approach: Add query result wrapper with success flag. Log unhandled query types. Throw on unknown queries instead of returning null.

**Backup System Lacks Encryption:**
- Issue: Backups stored as plaintext JSON files on disk
- Files: `utils/backupManager.js`, `database/` and `backups/` directories
- Impact: Backups contain plaintext passwords (if encryption disabled) and encrypted data; backup files inherit no additional protection
- Fix approach: Encrypt backup files before writing to disk. Require decryption password or key for restore operations.

**Missing CSRF Protection:**
- Issue: No CSRF tokens in state-changing requests (POST/PUT/DELETE)
- Files: All routes with POST/PUT/DELETE handlers
- Impact: Cross-site request forgery attacks possible (especially in classroom/shared environment)
- Fix approach: Add `csrf` middleware. Include token in all form submissions and AJAX requests.

**Audit Logging Optional and Incomplete:**
- Issue: Audit logging guarded by `if (req.securitySettings.audit_logging)` throughout codebase; many sensitive actions not logged
- Files: `routes/admin.js`, `routes/classes.js`, `middleware/audit.js`
- Impact: If logging disabled, no trail of sensitive changes (security setting toggles, data exports, deletions)
- Fix approach: Separate "critical audit events" from "optional audit events". Log critical events (security toggles, data deletion, role changes) regardless of setting.

## Known Bugs

**Database Query Parameter Mismatch:**
- Symptoms: SCA student review endpoints expect specific parameter order; wrong order crashes UPDATE
- Files: `routes/sca.js` (lines 138-142), `config/database.js` (lines 871-884)
- Trigger: POST /sca/findings/:id/review with classification update; parameters in wrong order
- Workaround: Check parameter order in both route handler and database executeSQL before each update

**Route Regex Typo in VM Comments:**
- Symptoms: POST /vm/vulns/:id/comments endpoint unreachable due to typo in route pattern
- Files: `routes/vm.js` (line 220 -- `/vulns:id/comments` missing slash)
- Trigger: Try to post comment on vulnerability; endpoint returns 404
- Workaround: Use direct database insert if route inaccessible; correct route pattern to `/vulns/:id/comments`

**Encryption Key Mismatch on Decryption:**
- Symptoms: If custom encryption key file is deleted while encrypted data exists, data becomes unrecoverable
- Files: `utils/encryption.js` (lines 104-106, 189)
- Trigger: Upload custom key, encrypt SSNs, delete custom key -- SSNs become garbage strings
- Workaround: Never delete custom key file if encrypted data exists. Create backup of key before any operations.

**MFA Secrets Lost on Disable:**
- Symptoms: Disabling MFA globally clears all users' secrets; re-enabling requires users to re-setup from scratch
- Files: `routes/admin.js` (lines 42-55)
- Trigger: Toggle MFA feature off -- all users lose secrets -- toggle on -- must reconfigure
- Workaround: Before disabling MFA, export backup of all active MFA secrets. Store separately for recovery.

## Security Considerations

**RBAC Bypass via Feature Toggle:**
- Risk: When RBAC disabled in security settings, all role checks pass silently with `req.rbacBypass = true`
- Files: `middleware/rbac.js` (lines 13-16)
- Current mitigation: UI disables toggle; logged to audit logs if audit logging enabled
- Recommendations: (1) Log RBAC bypass events with warning level even if audit logging disabled. (2) Require admin password confirmation before disabling RBAC. (3) Add visual warning banner on all pages when RBAC disabled.

**Authorization Check Inconsistency:**
- Risk: `/classes/:id` endpoint allows any authenticated user to view if student enrollment check fails but RBAC is disabled (line 39)
- Files: `routes/classes.js` (lines 39-47)
- Current mitigation: Enrollment check bypassed only if RBAC disabled
- Recommendations: Enforce enrollment check independently of RBAC setting. Split authorization concerns: RBAC governs role-based access; enrollment governs user-specific resource access.

**Session Secret Not Rotated:**
- Risk: Single hardcoded session secret means all session cookies since deployment can be verified/forged with same secret
- Files: `server.js` (line 45)
- Current mitigation: None; secret is hardcoded
- Recommendations: (1) Use environment variable with rotating value. (2) Implement session secret rotation every 30 days. (3) Invalidate all sessions on rotation.

**Default Encryption Key Known to All:**
- Risk: Every instance uses same hardcoded default key; if one key is leaked, all sensitive data across all instances compromised
- Files: `utils/encryption.js` (line 6)
- Current mitigation: BYOK (Bring Your Own Key) option available for admins
- Recommendations: (1) Generate unique encryption key per instance at initialization. (2) Require custom key upload before enabling field encryption. (3) Log all encryption key changes to immutable audit log.

**Plaintext Passwords Possible If Encryption Disabled:**
- Risk: `migratePasswordsToPlaintext()` function in `routes/admin.js` stores passwords as plaintext
- Files: `routes/admin.js` (lines 285-292)
- Current mitigation: Function only called when admin toggles encryption off
- Recommendations: (1) Remove plaintext password storage entirely. (2) If encryption must be toggled, use key rotation instead: encrypt with old key, decrypt, re-encrypt with new key. (3) Prevent toggling encryption off once data encrypted.

**Audit Log Size Unbounded (Eventually):**
- Risk: While codebase limits audit logs to 1000 entries (line 541-544), this still leaves unencrypted activity logs on disk
- Files: `config/database.js` (lines 540-545)
- Current mitigation: Logs pruned to 1000 entries; can be exported via audit log API
- Recommendations: (1) Encrypt audit logs at rest. (2) Implement log rotation and archival. (3) Add integrity checks (HMAC) to detect tampering.

**No Prevention of Privilege Escalation via Parameter Manipulation:**
- Risk: If RBAC disabled, students could potentially craft requests to admin endpoints (they would still be rejected if endpoint checks role, but inconsistency is risk)
- Files: Various routes with `requireRole` checks
- Current mitigation: Each endpoint explicitly checks role
- Recommendations: (1) Centralize authorization logic. (2) Whitelist safe endpoints in RBAC bypass mode. (3) Log all bypass instances prominently.

## Performance Bottlenecks

**N+1 Query Pattern in View Rendering:**
- Problem: Class detail page fetches class, then loops over students to fetch enrollment for each (line 58-64 in classes.js)
- Files: `routes/classes.js` (lines 51-64)
- Cause: Database returns whole enrollment objects; code joins separately for each student
- Improvement path: Use database JOIN in single query or batch fetch enrollments for all students at once

**Full Table Scans on Every Query:**
- Problem: JSON database filters in-memory arrays with `.filter()` and `.find()` for every query
- Files: `config/database.js` (lines 164-453)
- Cause: No indexes; custom database must iterate all records
- Improvement path: Add in-memory index map (hash by common query fields like student_id, class_id) for O(1) lookups instead of O(n)

**Synchronous File I/O Blocks Event Loop:**
- Problem: Database loads entire JSON file into memory on each save; no async handling
- Files: `config/database.js` (lines 133-141)
- Cause: `fs.writeFileSync()` and `fs.readFileSync()` block execution
- Improvement path: Use `fs.promises` for async read/write. Implement write queue to batch frequent saves.

**Classroom Manager Polls All Instances Every 30/60 Seconds:**
- Problem: Dashboard polls `/api/health` on all instances every 30s, `/api/summary` every 60s with staggered 100ms delays
- Files: `scripts/classroom-manager.js` (lines 953-967)
- Cause: No push notifications; polling overhead scales with team count
- Improvement path: Implement WebSocket connection for real-time updates. Fall back to polling only on connection loss.

**Dashboard HTML Regenerated for Every Request:**
- Problem: `dashboardHTML()` function generates entire HTML page as string on each GET /
- Files: `scripts/classroom-manager.js` (lines 450-809)
- Cause: No caching; HTML re-rendered even if data unchanged
- Improvement path: Cache static HTML template. Inject dynamic data via JSON endpoint. Use client-side templating.

## Fragile Areas

**Custom SQL Parser in Database Handler:**
- Files: `config/database.js` (lines 160-1074)
- Why fragile: String-matching SQL detection (`sql.includes('FROM users')`) is brittle. New queries need careful insertion in right place. Easy to miss edge cases or duplicate logic.
- Safe modification: (1) Add comprehensive test for new query before implementing. (2) Use regex pattern matching instead of string contains. (3) Refactor into separate handler per resource type.
- Test coverage: None detected for database module (no test file for database.js)

**RBAC Bypass Flag Spread Across Codebase:**
- Files: `middleware/rbac.js` (line 15), routes like `routes/admin.js` (line 27), views using `rbacBypass` variable
- Why fragile: Bypass flag checked inconsistently; some endpoints ignore it, others rely on it
- Safe modification: (1) Define explicit list of endpoints that allow bypass. (2) Create wrapper middleware that enforces bypass policy. (3) Test both RBAC on/off modes for each endpoint.
- Test coverage: No test coverage for RBAC bypass behavior

**Encryption Key Loading on Module Import:**
- Files: `utils/encryption.js` (line 189 -- `currentEncryptionKey = loadCustomKey()` at module level)
- Why fragile: Key loaded synchronously during require; if key file deleted after this module loads, old key persists until module reload
- Safe modification: (1) Add validation that key file still exists before encrypt/decrypt. (2) Load key on first use instead of module init. (3) Add key validity check endpoint that admin can call.
- Test coverage: No tests for key rotation or missing key scenarios

**Session Storage Hardcoded to Default Memory Store:**
- Files: `server.js` (line 44 -- `express-session` default store)
- Why fragile: Session data lost on server restart; classroom manager spawns new instances, losing all active sessions
- Safe modification: (1) Implement persistent session store (JSON file or SQLite). (2) Store team-specific sessions in instance-specific directory. (3) Add session migration on instance restart.
- Test coverage: No tests for multi-instance session handling

**Backup Restore Without Verification:**
- Files: `utils/backupManager.js` (restore function), `routes/admin.js` (line 473-492)
- Why fragile: Restores backup directly to data.json without validation that backup file is legitimate or not corrupted
- Safe modification: (1) Validate backup file structure before restore. (2) Create safety backup of current data before restore. (3) Add checksum verification. (4) Require admin to confirm before destructive restore.
- Test coverage: No tests for backup restore edge cases (missing file, corrupt JSON, partial restore failure)

## Scaling Limits

**In-Memory Database Capacity:**
- Current capacity: Tested with 100+ findings, 50+ students, 10+ classes in seedData; all held in one process memory
- Limit: Process will exhaust memory around 500MB of JSON data (estimated 50k+ records)
- Scaling path: (1) Migrate to SQLite for classroom-scale (unlimited). (2) Implement pagination/lazy loading in routes. (3) Archive old records to separate file. (4) Use clustering with shared data store for multi-process.

**Single-Process Event Loop Bottleneck:**
- Current capacity: Classroom manager spawns 1 process per team; each team instance is single-threaded Node.js
- Limit: ~50-100 concurrent requests per instance before noticeable slowdown due to blocking file I/O
- Scaling path: (1) Implement worker threads for file I/O. (2) Add reverse proxy (nginx) with caching. (3) Use connection pooling for database. (4) Offload heavy computations (hash password, encryption) to worker pool.

**File I/O Serialization:**
- Current capacity: Every database mutation triggers atomic write (`writeFileSync` then `renameSync`). At ~50 mutations/second, file I/O becomes bottleneck
- Limit: Real bottleneck around 100+ concurrent users doing mutations (e.g., all students submitting findings simultaneously)
- Scaling path: (1) Batch writes: queue mutations, flush to disk every 5s or after 100 mutations. (2) Use append-only log with periodic snapshots. (3) Migrate to database with write batching.

**Dashboard Polling Overhead:**
- Current capacity: Classroom manager can manage ~20 teams with 30s/60s polling intervals without excessive CPU
- Limit: 50+ teams will cause noticeable lag in dashboard updates and increased server load
- Scaling path: (1) Implement WebSocket for push updates. (2) Reduce polling frequency (60s/120s). (3) Client-side caching with exponential backoff on stale data.

## Dependencies at Risk

**express-session with Default In-Memory Store:**
- Risk: Sessions lost on restart; no sharing across instances; test data reset between sessions in classroom mode
- Impact: Teachers see empty classrooms if instances restart; students' work lost
- Migration plan: (1) Replace with persistent file-based store (sessionFileStore). (2) Store sessions in instance DATA_DIR so they survive restart. (3) Implement inter-process session sync for multi-team scenarios.

**Custom JSON Database vs. SQLite:**
- Risk: JSON database will become unmaintainable above 1000 records; no query optimization, no schema validation, brittle string-matching SQL
- Impact: New features (complex queries, analytics) become difficult; performance degrades; data integrity at risk
- Migration plan: (1) Create SQLite schema matching current JSON structure. (2) Write data migration script (JSON to SQLite). (3) Update all route handlers to use sqlite3 client instead of custom db interface. (4) Gradual migration: support both backends, deprecate JSON backend.

**speakeasy (TOTP) Library:**
- Risk: speakeasy v2.0.0 is old (2018); newer versions have better HMAC-SHA256 support; no active maintenance
- Impact: Potential cryptographic weaknesses in OTP generation; backup codes not implemented
- Migration plan: (1) Evaluate otplib or speakeasy v3+. (2) Implement backup codes as separate field. (3) Test OTP generation against test vectors.

**selfsigned (SSL Certificate Generation):**
- Risk: selfsigned library used for self-signed HTTPS in dev; in production, custom certificates must be provided
- Impact: Classroom HTTPS requires pre-generated certificates; no automation for cert rotation
- Migration plan: (1) Document custom certificate setup. (2) Use Let's Encrypt with auto-renewal for production. (3) Add certificate expiry check and warning in admin panel.

## Missing Critical Features

**No Password Complexity Requirements:**
- Problem: Users can set single-character passwords; no minimum entropy enforced
- Blocks: Cannot meet NIST password guidance; weak passwords vulnerable to brute force
- Improvement: (1) Enforce minimum 12 characters or passphrase. (2) Check against common password list. (3) Reject passwords that match username or email. (4) Add password strength meter.

**No Account Lockout After Failed Attempts:**
- Problem: Rate limiting exists but doesn't lock accounts; brute force on known usernames possible
- Blocks: Cannot prevent credential stuffing attacks; each account can endure unlimited login attempts
- Improvement: (1) Lock account after 5 failed attempts for 15 minutes. (2) Require email verification to unlock. (3) Notify user of failed attempts. (4) Add progressive delays (exponential backoff) on retries.

**No Session Invalidation on Security Change:**
- Problem: If admin disables MFA, user sessions remain active with old MFA state; if encryption toggled, no re-encryption of existing data
- Blocks: Cannot implement security policy enforcement (e.g., "all users must use MFA"); stale user sessions can exploit new settings
- Improvement: (1) Clear all sessions on global security setting change. (2) Force re-authentication after security update. (3) Add session-level security tag (e.g., "mfa-verified-at") and invalidate if requirements change.

**No Data Export or Deletion API:**
- Problem: Instructors cannot export student data (grades, progress); students cannot request data deletion (GDPR)
- Blocks: Cannot comply with privacy regulations; students stuck with accounts
- Improvement: (1) Implement CSV/JSON export for instructors. (2) Add student data export endpoint. (3) Implement account deletion with 30-day recovery window. (4) Add audit trail for all exports/deletions.

**No Timezone Handling:**
- Problem: All times stored and displayed in ISO 8601 UTC; no user-configurable timezone
- Blocks: Classroom in different timezones shows confusing times to students (e.g., "due at 14:00 UTC" vs. expected local time)
- Improvement: (1) Store user timezone in profile. (2) Display times in user's local timezone. (3) Store all times in UTC internally. (4) Add timezone picker in settings.

**No Multi-Language Support Implemented:**
- Problem: i18n middleware exists (`utils/i18n.js`) but only English strings used; no translation files
- Blocks: Classroom cannot serve non-English instructors or students
- Improvement: (1) Extract all strings to translation files (i18n JSON). (2) Add language picker in header. (3) Implement language switching without page reload. (4) Test with at least Spanish, French, Mandarin.

## Test Coverage Gaps

**Database Module Completely Untested:**
- What's not tested: Query parsing, parameter binding, JOIN logic, edge cases (null values, empty results, duplicate records)
- Files: `config/database.js` (entire module)
- Risk: New queries break silently; data corruption undetected
- Priority: High -- database is critical path for all features

**RBAC Bypass Mode Not Tested:**
- What's not tested: Behavior of each endpoint with RBAC on vs. off; authorization logic when bypass enabled
- Files: `middleware/rbac.js`, all route files
- Risk: Authorization bugs only discovered in production or when instructors toggle RBAC
- Priority: High -- security-critical

**Encryption/Decryption Edge Cases:**
- What's not tested: Decryption with wrong key, corruption in encrypted data, key rotation, double-encryption prevention
- Files: `utils/encryption.js`
- Risk: Data loss or corruption during encryption operations; silent failures
- Priority: High -- data integrity depends on this

**Backup/Restore Flow:**
- What's not tested: Restore from corrupted backup, restore from old backup during active session, frequency change during backup
- Files: `utils/backupManager.js`
- Risk: Restores fail or corrupt data; admin has no visibility into issues
- Priority: Medium -- affects data recovery

**Multi-Instance Session Handling:**
- What's not tested: Session persistence across team instance resets; behavior when classroom manager restarts
- Files: `scripts/classroom-manager.js`, session store integration
- Risk: Students lose sessions during classroom demo; session data lost
- Priority: Medium -- affects classroom experience

---

*Concerns audit: 2026-03-12*
