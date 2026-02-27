# Classroom QA Report: Potential Issues That Could Derail a Live Demo

## Summary

22 issues identified across 6 categories that could disrupt a live classroom demonstration. Issues are ordered by severity and likelihood of occurring during a demo.

---

## CATEGORY 1: Data Corruption When Toggling Security Features

### Issue 1 — Partial password migration corrupts login
- **File:** `routes/admin.js:231-244`
- **Severity:** Critical
- **Trigger:** Toggle `encryption_at_rest` ON when bcrypt encounters an error mid-migration
- **Impact:** Some users have hashed passwords, others plaintext. Login breaks for partially-migrated users. Demo is unrecoverable without re-seeding.
- **Mitigation:** Run `npm run setup` to re-seed the database. Avoid toggling encryption_at_rest more than once per demo.

### Issue 2 — Encryption key rotation destroys encrypted data
- **File:** `routes/admin.js:470-506`, `utils/encryption.js`
- **Severity:** Critical
- **Trigger:** Upload a custom BYOK key while field_encryption is OFF, then toggle field_encryption back ON
- **Impact:** Data encrypted with the old key cannot be decrypted with the new key. `decrypt()` silently returns encrypted ciphertext, which then gets double-encrypted. Permanent data loss.
- **Mitigation:** Never change the encryption key after data has been encrypted. If you must demo BYOK, do it before any encryption toggle.

### Issue 3 — Toggling encryption on/off repeatedly corrupts data
- **File:** `routes/admin.js:261-298`, `utils/encryption.js:148-165`
- **Severity:** Critical
- **Trigger:** Toggle field_encryption ON → OFF → ON → OFF multiple times
- **Impact:** Each failed decryption silently returns encrypted text, which gets re-encrypted on the next toggle. SSNs and grades become permanently unreadable.
- **Mitigation:** Only toggle encryption once per demo session (ON to demonstrate, then leave it).

### Issue 4 — No transactional protection on migration operations
- **File:** `routes/admin.js:42-58`
- **Severity:** High
- **Trigger:** Any error during migration leaves DB in inconsistent state
- **Impact:** Security setting flag and actual data state are out of sync. No rollback mechanism exists.

---

## CATEGORY 2: Server Crashes and Startup Failures

### Issue 5 — Backup restore doesn't reload in-memory database
- **File:** `utils/backupManager.js:99-132`
- **Severity:** Critical
- **Trigger:** Admin restores a backup via the UI
- **Impact:** The file on disk is replaced, but the running app continues using old in-memory data. Changes after restore overwrite the restored file. Appears to do nothing until server restart, at which point post-restore work is lost.
- **Mitigation:** Always restart the server after restoring a backup.

### Issue 6 — Corrupted database silently resets on restart
- **File:** `server.js:19-26`
- **Severity:** High
- **Trigger:** Server crashes during a database write (e.g., power loss, Ctrl+C during save)
- **Impact:** On restart, corrupted JSON causes `loadDatabase()` to fall back to empty DB. `seedDatabase()` runs automatically, wiping all custom data (classes, grades, MFA configs).
- **Mitigation:** Create manual backups before class. Keep a known-good `data.json` copy.

### Issue 7 — JSON database has no file locking
- **File:** `config/database.js:61-67`
- **Severity:** High
- **Trigger:** Two simultaneous requests that both trigger database writes
- **Impact:** Race condition can corrupt `data.json` with partial/interleaved writes.
- **Mitigation:** Avoid having multiple users actively modifying data at the same time.

---

## CATEGORY 3: Authentication & Session Issues

### Issue 8 — HTTPS toggle doesn't actually secure cookies
- **File:** `server.js:265-267`
- **Severity:** Medium
- **Trigger:** Toggle HTTPS ON during demo
- **Impact:** `req.sessionOptions` doesn't exist. Cookie secure flag is never set. Students may lose sessions unpredictably.

### Issue 9 — Rate limiter can lock out the admin
- **File:** `middleware/rateLimiter.js`
- **Severity:** High
- **Trigger:** Multiple failed login attempts from the same IP (all classroom users share localhost)
- **Impact:** Admin gets locked out mid-demo. No UI to reset rate limit counter.
- **Mitigation:** Toggle rate limiting OFF before demonstrating other features if needed.

### Issue 10 — MFA setup can't be undone per-user
- **File:** `routes/admin.js`
- **Severity:** Medium
- **Trigger:** Enable MFA → user sets up authenticator → disable MFA → re-enable MFA
- **Impact:** User's authenticator app may no longer match the stored secret. User is locked out.
- **Mitigation:** If re-enabling MFA, have users re-scan the QR code.

---

## CATEGORY 4: SQL Injection & Security

### Issue 11 — SQL injection in security settings toggle
- **File:** `config/security.js:27`
- **Severity:** Medium (educational context)
- **Detail:** `setting` parameter from user input is interpolated directly into SQL string via template literal.

### Issue 12 — Hardcoded session secret
- **File:** `server.js:44`
- **Severity:** Low (educational context)
- **Detail:** Session secret is hardcoded in source code.

---

## CATEGORY 5: UI/Template Rendering Errors

### Issue 13 — Null rejection_reason crashes deletion requests page
- **File:** `views/admin/deletion-requests.ejs:92`
- **Severity:** High
- **Trigger:** View a rejected deletion request where rejection_reason is null
- **Impact:** Page crashes with `TypeError: Cannot read property 'replace' of null`.

### Issue 14 — Null timestamps show "Invalid Date"
- **File:** `views/admin/dashboard.ejs:60`, `views/admin/audit-logs.ejs:30`
- **Severity:** Low
- **Trigger:** User has never logged in (null `last_login`)
- **Impact:** UI shows "Invalid Date" instead of "Never".

### Issue 15 — Missing securitySettings crashes all pages
- **File:** `views/partials/header.ejs:550-570`
- **Severity:** Medium
- **Trigger:** Any route that fails to load security settings middleware
- **Impact:** Every page renders with an error.

### Issue 16 — Undefined class_code shows "Back to undefined"
- **File:** `views/session-view.ejs:3`
- **Severity:** Low
- **Trigger:** Session object missing `class_code` property
- **Impact:** Navigation link shows "Back to undefined".

---

## CATEGORY 6: Operational Risks During Class

### Issue 17 — Audit log grows unbounded
- **File:** `middleware/audit.js`
- **Severity:** Medium
- **Trigger:** Extended class session with many students
- **Impact:** Database file grows, slowing all operations.

### Issue 18 — Backup schedule fills disk
- **File:** `utils/backupManager.js:147-153`
- **Severity:** Low
- **Trigger:** Backup enabled at 5-minute frequency during long class
- **Impact:** Many large backup files created.

### Issue 19 — No CSRF protection on forms
- **File:** Multiple view templates
- **Severity:** Medium (educational context)

### Issue 20 — Empty catch blocks hide DAST lab errors
- **File:** `views/dast/student-lab.ejs:26`
- **Severity:** Low
- **Trigger:** Malformed DAST scenario data
- **Impact:** Empty steps shown with no error indication.

### Issue 21 — Translation keys shown as raw text
- **File:** `utils/i18n.js:7-20`
- **Severity:** Medium
- **Trigger:** Translation files fail to load
- **Impact:** UI shows keys like "sod.requestDeletion" instead of translated text.

### Issue 22 — XSS in onclick handlers
- **File:** `views/admin/deletion-requests.ejs:43`
- **Severity:** Medium
- **Trigger:** Special characters in request.code field

---

## Pre-Class Checklist

- [ ] Run `npm run setup` to get a clean database
- [ ] Run `npm test` to verify all routes respond
- [ ] Verify `node_modules` is fully installed (`npm install`)
- [ ] Create a manual backup of `database/data.json` after setup
- [ ] Plan encryption toggles — only toggle ON once per demo
- [ ] Do NOT upload a custom BYOK key if data is already encrypted
- [ ] Test MFA flow end-to-end before class (have authenticator app ready)
- [ ] Keep a terminal visible to watch for console errors
- [ ] Restart the server after any backup restore
- [ ] If rate limiting is ON, be careful with failed login demos
