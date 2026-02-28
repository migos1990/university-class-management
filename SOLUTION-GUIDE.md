# Solution Guide for Instructors

## HEC Montreal — Application Security Platform

This guide is designed so that any new instructor can pick up the platform and teach the full Application Security curriculum from day one. It covers every module in the system: the 10 toggleable security features, the 4 hands-on security labs, and the classroom management infrastructure.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Platform Architecture Overview](#2-platform-architecture-overview)
3. [User Accounts and Roles](#3-user-accounts-and-roles)
4. [Course Modules (CS101, CS201, CS301)](#4-course-modules)
5. [Module: Multi-Factor Authentication (MFA)](#5-module-multi-factor-authentication-mfa)
6. [Module: Role-Based Access Control (RBAC)](#6-module-role-based-access-control-rbac)
7. [Module: Password Encryption (Encryption at Rest)](#7-module-password-encryption)
8. [Module: Field Encryption (AES-256-CBC)](#8-module-field-encryption-aes-256-cbc)
9. [Module: HTTPS/TLS (Encryption in Transit)](#9-module-httpstls-encryption-in-transit)
10. [Module: Audit Logging](#10-module-audit-logging)
11. [Module: Rate Limiting](#11-module-rate-limiting)
12. [Module: Segregation of Duties](#12-module-segregation-of-duties)
13. [Module: Database Backups](#13-module-database-backups)
14. [Module: Bring Your Own Key (BYOK)](#14-module-bring-your-own-key-byok)
15. [Lab: Static Code Analysis (SCA)](#15-lab-static-code-analysis-sca)
16. [Lab: Dynamic Application Security Testing (DAST)](#16-lab-dynamic-application-security-testing-dast)
17. [Lab: Vulnerability Manager (VM)](#17-lab-vulnerability-manager-vm)
18. [Lab: Penetration Testing (Pentest)](#18-lab-penetration-testing-pentest)
19. [Classroom Management](#19-classroom-management)
20. [Pre-Class Checklist](#20-pre-class-checklist)
21. [Troubleshooting](#21-troubleshooting)
22. [Appendix: Known Issues and Workarounds](#22-appendix-known-issues-and-workarounds)

---

## 1. Getting Started

### GitHub Codespaces (Recommended)

1. From the GitHub repository, click the green **Code** button and select the **Codespaces** tab.
2. Click **Create codespace on main**.
3. Wait for the container to build. Setup runs automatically (`npm install`, database seeding, SSL certificate generation).
4. The app starts automatically. When port **3000** is detected, click **Open in Browser** to access the **Instructor Dashboard**.
5. Team instances run on ports 3001-3012 and are labeled in the Ports tab.

**Useful Codespaces tips:**
- To share a team instance with students, right-click a port in the Ports tab and set visibility to **Public**.
- To run fewer teams (saves memory): stop the app, then run `TEAM_COUNT=4 npm start`.

### Running Locally

```bash
# Prerequisites: Node.js LTS v18+
npm install
npm run setup    # Initialize database, seed data, generate SSL certificates
npm start        # Launch instructor dashboard + all team instances
```

### Verifying the Setup

```bash
npm test         # Runs smoke tests against Team Alpha (port 3001)
```

This generates a `test-report.html` with pass/fail status for all login flows and page access.

---

## 2. Platform Architecture Overview

```
Port 3000  ->  Instructor Dashboard (monitor all teams, broadcast messages)
Port 3001  ->  Team Alpha   (isolated database + app instance)
Port 3002  ->  Team Bravo   (isolated database + app instance)
...
Port 3012  ->  Team Lima    (isolated database + app instance)
```

Each team instance is fully isolated with its own database, SSL certificates, and security settings. Changes students make in one instance do not affect others.

**Key directories:**
| Directory | Purpose |
|-----------|---------|
| `routes/` | All API endpoints (auth, admin, classes, labs) |
| `middleware/` | Auth, RBAC, audit logging, rate limiting |
| `config/` | Database engine, security settings |
| `utils/` | Encryption, password hashing, backups, seed data |
| `views/` | All EJS templates organized by module |
| `scripts/` | Classroom manager, setup, smoke tests |

---

## 3. User Accounts and Roles

### Default Credentials

| Username | Password | Role | Notes |
|----------|----------|------|-------|
| `admin` | `admin123` | Admin | Full access to all features and security panel |
| `prof_jones` | `prof123` | Professor | Owns CS101 and CS301 |
| `prof_smith` | `prof123` | Professor | Owns CS201 |
| `alice_student` | `student123` | Student | Enrolled in CS101, CS201 |
| `bob_student` | `student123` | Student | Enrolled in CS101, CS301 |
| `charlie_student` | `student123` | Student | Enrolled in CS201, CS301 |
| `diana_student` | `student123` | Student | Enrolled in CS101 |
| `eve_student` | `student123` | Student | Enrolled in CS201, CS301 |

### Role Permissions

| Capability | Admin | Professor | Student |
|------------|:-----:|:---------:|:-------:|
| Toggle security features | Yes | No | No |
| Manage backups and keys | Yes | No | No |
| Approve/reject deletion requests | Yes | No | No |
| View audit logs | Yes | No | No |
| Create/edit classes | Yes | Yes (own) | No |
| Request class deletion (SoD) | N/A | Yes | No |
| Review student lab work | Yes | Yes | No |
| Grade lab submissions | Yes | Yes | No |
| Access security labs | Yes | Yes | Yes |
| Submit lab findings | No | No | Yes |

---

## 4. Course Modules

The platform ships with three pre-seeded courses, each with 12 sessions:

### CS101 — Introduction to Programming (Prof. Jones)
Sessions cover Python basics through OOP: variables, control flow, loops, functions, lists, dictionaries, file I/O, error handling, modules, and a final project.

### CS201 — Data Structures (Prof. Smith)
Sessions cover arrays, linked lists, stacks, queues, recursion, trees, balanced trees, heaps, hash tables, graphs, graph algorithms, and algorithm analysis.

### CS301 — Application Security (Prof. Jones)
This is the primary course for the platform. Sessions map directly to the toggleable features:

| Session | Topic | Platform Module |
|---------|-------|-----------------|
| 1 | Introduction to Application Security | Overview of all toggles |
| 2 | Authentication Basics | Password Encryption toggle |
| 3 | Multi-Factor Authentication | MFA toggle |
| 4 | Authorization and Access Control | RBAC toggle |
| 5 | Encryption Fundamentals | Field Encryption toggle |
| 6 | Encryption in Transit | HTTPS/TLS toggle |
| 7 | Encryption at Rest | Field Encryption + BYOK |
| 8 | OWASP Top 10: Injection | SCA + DAST labs |
| 9 | OWASP Top 10: XSS and CSRF | DAST lab (CSRF scenario) |
| 10 | Session Management | Audit Logging toggle |
| 11 | Security Monitoring | Audit Logging + Rate Limiting |
| 12 | Security Best Practices | All modules combined |

---

## 5. Module: Multi-Factor Authentication (MFA)

### Learning Objective
Students understand why a second authentication factor matters and observe the TOTP (Time-based One-Time Password) flow in practice.

### How It Works
- **Toggle location:** Admin → Security Panel → "Multi-Factor Authentication"
- **Scope:** Applies to admin accounts only at login time
- **Technology:** TOTP using the `speakeasy` library + Google Authenticator
- **Code:** `routes/admin.js` (MFA setup/verify), `routes/auth.js:58-62` (login redirect to MFA)

### Teaching Flow

1. **Before enabling (insecure state):**
   - Log in as `admin` / `admin123` — direct access with just a password.
   - Discuss: What if someone steals or guesses the password?

2. **Enable MFA:**
   - Go to Admin → Security Panel → toggle MFA ON.
   - Navigate to Admin → MFA Setup.
   - A QR code appears. Scan it with Google Authenticator (or any TOTP app).
   - Enter the 6-digit code from the app to complete setup.

3. **Demonstrate the secured flow:**
   - Log out and log back in as `admin`.
   - After entering the correct password, you are redirected to an MFA verification page.
   - Enter the current 6-digit TOTP code from your authenticator app.
   - Only after both factors are verified does the session start.

4. **Discussion points:**
   - What are the three authentication factors? (Something you know, have, are)
   - Why is TOTP time-based? (Codes expire every 30 seconds)
   - What is the `window: 2` parameter? (Allows clock skew of +/- 60 seconds)
   - What happens if you lose your phone? (Discuss backup codes and recovery)

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/admin.js` | 140-172 | MFA setup: generates secret, creates QR code |
| `routes/admin.js` | 179-218 | MFA verification: validates TOTP code, saves secret |
| `routes/auth.js` | 58-62 | Login check: redirects admin to MFA if enabled |
| `routes/auth.js` | 102-157 | MFA verify page: validates code, creates session |

### Expected Answer / What Students Should Observe
- Without MFA: password alone grants full admin access.
- With MFA: a stolen password is insufficient; the attacker also needs the physical device with the authenticator app.
- The QR code encodes an `otpauth://` URI containing the shared secret.

---

## 6. Module: Role-Based Access Control (RBAC)

### Learning Objective
Students understand how access control restricts actions based on user roles, and what happens when access control is disabled.

### How It Works
- **Toggle location:** Admin → Security Panel → "Role-Based Access Control"
- **Default state:** ON
- **Technology:** Express middleware that checks `req.session.user.role` against an allowed-roles list
- **Code:** `middleware/rbac.js` (58 lines)

### Teaching Flow

1. **With RBAC ON (secure):**
   - Log in as `alice_student`. Navigate to `/admin/security`. Result: 403 Forbidden.
   - Log in as `prof_jones`. Navigate to `/admin/security`. Result: 403 Forbidden.
   - Log in as `admin`. Navigate to `/admin/security`. Result: Full access.
   - Discuss: each role sees only what it is authorized to see.

2. **Disable RBAC:**
   - As admin, toggle RBAC OFF in the Security Panel.
   - Log in as `alice_student` again. Navigate to `/admin/security`. Result: **Access granted** — the student can now see (and potentially toggle) admin-only security features.
   - Try accessing other students' grades by changing IDs in the URL.

3. **Discussion points:**
   - Principle of Least Privilege: users should only have access to what they need.
   - Horizontal vs. vertical privilege escalation.
   - Why RBAC should never be the only line of defense (defense in depth).
   - The IDOR vulnerability that appears when RBAC is off (see DAST Scenario 1).

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `middleware/rbac.js` | 1-58 | `requireRole()` middleware factory; checks role against allowed list |
| `routes/classes.js` | 33-47 | Enrollment check that depends on `rbac_enabled` |

### Expected Answer / What Students Should Observe
- With RBAC ON: each role is confined to its authorized pages and API endpoints.
- With RBAC OFF: any authenticated user can access any endpoint, including admin functions. This demonstrates why authorization must be enforced server-side.

---

## 7. Module: Password Encryption

### Learning Objective
Students understand the difference between storing passwords in plaintext vs. hashed form, and why hashing matters.

### How It Works
- **Toggle location:** Admin → Security Panel → "Password Encryption"
- **Technology:** bcrypt with 10 salt rounds via `utils/passwordHash.js`
- **Migration:** When toggled ON, all existing plaintext passwords are hashed. When toggled OFF, the `password_is_hashed` flag is reset (original plaintext passwords remain in the `password` column).
- **Code:** `routes/admin.js:245-292` (migration functions)

### Teaching Flow

1. **Before enabling (insecure state):**
   - Open the database file: `instances/team-N/database/data.json`
   - Find the `users` array. Observe that the `password` field contains plaintext: `admin123`, `prof123`, `student123`.
   - Discuss: if an attacker gains database access, every password is immediately exposed.

2. **Enable password encryption:**
   - As admin, toggle "Password Encryption" ON in the Security Panel.
   - Reopen the database file. The `password_hash` field now contains bcrypt hashes like `$2b$10$xK3...`.
   - The `password_is_hashed` flag is set to `1`.
   - Log in as any user — authentication still works because `routes/auth.js` uses `bcrypt.compare()`.

3. **Disable password encryption:**
   - Toggle OFF. The `password_is_hashed` flag resets to `0`.
   - Login falls back to direct string comparison (`password === user.password`).

4. **Discussion points:**
   - What is a salt and why does bcrypt include one?
   - Why can't you "decrypt" a bcrypt hash? (One-way function)
   - What is the cost factor (`10` rounds) and how does it affect brute-force resistance?
   - Rainbow table attacks and why salting defeats them.

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `utils/passwordHash.js` | all | `hashPassword()` and `comparePassword()` wrappers around bcrypt |
| `routes/admin.js` | 245-280 | `migratePasswordsToHashed()` — bulk hash with rollback |
| `routes/admin.js` | 285-292 | `migratePasswordsToPlaintext()` — revert flag |
| `routes/auth.js` | 32-39 | Login: branches on `password_is_hashed` flag |

### Expected Answer / What Students Should Observe
- Plaintext: `password: "admin123"` — directly readable.
- Hashed: `password_hash: "$2b$10$xK3yR..."` — unreadable, different each time due to random salt.
- Authentication still works because bcrypt.compare() verifies the password against the hash.

---

## 8. Module: Field Encryption (AES-256-CBC)

### Learning Objective
Students understand encryption at rest for sensitive data fields (PII) and how AES symmetric encryption works.

### How It Works
- **Toggle location:** Admin → Security Panel → "Data Encryption"
- **Technology:** AES-256-CBC using Node.js built-in `crypto` module
- **Fields encrypted:** SSN (users table) and grades (enrollments table)
- **Key:** Default `university-app-secret-key-32!` (32 bytes for AES-256), replaceable via BYOK
- **Format:** Encrypted values stored as `IV:ciphertext` (Base64-encoded)
- **Code:** `utils/encryption.js` (200 lines)

### Teaching Flow

1. **Before enabling:**
   - Inspect the database. Find `alice_student` with SSN `111-22-3333` and her grade `A` in CS101.
   - Both values are in plaintext — any database breach exposes PII.

2. **Enable field encryption:**
   - Toggle "Data Encryption" ON.
   - Reopen the database. SSN now looks like `a3f2b1...:8c4e5d...` and grade is similarly encrypted.
   - The `ssn_encrypted` and `grade_encrypted` flags are set to `1`.
   - The application still displays the correct values because it decrypts on read.

3. **Disable field encryption:**
   - Toggle OFF. Values are decrypted back to plaintext.

4. **Discussion points:**
   - What is AES-256-CBC? (Advanced Encryption Standard, 256-bit key, Cipher Block Chaining mode)
   - What is an IV (Initialization Vector) and why is it random per encryption? (Prevents identical plaintexts from producing identical ciphertexts)
   - What happens if the encryption key is lost? (Data is permanently unrecoverable)
   - Why is the key hardcoded in the source code a vulnerability? (See SCA finding #2)

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `utils/encryption.js` | all | `encrypt()` / `decrypt()` functions, key loading, BYOK support |
| `routes/admin.js` | 297-366 | `encryptSensitiveFields()` / `decryptSensitiveFields()` with rollback |

### Expected Answer / What Students Should Observe
- Plaintext: `ssn: "111-22-3333"`, `grade: "A"`
- Encrypted: `ssn: "f4a3...:9b2c..."`, `grade: "1e8f...:3d7a..."`
- The app displays decrypted values normally — encryption is transparent to the user.

### Important Caveat
> **Warning:** Do not toggle encryption on and off repeatedly in a single session. See [Known Issues](#22-appendix-known-issues-and-workarounds) for details.

---

## 9. Module: HTTPS/TLS (Encryption in Transit)

### Learning Objective
Students understand why data in transit must be encrypted and observe the difference between HTTP and HTTPS.

### How It Works
- **Toggle location:** Admin → Security Panel → "HTTPS/TLS"
- **Technology:** Self-signed SSL certificates generated during `npm run setup` (using `selfsigned` library)
- **Requires:** Server restart after toggling
- **Code:** `server.js` (HTTP/HTTPS server creation logic)

### Teaching Flow

1. **Before enabling:**
   - The app runs on HTTP. Open browser DevTools → Network tab.
   - Submit a login form. Observe the POST request — credentials are sent in plaintext.
   - Discuss: on a shared Wi-Fi network, anyone can capture these credentials.

2. **Enable HTTPS:**
   - Toggle HTTPS ON. The app shows a message: "Please restart the server."
   - After restart, the app runs on HTTPS with a self-signed certificate.
   - The browser shows a "Not Secure" warning because the certificate is self-signed (expected in a classroom setting).

3. **Discussion points:**
   - What does TLS protect? (Confidentiality and integrity of data in transit)
   - What is a self-signed certificate vs. a CA-signed certificate?
   - What is a man-in-the-middle (MITM) attack?
   - Why do browsers show warnings for self-signed certificates?
   - What is HSTS and why is it important?

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `server.js` | (HTTP/HTTPS logic) | Creates HTTP or HTTPS server based on toggle |
| `ssl/` directory | Generated | Contains self-signed certificate and private key |

### Expected Answer / What Students Should Observe
- HTTP: credentials visible in network traffic; URL bar shows "Not Secure."
- HTTPS: traffic is encrypted; URL bar shows a lock icon (with a warning for self-signed certs).

---

## 10. Module: Audit Logging

### Learning Objective
Students understand why security event logging is essential for detection, investigation, and compliance.

### How It Works
- **Toggle location:** Admin → Security Panel → "Audit Logging"
- **Default state:** OFF (intentionally — demonstrates the risk of not logging)
- **Storage:** `audit_logs` table in the JSON database (auto-pruned to 1000 entries)
- **Events logged:** LOGIN, LOGOUT, MFA_ENABLED, MFA_DISABLED, TOGGLE_SECURITY, VIEW_CLASS, CREATE_CLASS, DELETE_CLASS, MANUAL_BACKUP, RESTORE_BACKUP, and more
- **Code:** `middleware/audit.js` (81 lines)

### Teaching Flow

1. **Before enabling:**
   - Log in, navigate around, log out. Go to Admin → Audit Logs.
   - The log is empty — no actions were recorded.
   - Discuss: if an attacker compromises the system, there is no evidence of what happened.

2. **Enable audit logging:**
   - Toggle ON. Perform several actions: log in as different users, view classes, toggle another security feature.
   - Go to Admin → Audit Logs. All actions are now recorded with timestamp, user, role, action type, IP address, and details.

3. **Discussion points:**
   - What events should always be logged? (Authentication, authorization failures, data access, privilege changes)
   - What should NOT be logged? (Passwords, tokens, PII — see SCA finding #3 about credentials in logs)
   - How do audit logs support incident response and forensics?
   - What is log tampering and how can you protect log integrity?
   - Regulatory requirements (SOX, HIPAA, GDPR) that mandate audit trails.

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `middleware/audit.js` | 1-81 | `auditLog()` middleware factory, `logAuthAttempt()` helper |
| `routes/admin.js` | 112-134 | Audit log viewer with pagination |

### Expected Answer / What Students Should Observe
- With logging OFF: no record of any activity — an attacker could operate undetected.
- With logging ON: every action creates a timestamped entry with who, what, when, and from where.

---

## 11. Module: Rate Limiting

### Learning Objective
Students understand brute-force attacks and how rate limiting mitigates them.

### How It Works
- **Toggle location:** Admin → Security Panel → "Rate Limiting"
- **Threshold:** 5 failed login attempts per 15-minute window, per IP address
- **Code:** `middleware/rateLimiter.js` (88 lines)
- **Escape hatch:** Admin → Security Panel → "Reset Rate Limits" button

### Teaching Flow

1. **Before enabling:**
   - Attempt to log in with the wrong password 20 times in a row.
   - Every attempt gets the same "Invalid username or password" message — no lockout.
   - Discuss: an attacker can automate millions of password guesses.

2. **Enable rate limiting:**
   - Toggle ON. Attempt 6+ failed logins.
   - After the 5th failure, the response changes to: "Too many login attempts. Please try again in X minutes."
   - Even the correct password is rejected during the lockout window.

3. **Discussion points:**
   - What is a brute-force attack? What is credential stuffing?
   - Why is IP-based rate limiting imperfect? (Shared IPs, VPNs, botnets)
   - What are better alternatives? (Account lockout, CAPTCHA, progressive delays, device fingerprinting)
   - What about the MFA endpoint? (It has no rate limiting — see DAST Scenario 4)

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `middleware/rateLimiter.js` | 1-88 | `checkRateLimit` and `recordLoginAttempt` functions |
| `routes/admin.js` | 759-776 | Rate limit reset endpoint |

### Expected Answer / What Students Should Observe
- Without rate limiting: unlimited login attempts with no consequence.
- With rate limiting: after 5 failures, the IP is locked out for 15 minutes. This makes automated attacks impractical (but not impossible with distributed attackers).

---

## 12. Module: Segregation of Duties

### Learning Objective
Students understand the principle that no single individual should control all aspects of a critical process.

### How It Works
- **Toggle location:** Admin → Security Panel → "Segregation of Duties"
- **Workflow:** When SoD is ON, professors cannot directly delete classes. They must submit a deletion request. An admin must then approve or reject it (with a reason for rejection).
- **Code:** `routes/classes.js:169-307` (deletion + request flow), `routes/admin.js:613-753` (approval/rejection)

### Teaching Flow

1. **Before enabling:**
   - Log in as `prof_jones`. Navigate to a class. Click delete. The class is immediately deleted.
   - Discuss: a disgruntled or compromised professor could destroy all course data.

2. **Enable Segregation of Duties:**
   - Toggle ON. Log in as `prof_jones`. Attempt to delete a class.
   - Instead of immediate deletion, the professor sees a "Submit Deletion Request" form.
   - Submit the request.
   - Log in as `admin`. Go to Admin → Deletion Requests. The pending request is displayed.
   - Approve or reject it (rejection requires a reason).

3. **Discussion points:**
   - What is Segregation of Duties? (A control that requires more than one person to complete a critical action)
   - Where is SoD used in the real world? (Banking: maker/checker, code review: author/reviewer, infrastructure: change advisory boards)
   - How does SoD relate to the principle of least privilege?
   - What audit trail is created by the approval/rejection workflow?

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/classes.js` | 169-207 | DELETE endpoint: checks SoD and blocks professors |
| `routes/classes.js` | 212-307 | Deletion request form and submission |
| `routes/admin.js` | 613-633 | Deletion request list view |
| `routes/admin.js` | 639-753 | Approve and reject endpoints |

### Expected Answer / What Students Should Observe
- Without SoD: professors can delete classes immediately with no oversight.
- With SoD: deletion requires a two-person workflow (professor requests, admin approves), creating an audit trail and preventing unilateral destructive actions.

---

## 13. Module: Database Backups

### Learning Objective
Students understand the importance of backups for data recovery and business continuity.

### How It Works
- **Toggle location:** Admin → Backup & Restore
- **Features:** Manual backup creation, automatic scheduled backups (5 min to 24 hr intervals), restore from backup, download backup files, cleanup old backups
- **Storage:** `backups/` directory with files named `backup-YYYY-MM-DD-HHMMSS.json`
- **Code:** `utils/backupManager.js` (236 lines), `routes/admin.js:372-517`

### Teaching Flow

1. **Create a manual backup:**
   - Log in as admin. Go to Admin → Backup & Restore.
   - Click "Create Backup Now." A backup file is created.
   - Show the backup list with timestamps and file sizes.

2. **Enable automatic backups:**
   - Toggle automatic backups ON and set a frequency (e.g., 5 minutes for demo).
   - Wait for the interval to pass and observe a new backup appear.

3. **Demonstrate restore:**
   - Make a visible change (e.g., create a new class).
   - Restore from the earlier backup.
   - The change is reverted — the new class no longer exists.

4. **Download and inspect:**
   - Download a backup file. Open it — it is the full database in JSON format.
   - Discuss: backups contain all data including any plaintext passwords. Backup security matters.

5. **Discussion points:**
   - RPO (Recovery Point Objective) and RTO (Recovery Time Objective).
   - Backup encryption: should backups be encrypted? (Yes — they contain sensitive data)
   - Offsite backups and the 3-2-1 rule.
   - The path traversal vulnerability in the download endpoint (see SCA finding #10).

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `utils/backupManager.js` | all | `createBackup()`, `listBackups()`, `restoreBackup()`, scheduling |
| `routes/admin.js` | 372-517 | Backup management endpoints |

### Expected Answer / What Students Should Observe
- Backups capture the entire database state at a point in time.
- Restoring a backup reverts all changes made since that backup was taken.
- Backup files contain all sensitive data — they are a high-value target for attackers.

---

## 14. Module: Bring Your Own Key (BYOK)

### Learning Objective
Students understand encryption key management and the risks of shared/default keys.

### How It Works
- **Toggle location:** Admin → Key Management (BYOK)
- **Prerequisite:** Field encryption must be DISABLED before changing keys (to prevent data corruption).
- **Key format:** Base64-encoded, generated via `openssl rand -base64 32`
- **Storage:** `keys/custom-key.txt`
- **Code:** `utils/encryption.js` (key loading logic), `routes/admin.js:523-607`

### Teaching Flow

1. **Show the default key:**
   - Discuss: the default encryption key (`university-app-secret-key-32!`) is hardcoded in the source code (`utils/encryption.js`).
   - Anyone with access to the repo can decrypt all data. This is a critical vulnerability (SCA finding #2).

2. **Generate and upload a custom key:**
   - Generate a key: `openssl rand -base64 32`
   - Go to Admin → Key Management. Upload the key.
   - The system confirms the key was saved.

3. **Encrypt data with the custom key:**
   - Toggle Field Encryption ON. Data is now encrypted with the custom key.
   - Inspect the database — encrypted values are present.

4. **Demonstrate key loss scenario:**
   - Delete the custom key (Admin → Key Management → Delete Key).
   - If you did not first disable field encryption and decrypt, the data is now permanently unrecoverable.

5. **Discussion points:**
   - Key management lifecycle: generation, storage, rotation, destruction.
   - Hardware Security Modules (HSMs) and cloud KMS solutions.
   - Key escrow and recovery procedures.
   - Compliance requirements around key management (PCI-DSS, HIPAA).

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `utils/encryption.js` | (key loading) | Loads custom key from file, falls back to default |
| `routes/admin.js` | 523-607 | BYOK upload and delete endpoints |

### Expected Answer / What Students Should Observe
- Default key: hardcoded, shared across all deployments — a single point of failure.
- Custom key: unique per deployment, stored separately from code.
- Key loss = permanent data loss (there is no recovery without the key).

---

## 15. Lab: Static Code Analysis (SCA)

### Learning Objective
Students learn to review code for security vulnerabilities, classify findings, and understand the role of static analysis tools.

### How It Works
- **Access:** All authenticated users via the "SCA" link in the sidebar
- **Pre-seeded data:** 12 real findings mapped to actual code in the codebase
- **Student workflow:** Review each finding, classify it (confirmed / false positive / needs investigation), add notes, submit
- **Instructor workflow:** View the review matrix (students x findings), drill into individual student reviews, import confirmed findings to the Vulnerability Manager
- **Code:** `routes/sca.js` (181 lines)

### The 12 SCA Findings

| # | Title | File | CWE | Severity | Expected Classification |
|---|-------|------|-----|----------|------------------------|
| 1 | Hardcoded Session Secret | `server.js:44` | CWE-798 | Critical | **Confirmed** — the secret is in source code |
| 2 | Hardcoded AES Encryption Key | `utils/encryption.js:6` | CWE-321 | Critical | **Confirmed** — AES key is in source code |
| 3 | Plaintext Credentials Logged to Console | `server.js:141` | CWE-312 | High | **Confirmed** — passwords appear in logs |
| 4 | Plaintext Password Comparison | `routes/auth.js:38` | CWE-256 | Critical | **Confirmed** — password stored in plaintext |
| 5 | Audit Logging Defaults to OFF | `config/database.js:18` | CWE-778 | High | **Confirmed** — security events go unrecorded |
| 6 | IDOR: No Ownership Check | `routes/classes.js:39` | CWE-639 | High | **Confirmed** — student ID from URL, not session |
| 7 | No CSRF Protection | `server.js:1` | CWE-352 | High | **Confirmed** — no CSRF middleware configured |
| 8 | Rate Limiting Only on Login | `middleware/rateLimiter.js:1` | CWE-307 | Medium | **Confirmed** — other endpoints unprotected |
| 9 | No HTTP Security Headers | `server.js:1` | CWE-693 | Medium | **Confirmed** — no helmet middleware |
| 10 | Path Traversal in Backup Download | `routes/admin.js:435` | CWE-22 | High | **Confirmed** — filename from URL unsanitized |
| 11 | Outdated express-session | `package.json:24` | CWE-1035 | Medium | **Needs Investigation** — requires `npm audit` to verify |
| 12 | Session Cookie Missing secure Flag | `server.js:50` | CWE-614 | Medium | **Confirmed** — `secure: false` in config |

### Teaching Flow

1. **Introduction (instructor):**
   - Explain what static code analysis is: automated review of source code without executing it.
   - Show tools: Semgrep, SonarQube, CodeQL, npm audit.
   - Walk through one finding as an example (e.g., Finding #1: Hardcoded Session Secret).

2. **Student lab work:**
   - Students log in and navigate to the SCA lab.
   - They see all 12 findings with code snippets, CWE references, and severity levels.
   - For each finding, they must:
     - Read the code snippet and description
     - Navigate to the actual file to verify
     - Classify: confirmed, false positive, or needs investigation
     - Write notes explaining their reasoning
     - Suggest remediation if confirmed

3. **Review (instructor):**
   - Use the instructor dashboard to view the review matrix.
   - Click on individual students to see their classifications and reasoning.
   - Import confirmed findings to the Vulnerability Manager for tracking.

4. **Grading rubric suggestion:**
   - Correct classification: 3 points per finding (36 total)
   - Quality of reasoning: 2 points per finding (24 total)
   - Remediation suggestion quality: 1 point per finding (12 total)
   - Total: 72 points, or normalize to your preferred scale

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/sca.js` | 42-87 | Dashboard: student lab vs. instructor matrix |
| `routes/sca.js` | 120-154 | Student review submission |
| `routes/sca.js` | 176-179 | Import to Vulnerability Manager |
| `utils/seedData.js` | 173-253 | All 12 pre-seeded SCA findings |

---

## 16. Lab: Dynamic Application Security Testing (DAST)

### Learning Objective
Students learn to actively test a running application for vulnerabilities, execute exploitation steps, and document findings with evidence.

### How It Works
- **Access:** All authenticated users via the "DAST" link in the sidebar
- **Pre-seeded data:** 6 hands-on exploitation scenarios
- **Student workflow:** Follow step-by-step exploitation guides, trigger the vulnerability, document evidence, assess impact, submit findings with severity ratings
- **Instructor workflow:** View submission counts per scenario, review student findings, provide feedback and grades, import to VM
- **Preconditions:** Some scenarios require specific security settings (e.g., RBAC disabled)
- **Code:** `routes/dast.js` (235 lines)

### The 6 DAST Scenarios

| # | Title | OWASP Category | Severity | Precondition |
|---|-------|---------------|----------|-------------|
| 1 | IDOR: Access Another Student's Grades | A01 - Broken Access Control | High | RBAC must be OFF |
| 2 | Plaintext Password Storage in Database | A02 - Cryptographic Failures | Critical | None |
| 3 | CSRF: Force Admin to Disable Security | A01 - Broken Access Control | High | None |
| 4 | Brute Force MFA (No Rate Limit) | A07 - Auth Failures | Medium | None |
| 5 | Credentials Exposed in Server Logs | A09 - Logging Failures | High | None |
| 6 | Path Traversal via Backup Download | A01 - Broken Access Control | High | None |

### Scenario-by-Scenario Solutions

#### Scenario 1: IDOR (Insecure Direct Object Reference)
**Setup:** Instructor must disable RBAC in the Security Panel.

**Steps and expected results:**
1. Log in as `alice_student` (password: `student123`).
2. Navigate to "My Classes." Note the student ID in the URL (e.g., `/classes/1`).
3. Navigate to `/classes` and find a class where Alice is not enrolled.
4. Manually change the student ID in the URL to another student's ID (try IDs 4-8).
5. **Expected result:** Alice can see enrollment records and grades belonging to other students.
6. **Evidence:** Screenshot of the URL with a different student's ID showing another student's grade.

**Why it works:** `routes/classes.js:39` uses the student ID from the URL parameter instead of the session. Without RBAC enforcing enrollment checks, any student can access any enrollment record.

#### Scenario 2: Plaintext Password Storage
**Steps and expected results:**
1. Log in as `admin`. Go to Admin → Backup & Restore.
2. Click "Create Backup Now," then download the backup file.
3. Open the JSON file and locate the `users` array.
4. **Expected result:** The `password` field contains plaintext passwords for every user (e.g., `admin123`, `prof123`, `student123`).
5. **Evidence:** Screenshot of the JSON file showing plaintext passwords.

**Why it works:** When Password Encryption is OFF, the database stores passwords as-is. The backup is a full database dump.

#### Scenario 3: CSRF (Cross-Site Request Forgery)
**Steps and expected results:**
1. Log in as admin. Confirm Audit Logging is ON.
2. Open DevTools → Network tab. Toggle Audit Logging OFF and capture the POST request.
3. Note: the POST to `/admin/security/toggle/audit_logging` has no CSRF token.
4. Create an HTML page with a hidden form that auto-submits to the same URL.
5. Open the page in another tab while still logged in as admin.
6. **Expected result:** The security setting changes without the admin's knowledge.

**Why it works:** No CSRF middleware is configured. The server accepts any POST from an authenticated session, regardless of origin.

#### Scenario 4: Brute Force MFA
**Steps and expected results:**
1. Enable MFA and set it up for the admin account.
2. Log out and start logging in as admin (reach the MFA prompt).
3. Submit incorrect 6-digit codes rapidly (manually or via a script).
4. **Expected result:** No 429 (Too Many Requests) response is ever returned.
5. **Evidence:** Screenshot showing many consecutive failed MFA attempts with no lockout.

**Why it works:** `middleware/rateLimiter.js` is only applied to `/auth/login`, not to `/auth/mfa-verify`. The MFA endpoint accepts unlimited attempts.

#### Scenario 5: Credentials in Server Logs
**Steps and expected results:**
1. Log in as admin. Open the Audit Logs page.
2. In another tab, attempt to log in as any user.
3. Check the server console output (visible in the Codespaces terminal).
4. **Expected result:** The console shows `Login attempt: username:password` in plaintext.
5. **Evidence:** Screenshot of the console log showing plaintext credentials.

**Why it works:** `server.js:141` contains a `console.log` that outputs both username and password on every login attempt.

#### Scenario 6: Path Traversal
**Steps and expected results:**
1. Log in as admin. Go to Backup & Restore. Create at least one backup.
2. Note the download URL format: `/admin/backups/download/backup-YYYY-MM-DD-HHMMSS.json`.
3. Replace the filename with `../../package.json`.
4. **Expected result:** The server returns the contents of `package.json` (or any file you specify).
5. **Evidence:** Screenshot of the response showing file contents from outside the backup directory.

**Why it works:** `routes/admin.js:498-508` passes `req.params.filename` directly to `res.download()` without validating that the resolved path stays within the backup directory.

### Teaching Flow

1. **Introduction:** Explain the difference between SCA (static, looks at code) and DAST (dynamic, tests the running app).
2. **Setup:** Enable/disable relevant security settings per scenario prerequisites.
3. **Lab work:** Students work through scenarios, trigger vulnerabilities, collect evidence.
4. **Debrief:** Review student submissions, discuss impact, and show remediation approaches.

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/dast.js` | 34-71 | Dashboard views |
| `routes/dast.js` | 74-105 | Scenario detail view |
| `routes/dast.js` | 108-138 | Precondition checking |
| `routes/dast.js` | 141-180 | Student finding submission |
| `utils/seedData.js` | 258-356 | All 6 pre-seeded DAST scenarios |

---

## 17. Lab: Vulnerability Manager (VM)

### Learning Objective
Students learn how organizations track, prioritize, and remediate security vulnerabilities through a central registry.

### How It Works
- **Access:** All authenticated users via the "Vuln Manager" link in the sidebar
- **Pre-seeded data:** 12 vulnerabilities aggregated from SCA and DAST findings
- **Sources:** Findings can be imported from SCA, DAST, and Pentest labs, or created manually
- **Status workflow:** `open` → `in_progress` → `resolved` (or `wont_fix`)
- **Features:** Priority levels (1-4), CVSS scores, assigned-to tracking, remediation plans with deadlines, collaborative comments, full status history
- **Code:** `routes/vm.js` (240 lines)

### Status Transition Rules

```
open ─────────→ in_progress     (professor or admin)
open ─────────→ wont_fix        (admin only)
in_progress ──→ resolved        (requires resolution_notes)
in_progress ──→ open            (regression)
resolved ─────→ open            (regression)
wont_fix ─────→ open            (reopen)
```

### The 12 Pre-Seeded Vulnerabilities

| # | Title | Source | Severity | Initial Status |
|---|-------|--------|----------|----------------|
| 1 | Hardcoded Session Secret | SCA #1 | Critical | Open |
| 2 | Hardcoded AES Encryption Key | SCA #2 | Critical | In Progress |
| 3 | Plaintext Password Comparison | SCA #4 | Critical | Open |
| 4 | Plaintext Credentials in Logs | DAST #5 | High | Open |
| 5 | IDOR via Disabled RBAC | DAST #1 | High | Open |
| 6 | CSRF on Security Settings | DAST #3 | High | Open |
| 7 | Path Traversal in Backup Download | SCA #10 | High | Open |
| 8 | Brute Force: No MFA Rate Limit | DAST #4 | Medium | In Progress |
| 9 | No HTTP Security Headers | SCA #9 | Medium | Resolved |
| 10 | Session Cookie Missing secure Flag | SCA #12 | Medium | Open |
| 11 | Outdated express-session | SCA #11 | Medium | Won't Fix |
| 12 | Audit Logging Defaults to OFF | SCA #5 | Low | Open |

### Teaching Flow

1. **Introduction:**
   - Explain vulnerability management lifecycle: identify → assess → prioritize → remediate → verify → close.
   - Show the VM dashboard with statistics (open, in-progress, resolved, critical count).

2. **Triage exercise:**
   - Students review the 12 pre-seeded vulnerabilities.
   - They must prioritize: which should be fixed first and why?
   - Expected answer: Critical severity + high CVSS + easy exploitability = highest priority.
   - Priority ranking: #1 (session secret), #3 (plaintext passwords), #2 (AES key) should be top.

3. **Status transitions:**
   - Demonstrate moving a vulnerability from `open` → `in_progress` (assign it to someone).
   - Add a remediation plan and deadline.
   - Move to `resolved` with resolution notes.
   - Show the full status history trail.

4. **Collaboration:**
   - Add comments to vulnerabilities for team discussion.
   - Show how multiple people can contribute to tracking a vulnerability.

5. **Discussion points:**
   - SLA-based remediation: Critical = 24 hours, High = 7 days, Medium = 30 days, Low = 90 days.
   - When is "Won't Fix" acceptable? (Accepted risk with documentation and approval)
   - How does the VM aggregate findings from multiple sources (SCA, DAST, Pentest)?
   - Real-world tools: Jira, ServiceNow, DefectDojo, Tenable.

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/vm.js` | 12-17 | Status transition rules |
| `routes/vm.js` | 47-70 | Dashboard with sorting and statistics |
| `routes/vm.js` | 89-104 | Vulnerability detail with history and comments |
| `routes/vm.js` | 153-209 | Status transition logic with validation |
| `routes/vm.js` | 220-238 | Collaborative comments |
| `utils/seedData.js` | 362-454 | All 12 pre-seeded VM vulnerabilities |

---

## 18. Lab: Penetration Testing (Pentest)

### Learning Objective
Students learn the structured methodology of a penetration test by conducting their own engagement through all 5 phases.

### How It Works
- **Access:** Students via "Pentest Lab" in the sidebar; instructors see all engagements
- **Auto-creation:** A student's engagement is automatically created when they first visit the lab
- **Phases:** Reconnaissance → Enumeration → Vulnerability Identification → Exploitation → Reporting
- **Progression:** Students must add at least 1 finding per phase before advancing to the next
- **Submission:** All 5 phases must have findings before the engagement can be submitted
- **Report builder:** Generates a structured pentest report from all findings and notes
- **Code:** `routes/pentest.js` (315 lines)

### The 5 Phases — What Students Should Do

#### Phase 1: Reconnaissance
**Objective:** Gather information about the target application.

**Expected student actions:**
- Identify the technology stack (Node.js, Express, EJS templates)
- Map the application URLs and endpoints
- Identify user roles and login pages
- Note all visible functionality

**Tools to mention:** Wappalyzer, Nmap, Google dorking, manual browsing

**Sample finding:**
- Title: "Application Technology Stack Identified"
- Severity: Info
- Description: "The application runs on Node.js with Express framework. EJS is used for server-side rendering. The application uses a JSON-based database."

#### Phase 2: Enumeration
**Objective:** Identify specific services, endpoints, and user accounts.

**Expected student actions:**
- Enumerate all accessible URL paths
- Identify API endpoints and their methods
- List user accounts (via login error messages or public pages)
- Map the application's file structure if accessible

**Tools to mention:** Burp Suite, dirb/gobuster, browser DevTools

**Sample finding:**
- Title: "User Enumeration via Login Error Messages"
- Severity: Low
- Description: "The login page returns 'Invalid username or password' for both invalid usernames and invalid passwords, which is good practice. However, the default accounts are documented in the README."

#### Phase 3: Vulnerability Identification
**Objective:** Find specific vulnerabilities in the target.

**Expected student actions:**
- Reference findings from the SCA and DAST labs
- Test for additional vulnerabilities not covered in other labs
- Classify each vulnerability with CWE and severity
- Document the affected component

**Tools to mention:** OWASP ZAP, Burp Scanner, manual testing

**Sample finding:**
- Title: "No CSRF Protection on Forms"
- Severity: High
- CWE: CWE-352
- Description: "All POST endpoints accept requests without CSRF tokens. This allows cross-site request forgery attacks."

#### Phase 4: Exploitation
**Objective:** Demonstrate the impact of identified vulnerabilities.

**Expected student actions:**
- Attempt to exploit at least one vulnerability
- Document the exact steps to reproduce
- Capture evidence (screenshots, request/response logs)
- Assess the real-world impact

**Sample finding:**
- Title: "Exploited Path Traversal to Read Server Files"
- Severity: High
- Evidence: "Modified the backup download URL to `../../package.json` and received the server's package.json file."
- Impact: "An attacker with admin access can read any file on the server."

#### Phase 5: Reporting
**Objective:** Compile all findings into a professional penetration test report.

**Expected student actions:**
- Use the Report Builder to compile their findings
- Write an executive summary
- Prioritize findings by severity and business impact
- Provide clear remediation recommendations for each finding
- Submit the engagement

### Teaching Flow

1. **Introduction (30 minutes):**
   - Explain the pentest methodology and the 5 phases.
   - Emphasize: always get written authorization before testing (scope, rules of engagement).
   - Walk through the lab interface and show how to add findings and notes.

2. **Lab work (2-3 class sessions):**
   - Students work through each phase independently.
   - They must document findings, tools used, and notes for each phase.
   - They advance through phases as they complete them.

3. **Report submission:**
   - Students use the Report Builder to create their final report.
   - All 5 phases must have at least 1 finding to submit.

4. **Grading (instructor):**
   - Go to Pentest Lab → see all engagements.
   - Click on each student's engagement to review.
   - Provide feedback and grades.

5. **Grading rubric suggestion:**
   - Reconnaissance thoroughness: 15 points
   - Enumeration completeness: 15 points
   - Vulnerability identification accuracy: 25 points
   - Exploitation quality and evidence: 25 points
   - Report clarity and recommendations: 20 points
   - Total: 100 points

### Key Code References
| File | Lines | What It Does |
|------|-------|--------------|
| `routes/pentest.js` | 7-14 | Phase definitions and labels |
| `routes/pentest.js` | 21-31 | Auto-create engagement |
| `routes/pentest.js` | 77-97 | Student lab view |
| `routes/pentest.js` | 121-142 | Phase advancement with guard |
| `routes/pentest.js` | 170-192 | Finding submission |
| `routes/pentest.js` | 237-263 | Engagement submission |
| `routes/pentest.js` | 266-277 | Instructor grading |
| `routes/pentest.js` | 280-313 | Bulk import to VM |

---

## 19. Classroom Management

### How It Works
- The instructor dashboard runs on port 3000 and monitors all team instances.
- Each team runs on its own port (3001-3012) with its own isolated database.
- Configuration is in `classroom.config.json`.

### Instructor Dashboard Features
- **Team Status Grid:** See which teams are running and accessible.
- **Broadcast Messages:** Send a message to all team instances simultaneously.
- **Security Summary:** Pull `/api/summary` from each team to see their security settings.
- **Reset Teams:** Reset individual team databases to the initial seeded state.

### Common Operations

| Task | Command / Action |
|------|-----------------|
| Start all teams | `npm start` |
| Start fewer teams | `TEAM_COUNT=4 npm start` |
| Stop all teams | `npm stop` |
| Reset a team | Use the Reset button on the instructor dashboard |
| Run smoke tests | `npm test` |
| Check team status | Visit the instructor dashboard at port 3000 |

### Sharing Team Instances with Students (Codespaces)
1. Open the **Ports** tab in Codespaces.
2. Right-click the port for the team (e.g., 3001 for Team Alpha).
3. Set visibility to **Public**.
4. Share the URL with the team.

---

## 20. Pre-Class Checklist

Run through this checklist before every class to ensure the platform is working correctly:

- [ ] Run `npm run setup` for a clean database (resets all data to seed state)
- [ ] Run `npm test` and verify all tests pass (generates `test-report.html`)
- [ ] Log in as `admin` / `admin123` — confirm access to Security Panel
- [ ] Log in as `prof_jones` / `prof123` — confirm access to classes
- [ ] Log in as `alice_student` / `student123` — confirm access to labs
- [ ] Verify all security toggles are in their default state (all OFF except RBAC)
- [ ] Create a manual backup before class starts
- [ ] Have the Google Authenticator app ready on your phone (for MFA demos)
- [ ] Verify ports 3000-3012 are accessible (or whichever ports you need)
- [ ] If using Codespaces, set required ports to Public visibility

### Important Operational Notes

1. **Encryption toggle:** Only toggle field encryption once per demo session. Toggling back and forth rapidly can corrupt data. If data gets corrupted, run `npm run setup` to reset.

2. **BYOK before encryption:** Always upload a custom key BEFORE enabling field encryption. Never delete a custom key while field encryption is ON.

3. **HTTPS requires restart:** After toggling HTTPS, you must restart the server. Plan this as a natural break in your lecture.

4. **Backup before experiments:** Always create a backup before demonstrating destructive features (encryption toggling, class deletion, database restore).

5. **Rate limiting lockout:** If you or a student gets locked out by rate limiting, use Admin → Security Panel → "Reset Rate Limits" to clear all lockouts.

---

## 21. Troubleshooting

| Problem | Solution |
|---------|----------|
| App doesn't start | Run `npm run setup` first. Check if ports 3000-3012 are available. |
| Can't log in after enabling MFA | Complete MFA setup first. Use Google Authenticator for the 6-digit code. If locked out, toggle MFA OFF from another admin session or reset the database. |
| Passwords don't work after toggling encryption | Run `npm run setup` to reset the database to a known good state. |
| Data looks corrupted after toggling field encryption | This is a known issue with toggling encryption repeatedly. Run `npm run setup` to reset. |
| Student can't access a page | Check if RBAC is enabled and the student is enrolled in the relevant class. |
| Rate limited and can't log in | Wait 15 minutes, or use Admin → Reset Rate Limits. |
| HTTPS shows certificate warning | This is expected — the platform uses self-signed certificates. Click "Advanced" → "Proceed" in the browser. |
| Backup restore doesn't seem to work | After restoring, restart the server to reload the in-memory database. |
| Team instance not responding | Check the terminal output for errors. Try `npm stop` then `npm start` to restart all instances. |
| Codespaces port not accessible | Check the Ports tab. Ensure the port is set to Public visibility. |

---

## 22. Appendix: Known Issues and Workarounds

These are documented issues in the platform. They do not need to be fixed before class — in fact, some serve as useful teaching moments.

### Data Integrity Issues

1. **Password migration can corrupt logins:** If `migratePasswordsToHashed()` fails partway through, some users may have hashed passwords while others have plaintext, causing login failures. **Workaround:** Run `npm run setup` to reset.

2. **Encryption key rotation destroys data:** Changing the BYOK key while data is encrypted with the old key makes that data unrecoverable. **Workaround:** Always disable field encryption before changing keys.

3. **Toggling encryption repeatedly corrupts data:** Multiple rapid toggles can double-encrypt or fail to decrypt correctly. **Workaround:** Toggle once per direction per session. Reset with `npm run setup` if needed.

### Operational Issues

4. **Backup restore doesn't reload in-memory database:** After restoring from backup, the in-memory database still holds old data. **Workaround:** Restart the server after restoring.

5. **Rate limiter can lock out admin:** If the admin fails 5+ logins, they are locked out like any other user. **Workaround:** Wait 15 minutes, or restart the server (clears in-memory rate limit data).

6. **MFA cannot be undone per-user:** Once MFA is set up for a user, there is no per-user disable option (only global toggle). **Workaround:** Toggle MFA OFF globally, which clears all users' MFA secrets.

### Security Issues (Intentional for Teaching)

7. **No CSRF protection:** All forms lack CSRF tokens. This is intentional — it is the subject of DAST Scenario 3.

8. **Hardcoded keys in source code:** Session secret and AES key are hardcoded. This is intentional — they are the subject of SCA findings #1 and #2.

9. **Session cookie missing secure flag:** Cookie is not marked secure. This is intentional — it is the subject of SCA finding #12.

---

*This guide was created for the HEC Montreal Application Security Platform v3.0. For updates and issues, check the repository's README.md and QA-CLASSROOM-ISSUES.md.*
