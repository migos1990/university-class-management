> **[Lire en français](README.fr.md)** | English (current)

# HEC Montréal - Application Security Platform
## University Class Management System

This application helps students learn about application security through hands-on experience with toggleable security features. Built for HEC Montréal's Application Security course.

---

## Quick Start (GitHub Codespaces)

GitHub Codespaces gives you a full development environment in the cloud — no need to install Node.js or anything else on your machine.

1. From the GitHub repository page, click the green **Code** button, then select the **Codespaces** tab.
2. Click **Create codespace on main** (or your branch of choice).
3. Wait for the container to build. The setup runs automatically (`npm install`, database seeding, SSL certificate generation).
4. The app starts automatically. When port **3000** is detected, click **Open in Browser** to access the **Instructor Dashboard**.
5. From the dashboard you can see all team instances, monitor progress, and broadcast messages.

> **Codespaces notes**
> - The app auto-starts on every Codespace launch via `postStartCommand`.
> - Port 3000 is the **Instructor Dashboard** and opens automatically.
> - Team ports (3001–3012) are labelled with team names (Alpha through Lima) in the **Ports** tab.
> - To share a team instance with students, right-click a port in the **Ports** tab and set visibility to **Public**.
> - To run fewer teams (saves memory): stop the app, then `TEAM_COUNT=4 npm start`.

### Running Locally (Alternative)

**Prerequisites:** [Node.js](https://nodejs.org) LTS (v18 or newer).

```bash
# 1. Install dependencies
npm install

# 2. Initialize database, seed sample data, generate SSL certificates
npm run setup

# 3. Start the application (launches instructor dashboard + all team instances)
npm start
```

The Instructor Dashboard opens at **http://localhost:3000**. Team instances run on ports 3001–3012.

> **Windows tips**
> - If `npm` is not recognized, restart your terminal after installing Node.js.
> - If you see permission errors, try running the terminal as Administrator.

---

## Default Login Accounts

### Admin Account (Full Access)
- Username: `admin`
- Password: `admin123`

### Professor Accounts (Can Edit Classes)
- Username: `prof_jones` | Password: `prof123`
- Username: `prof_smith` | Password: `prof123`

### Student Accounts
- Username: `alice_student` | Password: `student123`
- Username: `bob_student` | Password: `student123`
- Username: `charlie_student` | Password: `student123`
- Username: `diana_student` | Password: `student123`
- Username: `eve_student` | Password: `student123`

---

## Security Features

Login as **admin** and visit the **Security Panel** to toggle these features:

1. **Multi-Factor Authentication (MFA)** - Require Google Authenticator for admin login
2. **Role-Based Access Control (RBAC)** - Restrict access based on user roles
3. **Password Encryption** - Hash passwords with bcrypt
4. **Data Encryption** - Encrypt sensitive data (SSN, grades) with AES-256-CBC
5. **HTTPS/TLS** - Secure communication with encryption in transit
6. **Audit Logging** - Track all user actions
7. **Rate Limiting** - Protect against brute force attacks (5 attempts per 15 minutes)
8. **Segregation of Duties** - Require admin approval for class deletions by professors
9. **Database Backups** - Automatic scheduled backups at configurable intervals
10. **Bring Your Own Key (BYOK)** - Upload custom encryption keys for data protection

---

## Security Curriculum Labs

The platform includes four specialized labs for hands-on security training:

### Static Code Analysis (SCA)
Instructors create code findings with CWE references and severity levels. Students classify and assess each finding. A review matrix tracks student submission progress. Findings can be imported into the Vulnerability Manager.

### Dynamic Application Security Testing (DAST)
Pre-built vulnerability scenarios with step-by-step exploitation guides. Students execute tests and submit findings with severity ratings and CVSS scores. Scenarios can be imported into the Vulnerability Manager.

### Vulnerability Manager (VM)
A central vulnerability registry that aggregates findings from SCA, DAST, and Pentest labs. Tracks vulnerability status (`open` → `in_progress` → `resolved` → `wont_fix`) with priority levels, remediation tracking, comments, and full status history.

### Penetration Testing (Pentest)
Students conduct penetration testing engagements following a 5-phase methodology:
1. Reconnaissance
2. Enumeration
3. Vulnerability Identification
4. Exploitation
5. Reporting

Each engagement tracks phase-specific notes, findings, and reports. Instructors can review and grade submitted engagements.

---

## How It Works

When you run `npm start`, the system launches:
- **Instructor Dashboard** on port 3000 — monitor all teams, security configs, lab progress, broadcast messages
- **Team instances** on ports 3001–3012 — each team gets its own isolated database and app instance

### Configuring Teams

Edit `classroom.config.json` to customize team names, ports, and other settings.

To run fewer teams (useful for smaller classes or limited resources):
```bash
TEAM_COUNT=4 npm start   # Only launches teams 1–4
```

### Stopping the App

```bash
npm stop    # Gracefully stops all team instances
```

---

## Inspecting the Database

The application uses a JSON-based database. Each team instance stores its data in `instances/team-N/database/`.

### What to Look For:
- `users` array: See password encryption (plaintext vs bcrypt hashes)
- `enrollments` array: See grade encryption (plaintext vs encrypted)
- `audit_logs` array: Track all user actions
- Toggle security features and reload the file to see the changes!

---

## Troubleshooting

**App doesn't start?**
- Make sure you ran `npm run setup` first (done automatically in Codespaces)
- Check if ports 3000–3012 are available

**Can't login after enabling MFA?**
- Make sure you've completed the MFA setup first
- Use Google Authenticator app to get the 6-digit code

**Need to reset a team?**
- Use the "Reset" button on the Instructor Dashboard, or delete the team's `instances/team-N/database/` folder and restart

---

## Available npm Scripts

| Command | Description |
|---------|-------------|
| `npm install` | Install all dependencies |
| `npm run setup` | Initialize database, seed sample data, and generate SSL certificates |
| `npm start` | Start the instructor dashboard + all team instances |
| `npm stop` | Stop all running instances |
| `npm test` | Run smoke tests against Team Alpha (port 3001) |
| `npm run test:open` | Run smoke tests and automatically open the report in a browser |

---

## For Instructors

This application is designed for teaching application security concepts to non-technical students. Each security feature can be toggled ON/OFF to demonstrate the difference between secure and insecure implementations.

### Pre-Class Verification

Run the smoke test before class to ensure the application is working correctly:

```bash
npm test
```

This generates an HTML report (`test-report.html`) showing:
- Login tests for all user roles (admin, professor, student)
- Page access verification
- Pass/fail status with error details

### What Students Can Observe

- Plaintext vs encrypted data in the database
- Different access levels for different roles
- MFA authentication flow
- HTTP vs HTTPS connections
- Audit trails of user actions
- Rate limiting in action
- Segregation of duties workflow for class deletions
- Backup and recovery processes
- Custom encryption key management (BYOK)
- Hands-on security labs: SCA, DAST, Vulnerability Management, and Penetration Testing

### Security Panel

The redesigned Security Panel (Admin → Security) shows each feature as a card with:
- Clear description of what the feature does
- Visual impact indicator (e.g., "admin123" → "$2b$10$xK3...")
- Easy toggle switch

---

## Version History

### Version 3.0 (2026-02-27)
**Codespaces-First Simplification:**

- **Classroom mode is now the default** — `npm start` launches the instructor dashboard + all team instances
- **Auto-start in Codespaces** — the app launches automatically when the Codespace starts
- **Configurable team count** — use `TEAM_COUNT` env var to run fewer instances
- **Codespaces URL detection** — dashboard links work correctly in Codespaces (auto-detects forwarded port URLs)
- **Simplified npm scripts** — removed redundant `classroom:*` scripts; `npm stop` replaces `npm run classroom:stop`
- **Bind to 0.0.0.0** — ensures Codespaces port forwarding works correctly

### Version 2.0 (2026-02-02)
**Major UI Redesign & HEC Montréal Branding:**

**New Features:**
- **HEC Montréal Branding** - Official colors (#002855 navy), logo, and styling throughout
- **Sidebar Navigation** - Modern fixed sidebar layout replacing top navigation
- **Card-Based Security Panel** - Each security feature displayed as a card with impact preview
- **Smoke Test Script** - Run `npm test` to verify all key functions before class
- **Improved Error Messages** - Clearer login failure feedback

**UI Improvements:**
- Consistent page headers with title and subtitle
- Stat cards on admin dashboard
- Improved table styling
- Better empty states
- Sticky security status bar

**For Instructors:**
- New `npm test` command generates HTML report
- Tests login for all 3 roles automatically
- Shows pass/fail with detailed error information

**Breaking Changes:**
- French translation removed (English only)
- Language selector removed from header

---

### Version 1.9 (2026-02-01)
**Major Fix - Reverted to Working Template Pattern:**
- Reverted all EJS templates back to v1.2's working `<%- include('partials/header') %>` / `<%- include('partials/footer') %>` pattern
- The broken `const body = \`...\`` template literal pattern has been completely removed
- All templates now use standard EJS syntax that works reliably
- Restored `views/partials/header.ejs` and `views/partials/footer.ejs`
- Updated header with translation support (French) and SoD badge
- Removed `views/layout.ejs` (not needed with header/footer partials)
- **IMPORTANT**: Delete your old `university-class-management` folder completely before extracting

### Version 1.8 (2026-02-01)
**Note:**
- Fresh build with all EJS template fixes confirmed (still had issues due to broken template pattern)
- **Use v1.9 instead**

### Version 1.7 (2026-02-01)
**Bug Fixes:**
- Thorough automated audit found and fixed remaining unescaped EJS tag
- Fixed `views/admin/audit-logs.ejs` line 56: `<% }); %>` → `\<% }); %>`

### Version 1.6
**Bug Fixes:**
- Complete audit and fix of ALL EJS template syntax errors across the entire application
- Fixed files with unescaped EJS tags inside template literals (`<%` → `\<%`):
  - `views/classes/delete-request.ejs`
  - `views/admin/backups.ejs`
  - `views/admin/byok.ejs`
  - `views/admin/dashboard.ejs`
  - `views/admin/security-panel.ejs`
  - `views/admin/audit-logs.ejs`
  - `views/admin/mfa-setup.ejs`
  - `views/admin/deletion-requests.ejs`
  - `views/class-details.ejs`
  - `views/student/dashboard.ejs`
  - `views/session-view.ejs`
  - `views/professor/edit-session.ejs`
  - `views/professor/dashboard.ejs`

### Version 1.5
**Bug Fixes:**
- Partial fix for EJS template syntax errors (incomplete)

### Version 1.4
**Updates:**
- Initial bug fix attempt for EJS template errors

### Version 1.3
**Updates:**
- Package updates and maintenance

### Version 1.2
**New Features:**
- **French Translation System** - Toggle between English and French UI
- **Segregation of Duties** - Admin approval required for class deletions
- **Bring Your Own Key (BYOK)** - Upload custom encryption keys
- **Scheduled Database Backups** - Automatic backups (5min - 24hr intervals)
- **Enhanced Documentation** - Windows startup instructions, JSON database viewing

**Technical Changes:**
- Added i18n translation infrastructure
- Added `deletion_requests` database table
- Added backup scheduling system
- Added custom encryption key support
- Expanded `security_settings` table with 3 new toggles

### Version 1.1 (Initial Release - 2026-02-01)
**Features:**
- 7 toggleable security features (MFA, RBAC, encryption, HTTPS, audit logging, rate limiting)
- Role-based dashboards (Admin, Professor, Student)
- JSON-based database system
- Sample data seeding
- Self-signed SSL certificate generation

**Security Toggles:**
1. Multi-Factor Authentication (MFA)
2. Role-Based Access Control (RBAC)
3. Password Encryption (bcrypt)
4. Field Encryption (AES-256)
5. HTTPS/TLS
6. Audit Logging
7. Rate Limiting
