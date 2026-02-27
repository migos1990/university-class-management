# HEC Montréal - Application Security Platform
## University Class Management System

This application helps students learn about application security through hands-on experience with toggleable security features. Built for HEC Montréal's Application Security course.

---

## Quick Start

Choose **one** of the two options below depending on your setup.

### Option A: Run Locally on Your Laptop

**Prerequisites:** [Node.js](https://nodejs.org) LTS (v18 or newer) must be installed.

```bash
# 1. Install dependencies
npm install

# 2. Initialize the database, seed sample data, and generate SSL certificates
npm run setup

# 3. Start the application
npm start
```

Open your browser to **http://localhost:3000** and log in with one of the [default accounts](#default-login-accounts) below.

> **Windows tips**
> - The commands above work the same in Command Prompt, PowerShell, and Git Bash.
> - If `npm` is not recognized, restart your terminal after installing Node.js.
> - If port 3000 is in use, close other applications using that port or set a custom port: `PORT=3001 npm start`
> - If you see permission errors, try running the terminal as Administrator.

### Option B: Run in GitHub Codespaces (No Local Install)

GitHub Codespaces gives you a full development environment in the cloud — no need to install Node.js or anything else on your machine.

1. From the GitHub repository page, click the green **Code** button, then select the **Codespaces** tab.
2. Click **Create codespace on main** (or your branch of choice).
3. Wait for the container to build. The `postCreateCommand` automatically runs `npm install` and `npm run setup` for you.
4. Once the terminal is ready, start the app:
   ```bash
   npm start
   ```
5. When the server starts, Codespaces detects port **3000** and shows a notification. Click **Open in Browser** (or find the forwarded port in the **Ports** tab) to access the app.

> **Codespaces notes**
> - The devcontainer pre-forwards ports 3000–3012 so both the single-instance app and classroom mode work out of the box.
> - Port 3000 is labelled "Classroom Dashboard" and opens automatically when forwarded.
> - Each team port (3001–3012) is labelled with the team name (Alpha through Lima).
> - To share your running app with others, right-click a port in the **Ports** tab and set visibility to **Public**.

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

## Classroom Mode

Launch multiple isolated instances for team-based classroom exercises:

```bash
# Start all team instances (default: 12 teams)
npm run classroom

# Setup helper for classroom configuration
npm run classroom:setup

# Stop all running instances
npm run classroom:stop
```

- **Dashboard:** http://localhost:3000
- **Team instances:** http://localhost:3001 through http://localhost:3012
- Each team gets its own isolated database and port
- Configuration: `classroom.config.json`

---

## Inspecting the Database

The application uses a JSON-based database stored in `database/data.json`.

### Viewing the Database:

**Option 1: VS Code (Recommended)**
1. Open the project folder in VS Code
2. Navigate to `database/data.json`
3. Use "Format Document" (Shift+Alt+F on Windows/Linux, Shift+Option+F on Mac) for better readability

**Option 2: Web Browser**
1. Open Chrome, Firefox, or Edge
2. Press Ctrl+O (or Cmd+O on Mac) and select `database/data.json`
3. Install a JSON viewer extension for better formatting

**Option 3: Command Line**
- **Windows:** `type database\data.json | more`
- **Mac/Linux:** `cat database/data.json | jq .` (if jq is installed)
- **Without jq:** `cat database/data.json | more`

### What to Look For:
- `users` array: See password encryption (plaintext vs bcrypt hashes)
- `enrollments` array: See grade encryption (plaintext vs encrypted)
- `audit_logs` array: Track all user actions
- Toggle security features and reload the file to see the changes!

---

## Troubleshooting

**Port already in use?**
- Close other applications using port 3000
- Or change the port in `server.js`

**Can't login after enabling MFA?**
- Make sure you've completed the MFA setup first
- Use Google Authenticator app to get the 6-digit code

**Database issues?**
- Close any programs that might be accessing `database/data.json`
- Restart the application
- If the database becomes corrupted, delete `database/data.json` and run `npm run setup` again

---

## Available npm Scripts

| Command | Description |
|---------|-------------|
| `npm install` | Install all dependencies |
| `npm run setup` | Initialize database, seed sample data, and generate SSL certificates |
| `npm start` | Start the application on http://localhost:3000 |
| `npm test` | Run smoke tests and generate an HTML report (`test-report.html`) |
| `npm run test:open` | Run smoke tests and automatically open the report in a browser |
| `npm run classroom` | Launch multiple team instances for classroom use |
| `npm run classroom:setup` | Interactive classroom configuration helper |
| `npm run classroom:stop` | Stop all running classroom instances |

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
