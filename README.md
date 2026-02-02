# HEC Montréal - Application Security Platform
## University Class Management System

This application helps students learn about application security through hands-on experience with toggleable security features. Built for HEC Montréal's Application Security course.

---

## Quick Start (3 Steps!)

### Step 1: Install Node.js
Download and install Node.js from [nodejs.org](https://nodejs.org) (choose the LTS version)

### Step 2: Setup the Application
Open a terminal/command prompt in this folder and run:
```bash
npm install
npm run setup
```

### Step 3: Start the Application
```bash
npm start
```

Then open your web browser and go to: **http://localhost:3000**

### Windows-Specific Instructions

**If you're using Windows Command Prompt:**
```cmd
npm install
npm run setup
npm start
```

**If you're using PowerShell:**
```powershell
npm install
npm run setup
npm start
```

**If you're using Git Bash:**
```bash
npm install
npm run setup
npm start
```

**Common Windows Issues:**
- If `npm` is not recognized, restart your terminal after installing Node.js
- If port 3000 is in use, close other applications or edit `server.js` to use a different port
- If you see permission errors, try running the terminal as Administrator

---

## Default Login Accounts

### Admin Account (Full Access)
- Username: `admin`
- Password: `admin123`

### Professor Accounts (Can Edit Classes)
- Username: `prof_jones` | Password: `prof123`
- Username: `prof_smith` | Password: `prof123`

### Student Accounts (View Only)
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
4. **Data Encryption** - Encrypt sensitive data (SSN, grades)
5. **HTTPS/TLS** - Secure communication with encryption in transit
6. **Audit Logging** - Track all user actions
7. **Rate Limiting** - Protect against brute force attacks

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

### Security Panel

The redesigned Security Panel (Admin → Security) shows each feature as a card with:
- Clear description of what the feature does
- Visual impact indicator (e.g., "admin123" → "$2b$10$xK3...")
- Easy toggle switch

See `docs/LAB_EXERCISES.md` for structured learning activities.

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
