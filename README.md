# University Class Management System
## Application Security Learning Platform

This application helps students learn about application security through hands-on experience with toggleable security features.

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

To see how security affects the data:

1. Download [DB Browser for SQLite](https://sqlitebrowser.org/)
2. Open the file: `database/classmanagement.db`
3. Browse the `users` table to see password encryption
4. Browse the `enrollments` table to see grade encryption
5. Toggle security features and refresh to see the changes!

---

## Troubleshooting

**Port already in use?**
- Close other applications using port 3000
- Or change the port in `server.js`

**Can't login after enabling MFA?**
- Make sure you've completed the MFA setup first
- Use Google Authenticator app to get the 6-digit code

**Database locked error?**
- Close DB Browser for SQLite if it's open
- Restart the application

---

## For Instructors

This application is designed for teaching application security concepts to non-technical students. Each security feature can be toggled ON/OFF to demonstrate the difference between secure and insecure implementations.

Students can observe:
- Plaintext vs encrypted data in the database
- Different access levels for different roles
- MFA authentication flow
- HTTP vs HTTPS connections
- Audit trails of user actions
- Rate limiting in action

See `docs/LAB_EXERCISES.md` for structured learning activities.
