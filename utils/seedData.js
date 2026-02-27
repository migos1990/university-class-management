const { db } = require('../config/database');

function seedDatabase() {
  console.log('Starting database seeding...');

  // Clear existing data
  db.prepare('DELETE FROM enrollments').run();
  db.prepare('DELETE FROM sessions').run();
  db.prepare('DELETE FROM classes').run();
  db.prepare('DELETE FROM users').run();
  db.prepare('DELETE FROM audit_logs').run();
  db.prepare('DELETE FROM rate_limit_attempts').run();

  // Insert users
  console.log('Creating users...');
  const userStmt = db.prepare(`
    INSERT INTO users (username, email, password, role, ssn)
    VALUES (?, ?, ?, ?, ?)
  `);

  // Admin
  userStmt.run('admin', 'admin@university.edu', 'admin123', 'admin', null);

  // Professors
  userStmt.run('prof_jones', 'jones@university.edu', 'prof123', 'professor', null);
  userStmt.run('prof_smith', 'smith@university.edu', 'prof123', 'professor', null);

  // Students with SSNs
  userStmt.run('alice_student', 'alice@university.edu', 'student123', 'student', '111-22-3333');
  userStmt.run('bob_student', 'bob@university.edu', 'student123', 'student', '222-33-4444');
  userStmt.run('charlie_student', 'charlie@university.edu', 'student123', 'student', '333-44-5555');
  userStmt.run('diana_student', 'diana@university.edu', 'student123', 'student', '444-55-6666');
  userStmt.run('eve_student', 'eve@university.edu', 'student123', 'student', '555-66-7777');

  // Get user IDs
  const profJones = db.prepare('SELECT id FROM users WHERE username = ?').get('prof_jones');
  const profSmith = db.prepare('SELECT id FROM users WHERE username = ?').get('prof_smith');

  // Insert classes
  console.log('Creating classes...');
  const classStmt = db.prepare(`
    INSERT INTO classes (code, name, description, semester, professor_id)
    VALUES (?, ?, ?, ?, ?)
  `);

  classStmt.run(
    'CS101',
    'Introduction to Programming',
    'Learn the fundamentals of programming using Python. Topics include variables, control structures, functions, and basic data structures.',
    'Fall 2026',
    profJones.id
  );

  classStmt.run(
    'CS201',
    'Data Structures',
    'Study of abstract data types, including lists, stacks, queues, trees, and graphs. Emphasis on algorithm analysis and implementation.',
    'Fall 2026',
    profSmith.id
  );

  classStmt.run(
    'CS301',
    'Application Security',
    'Comprehensive overview of security in modern applications. Topics include authentication, authorization, encryption, and common vulnerabilities.',
    'Fall 2026',
    profJones.id
  );

  // Get class IDs
  const cs101 = db.prepare('SELECT id FROM classes WHERE code = ?').get('CS101');
  const cs201 = db.prepare('SELECT id FROM classes WHERE code = ?').get('CS201');
  const cs301 = db.prepare('SELECT id FROM classes WHERE code = ?').get('CS301');

  // Insert sessions
  console.log('Creating sessions...');
  const sessionStmt = db.prepare(`
    INSERT INTO sessions (class_id, session_number, title, description, content, date)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  // CS101 Sessions
  const cs101Sessions = [
    { num: 1, title: 'Introduction to Python', desc: 'Course overview and Python basics', content: 'Welcome to CS101! In this session, we introduce Python programming language, its history, and why it is great for beginners. We will set up the development environment and write our first "Hello, World!" program.' },
    { num: 2, title: 'Variables and Data Types', desc: 'Understanding variables, strings, numbers', content: 'Learn about different data types in Python including integers, floats, strings, and booleans. We will practice declaring variables, performing arithmetic operations, and string manipulations.' },
    { num: 3, title: 'Control Flow', desc: 'If statements and conditional logic', content: 'Understand how to control program flow using if, elif, and else statements. We will build decision-making programs and learn about comparison operators and logical operators.' },
    { num: 4, title: 'Loops', desc: 'For loops and while loops', content: 'Master iteration using for and while loops. We will practice iterating over sequences, using range(), and understanding loop control statements like break and continue.' },
    { num: 5, title: 'Functions', desc: 'Defining and calling functions', content: 'Learn to write reusable code with functions. Topics include function definitions, parameters, return values, and scope. We will also cover lambda functions and built-in functions.' },
    { num: 6, title: 'Lists and Tuples', desc: 'Working with sequences', content: 'Explore Python lists and tuples. Learn about indexing, slicing, list methods, and the differences between mutable and immutable sequences.' },
    { num: 7, title: 'Dictionaries', desc: 'Key-value data structures', content: 'Understand dictionaries and their use cases. Practice creating, accessing, and modifying dictionaries. Learn about dictionary methods and iteration.' },
    { num: 8, title: 'File I/O', desc: 'Reading and writing files', content: 'Learn to work with files in Python. Practice opening, reading, writing, and closing files. Understand different file modes and exception handling with files.' },
    { num: 9, title: 'Error Handling', desc: 'Try-except blocks', content: 'Master exception handling in Python. Learn about try, except, finally, and raise statements. Understand common exceptions and how to handle them gracefully.' },
    { num: 10, title: 'Modules and Packages', desc: 'Code organization and imports', content: 'Understand Python modules and packages. Learn to import modules, create your own modules, and explore the Python Standard Library.' },
    { num: 11, title: 'Object-Oriented Programming', desc: 'Classes and objects', content: 'Introduction to OOP concepts in Python. Learn about classes, objects, attributes, methods, inheritance, and encapsulation.' },
    { num: 12, title: 'Final Project', desc: 'Build a complete application', content: 'Apply everything you have learned to build a complete Python application. Present your project to the class and receive feedback.' }
  ];

  cs101Sessions.forEach(session => {
    sessionStmt.run(cs101.id, session.num, session.title, session.desc, session.content, `2026-09-${session.num.toString().padStart(2, '0')}`);
  });

  // CS201 Sessions
  const cs201Sessions = [
    { num: 1, title: 'Introduction to Data Structures', desc: 'Course overview and abstract data types', content: 'Welcome to CS201! This course covers essential data structures used in computer science. We will discuss abstract data types, algorithm analysis, and Big-O notation.' },
    { num: 2, title: 'Arrays and Linked Lists', desc: 'Linear data structures', content: 'Compare arrays and linked lists. Understand their implementations, time complexities, and use cases. Practice implementing singly and doubly linked lists.' },
    { num: 3, title: 'Stacks', desc: 'LIFO data structure', content: 'Learn about stacks and their applications. Implement stack operations (push, pop, peek) using arrays and linked lists. Explore real-world use cases like function call stacks.' },
    { num: 4, title: 'Queues', desc: 'FIFO data structure', content: 'Understand queues, priority queues, and deques. Implement queue operations and explore applications like task scheduling and breadth-first search.' },
    { num: 5, title: 'Recursion', desc: 'Recursive problem solving', content: 'Master recursive thinking and implementation. Practice writing recursive functions, understand base cases, and analyze recursive algorithms.' },
    { num: 6, title: 'Trees', desc: 'Hierarchical data structures', content: 'Introduction to tree structures including binary trees, binary search trees, and tree traversal algorithms (inorder, preorder, postorder).' },
    { num: 7, title: 'Balanced Trees', desc: 'AVL trees and Red-Black trees', content: 'Learn about self-balancing trees. Understand rotations, balance factors, and the importance of balanced trees for performance.' },
    { num: 8, title: 'Heaps', desc: 'Binary heaps and priority queues', content: 'Explore heap data structures and their applications. Implement heap operations and use heaps to implement efficient priority queues.' },
    { num: 9, title: 'Hash Tables', desc: 'Fast lookup data structures', content: 'Understand hash tables, hash functions, and collision resolution strategies. Analyze time complexity and implement a hash table from scratch.' },
    { num: 10, title: 'Graphs', desc: 'Graph representation and traversal', content: 'Introduction to graph theory and graph data structures. Learn adjacency lists and adjacency matrices. Implement graph traversal algorithms.' },
    { num: 11, title: 'Graph Algorithms', desc: 'BFS, DFS, and shortest path', content: 'Study common graph algorithms including breadth-first search, depth-first search, Dijkstra algorithm, and minimum spanning trees.' },
    { num: 12, title: 'Algorithm Analysis', desc: 'Review and comparison', content: 'Review all data structures covered in the course. Compare their time and space complexities. Discuss when to use each data structure in practice.' }
  ];

  cs201Sessions.forEach(session => {
    sessionStmt.run(cs201.id, session.num, session.title, session.desc, session.content, `2026-09-${session.num.toString().padStart(2, '0')}`);
  });

  // CS301 Sessions
  const cs301Sessions = [
    { num: 1, title: 'Introduction to Application Security', desc: 'Security fundamentals and threat landscape', content: 'Welcome to CS301! This course covers essential security concepts for modern applications. We will explore the CIA triad, threat modeling, and the current security landscape.' },
    { num: 2, title: 'Authentication Basics', desc: 'Passwords and credential management', content: 'Learn about authentication mechanisms. Understand password storage, hashing algorithms (bcrypt, scrypt), and best practices for credential management.' },
    { num: 3, title: 'Multi-Factor Authentication', desc: 'MFA and TOTP', content: 'Explore multi-factor authentication methods. Implement TOTP-based MFA using Google Authenticator. Understand the security benefits of MFA.' },
    { num: 4, title: 'Authorization and Access Control', desc: 'RBAC and permissions', content: 'Study authorization mechanisms including role-based access control (RBAC) and attribute-based access control (ABAC). Learn to implement proper access controls.' },
    { num: 5, title: 'Encryption Fundamentals', desc: 'Symmetric and asymmetric encryption', content: 'Understand encryption concepts including symmetric encryption (AES), asymmetric encryption (RSA), and when to use each. Practice encrypting sensitive data.' },
    { num: 6, title: 'Encryption in Transit', desc: 'TLS/SSL and HTTPS', content: 'Learn about transport layer security. Understand how HTTPS works, certificate authorities, and implementing secure communication in applications.' },
    { num: 7, title: 'Encryption at Rest', desc: 'Database encryption and key management', content: 'Explore data encryption strategies for stored data. Learn about database encryption, file encryption, and secure key management practices.' },
    { num: 8, title: 'OWASP Top 10: Injection', desc: 'SQL injection and prevention', content: 'Study injection attacks, particularly SQL injection. Learn how to prevent injection vulnerabilities using parameterized queries and input validation.' },
    { num: 9, title: 'OWASP Top 10: XSS and CSRF', desc: 'Cross-site scripting and request forgery', content: 'Understand XSS and CSRF attacks. Learn prevention techniques including output encoding, content security policy, and CSRF tokens.' },
    { num: 10, title: 'Session Management', desc: 'Secure sessions and tokens', content: 'Learn about secure session management, JWT tokens, and session hijacking prevention. Implement secure session handling in web applications.' },
    { num: 11, title: 'Security Monitoring', desc: 'Logging and audit trails', content: 'Understand the importance of security monitoring and audit logging. Learn what events to log, how to protect logs, and using logs for incident response.' },
    { num: 12, title: 'Security Best Practices', desc: 'Defense in depth and secure SDLC', content: 'Review security best practices including defense in depth, principle of least privilege, and integrating security throughout the software development lifecycle.' }
  ];

  cs301Sessions.forEach(session => {
    sessionStmt.run(cs301.id, session.num, session.title, session.desc, session.content, `2026-09-${session.num.toString().padStart(2, '0')}`);
  });

  // Get student IDs
  const alice = db.prepare('SELECT id FROM users WHERE username = ?').get('alice_student');
  const bob = db.prepare('SELECT id FROM users WHERE username = ?').get('bob_student');
  const charlie = db.prepare('SELECT id FROM users WHERE username = ?').get('charlie_student');
  const diana = db.prepare('SELECT id FROM users WHERE username = ?').get('diana_student');
  const eve = db.prepare('SELECT id FROM users WHERE username = ?').get('eve_student');

  // Insert enrollments
  console.log('Creating enrollments...');
  const enrollStmt = db.prepare(`
    INSERT INTO enrollments (student_id, class_id, grade)
    VALUES (?, ?, ?)
  `);

  enrollStmt.run(alice.id, cs101.id, 'A');
  enrollStmt.run(alice.id, cs201.id, 'B+');

  enrollStmt.run(bob.id, cs101.id, 'B');
  enrollStmt.run(bob.id, cs301.id, 'A-');

  enrollStmt.run(charlie.id, cs201.id, 'A-');
  enrollStmt.run(charlie.id, cs301.id, 'A');

  enrollStmt.run(diana.id, cs101.id, 'B+');

  enrollStmt.run(eve.id, cs201.id, 'C+');
  enrollStmt.run(eve.id, cs301.id, 'B');

  // -------------------------------------------------------
  // SCA Findings (12 real findings mapped to codebase)
  // -------------------------------------------------------
  console.log('Seeding SCA findings...');
  const scaStmt = db.prepare(`
    INSERT INTO sca_findings (id, title, file_path, line_number, code_snippet, category, cwe, severity, description, tool, remediation, false_positive_reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const scaFindings = [
    [1, 'Hardcoded Session Secret', 'server.js', 44,
      "secret: 'university-secret-key-change-in-production'",
      'Hardcoded Credentials', 'CWE-798', 'Critical',
      'The Express session secret is hardcoded in source code. Anyone with code access can forge session cookies, leading to authentication bypass.',
      'Semgrep', 'Move the secret to an environment variable (SESSION_SECRET). Generate a cryptographically random 64-byte value for production.', null],

    [2, 'Hardcoded AES Encryption Key', 'utils/encryption.js', 6,
      "const ENCRYPTION_KEY = 'university-encryption-key-32byte';",
      'Hardcoded Credentials', 'CWE-321', 'Critical',
      'The AES-256 encryption key is hardcoded. Compromise of the key allows decryption of all encrypted PII (SSNs, grades) in the database.',
      'Semgrep', 'Load the key from an environment variable (ENCRYPTION_KEY). Use a key derivation function (PBKDF2/Argon2) if deriving from a passphrase.', null],

    [3, 'Plaintext Credentials Logged to Console', 'server.js', 141,
      "console.log(`Login attempt: ${username}:${password}`);",
      'Sensitive Data Exposure', 'CWE-312', 'High',
      'Plaintext passwords are written to the console/log on every login attempt. Log aggregation systems (Splunk, CloudWatch) will store and expose credentials.',
      'Semgrep', 'Remove the password from the log statement. Log only the username and outcome (success/failure).', null],

    [4, 'Plaintext Password Comparison', 'routes/auth.js', 38,
      "if (user.password === password) {",
      'Insecure Authentication', 'CWE-256', 'Critical',
      'Passwords are stored and compared in plaintext. A database breach exposes every user\'s password immediately.',
      'Semgrep', 'Hash passwords with bcrypt/argon2 on registration. Compare using bcrypt.compare() at login. Migrate existing users on next login.', null],

    [5, 'Audit Logging Defaults to OFF', 'config/database.js', 18,
      "audit_logging: 0",
      'Security Misconfiguration', 'CWE-778', 'High',
      'Audit logging is disabled by default. Security-relevant events (logins, privilege changes, data access) are not recorded, preventing incident detection and forensics.',
      'Manual Review', 'Change the default to audit_logging: 1. Document the intentional-off toggle in the Security Panel as a teaching tool only.', null],

    [6, 'IDOR: No Ownership Check on Enrollment Access', 'routes/classes.js', 39,
      "const enrollment = db.prepare('SELECT * FROM enrollments WHERE student_id = ? AND class_id = ?').get(req.params.studentId, req.params.classId);",
      'Broken Access Control', 'CWE-639', 'High',
      'The endpoint uses the student ID from the URL path rather than the authenticated session. Students can read any other student\'s enrollment records by changing the ID in the URL.',
      'Semgrep', 'Replace req.params.studentId with req.session.userId. Verify resource ownership before returning data.', null],

    [7, 'No CSRF Protection on State-Changing Requests', 'server.js', 1,
      "// No CSRF middleware configured",
      'CSRF', 'CWE-352', 'High',
      'POST/PUT/DELETE routes have no CSRF token validation. An attacker can craft a malicious page that triggers authenticated state-changing actions on behalf of a logged-in user.',
      'Manual Review', 'Add the csurf middleware (or a modern equivalent like csrf-csrf). Include the token in all forms and AJAX requests.', null],

    [8, 'Rate Limiting Only on Login Route', 'middleware/rateLimiter.js', 1,
      "// Applied only to /auth/login",
      'Security Misconfiguration', 'CWE-307', 'Medium',
      'Rate limiting is only applied to the login endpoint. Password reset, MFA verification, and API endpoints remain vulnerable to automated brute-force attacks.',
      'Manual Review', 'Apply rate limiting globally or to all sensitive endpoints. Use different limits per endpoint based on sensitivity.', null],

    [9, 'No HTTP Security Headers', 'server.js', 1,
      "// No helmet() or security headers configured",
      'Security Misconfiguration', 'CWE-693', 'Medium',
      'The application does not set security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options). This leaves it vulnerable to clickjacking, MIME-sniffing, and XSS amplification.',
      'Semgrep', 'Add the helmet middleware: app.use(helmet()). Configure Content-Security-Policy for the application\'s specific sources.', null],

    [10, 'Path Traversal in Backup Download', 'routes/admin.js', 435,
      "const filepath = path.join(BACKUP_DIR, req.params.filename);",
      'Path Traversal', 'CWE-22', 'High',
      'The backup filename comes directly from the URL without validation. An attacker with admin access can request ../../etc/passwd or any other file on the server.',
      'Semgrep', 'Validate that the resolved path starts with BACKUP_DIR: assert(filepath.startsWith(BACKUP_DIR)). Reject requests with path separators in the filename.', null],

    [11, 'Outdated express-session with Known Vulnerabilities', 'package.json', 24,
      '"express-session": "^1.17.0"',
      'Vulnerable Dependency', 'CWE-1035', 'Medium',
      'The project uses an older version of express-session. Dependencies should be kept current to include security patches.',
      'npm audit', 'Run npm audit fix. Pin to the latest stable version. Add npm audit to the CI pipeline to catch regressions.', null],

    [12, 'Session Cookie Missing secure Flag', 'server.js', 50,
      "cookie: { secure: false }",
      'Sensitive Cookie', 'CWE-614', 'Medium',
      'The session cookie does not have the secure flag set. Over an HTTP connection the session token is transmitted in plaintext and can be intercepted by a network attacker.',
      'Semgrep', 'Set secure: process.env.NODE_ENV === "production" so the flag is active in production HTTPS deployments while remaining usable in local HTTP dev.', null]
  ];

  scaFindings.forEach(f => scaStmt.run(...f));

  // -------------------------------------------------------
  // DAST Scenarios (6 hands-on exploit scenarios)
  // -------------------------------------------------------
  console.log('Seeding DAST scenarios...');
  const dastStmt = db.prepare(`
    INSERT INTO dast_scenarios (id, title, vulnerability_type, owasp_category, severity, description, precondition, steps, exploit_url, expected_finding, affected_file, affected_lines, cvss_base_score, active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const dastScenarios = [
    [1, 'IDOR: Access Another Student\'s Grades',
      'Insecure Direct Object Reference', 'A01:2021 - Broken Access Control', 'High',
      'When RBAC is disabled the server skips ownership checks. A student can view any other student\'s grades by modifying the student ID in the URL.',
      'rbac_disabled',
      JSON.stringify([
        'Log in as alice_student (password: student123)',
        'Navigate to My Classes and note your student ID in the URL',
        'Go to /classes and find a class you are not enrolled in',
        'Manually change the student ID in the URL to another student\'s ID (e.g., try IDs 1-8)',
        'Observe that you can read enrolment records and grades belonging to other students',
        'Document the affected URL, the IDs you were able to access, and the data exposed'
      ]),
      '/classes', 'Student can read grade records belonging to other users without authorisation',
      'routes/classes.js', '39-55', '7.5', 1],

    [2, 'Plaintext Password Storage in Database',
      'Sensitive Data Exposure', 'A02:2021 - Cryptographic Failures', 'Critical',
      'Passwords are stored in plaintext in the JSON database. Anyone who can read the database file — or trigger a backup download — obtains every user\'s password.',
      'none',
      JSON.stringify([
        'Log in as admin (password: admin123)',
        'Go to Admin → Backup & Restore',
        'Click "Create Backup Now" then download the backup file',
        'Open the JSON file and locate the users array',
        'Observe that the password field contains the plaintext password for every user',
        'Note that you can now log in as any user without needing to crack any hash'
      ]),
      '/admin/backup', 'Plaintext passwords visible in the database backup',
      'config/database.js', '225-243', '9.1', 1],

    [3, 'CSRF: Force Admin to Disable Security Feature',
      'Cross-Site Request Forgery', 'A01:2021 - Broken Access Control', 'High',
      'State-changing POST requests do not include CSRF tokens. An attacker can craft a page that, when visited by a logged-in admin, silently disables a security setting.',
      'none',
      JSON.stringify([
        'Log in as admin and note that Audit Logging is currently enabled',
        'Open browser DevTools → Network tab',
        'Toggle Audit Logging off and on, capture the POST request',
        'Craft an HTML page with a hidden form that submits the same POST to the same URL',
        'Send the link to the admin (or open it in a second tab while still logged in as admin)',
        'Observe that the security setting changes without any CSRF token being required'
      ]),
      '/admin/security', 'Security settings can be changed by a forged cross-origin request',
      'server.js', '1-50', '8.8', 1],

    [4, 'Brute Force MFA Verification (No Rate Limit)',
      'Brute Force', 'A07:2021 - Identification and Authentication Failures', 'Medium',
      'The MFA token verification endpoint does not enforce rate limiting. An attacker can automate requests to guess a 6-digit TOTP code (1 000 000 possible values) within seconds.',
      'none',
      JSON.stringify([
        'Enable MFA for alice_student from the profile page',
        'Log out, then attempt to log in as alice_student',
        'At the MFA prompt, intercept the POST /auth/verify-mfa request with Burp Suite or a script',
        'Send 1000 sequential 6-digit codes via repeater/intruder in under 60 seconds',
        'Observe that none of the requests return a 429 Too Many Requests response',
        'Note that a real attacker could exhaust the full keyspace in ~17 minutes'
      ]),
      '/auth/verify-mfa', 'MFA verification accepts unlimited attempts with no lockout',
      'middleware/rateLimiter.js', '1-30', '6.5', 1],

    [5, 'Credentials Exposed in Server Logs',
      'Sensitive Data Exposure', 'A09:2021 - Security Logging and Monitoring Failures', 'High',
      'The server logs the plaintext username and password on every login attempt. The logs are accessible in the admin panel.',
      'none',
      JSON.stringify([
        'Log in as admin and open the Audit Logs page',
        'In a second tab, attempt to log in as any user (successful or failed)',
        'Return to Audit Logs and observe the new entry',
        'If you have server console access, inspect the console output for the login attempt',
        'Note the plaintext password visible in the console/log entry',
        'Consider the impact if these logs are shipped to a centralised log system'
      ]),
      '/admin/audit-logs', 'User passwords appear in plaintext in application logs',
      'server.js', '135-145', '7.5', 1],

    [6, 'Path Traversal: Read Arbitrary Server Files via Backup Download',
      'Path Traversal', 'A01:2021 - Broken Access Control', 'High',
      'The backup download endpoint uses the filename from the URL without sanitisation. An admin (or attacker with admin access) can request any file on the server.',
      'none',
      JSON.stringify([
        'Log in as admin',
        'Navigate to Admin → Backup & Restore and create at least one backup',
        'Note the backup filename format: backup-YYYY-MM-DD-HHMMSS.json',
        'Modify the download URL, replacing the filename with: ../../package.json',
        'Observe that the server returns the contents of package.json',
        'Try ../../.env or ../../config/database.js to see what other files are readable'
      ]),
      '/admin/backup/download', 'Path traversal allows reading arbitrary server files',
      'routes/admin.js', '430-445', '8.1', 1]
  ];

  dastScenarios.forEach(s => dastStmt.run(...s));

  // -------------------------------------------------------
  // VM Vulnerabilities (12 pre-populated findings)
  // -------------------------------------------------------
  console.log('Seeding VM vulnerabilities...');
  const vmStmt = db.prepare(`
    INSERT INTO vulnerabilities (id, title, source, source_id, owasp_category, cwe, cvss_vector, cvss_score, severity, affected_component, description, status, assigned_to, priority, remediation_plan, remediation_deadline, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();
  const vmVulns = [
    [1, 'Hardcoded Session Secret', 'sca', 1,
      'A02:2021 - Cryptographic Failures', 'CWE-798',
      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', 8.1,
      'Critical', 'server.js',
      'Session secret is hardcoded in source code, allowing forged session tokens.',
      'open', null, 1, null, null, now, now],

    [2, 'Hardcoded AES Encryption Key', 'sca', 2,
      'A02:2021 - Cryptographic Failures', 'CWE-321',
      'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N', 6.5,
      'Critical', 'utils/encryption.js',
      'AES key is hardcoded; compromise exposes all encrypted PII.',
      'in_progress', null, 1, 'Migrate to environment variable ENCRYPTION_KEY', null, now, now],

    [3, 'Plaintext Password Comparison', 'sca', 4,
      'A07:2021 - Identification and Authentication Failures', 'CWE-256',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5,
      'Critical', 'routes/auth.js',
      'Passwords stored and compared in plaintext; database breach exposes all credentials immediately.',
      'open', null, 1, null, null, now, now],

    [4, 'Plaintext Credentials in Logs', 'dast', 5,
      'A09:2021 - Security Logging and Monitoring Failures', 'CWE-312',
      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5,
      'High', 'server.js',
      'Plaintext passwords are logged on every authentication attempt.',
      'open', null, 2, null, null, now, now],

    [5, 'IDOR via Disabled RBAC', 'dast', 1,
      'A01:2021 - Broken Access Control', 'CWE-639',
      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 6.5,
      'High', 'routes/classes.js',
      'When RBAC is off, ownership checks are skipped; students can view peer grades.',
      'open', null, 2, null, null, now, now],

    [6, 'CSRF on Security Settings Endpoint', 'dast', 3,
      'A01:2021 - Broken Access Control', 'CWE-352',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N', 6.5,
      'High', 'server.js',
      'No CSRF protection on POST endpoints; forged requests can silently alter security settings.',
      'open', null, 2, null, null, now, now],

    [7, 'Path Traversal in Backup Download', 'sca', 10,
      'A01:2021 - Broken Access Control', 'CWE-22',
      'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N', 4.9,
      'High', 'routes/admin.js',
      'Backup filename from URL is not sanitised; arbitrary server files can be read.',
      'open', null, 2, null, null, now, now],

    [8, 'Brute Force: No MFA Rate Limit', 'dast', 4,
      'A07:2021 - Identification and Authentication Failures', 'CWE-307',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', 6.5,
      'Medium', 'middleware/rateLimiter.js',
      'MFA verification endpoint has no rate limit, allowing brute-force of 6-digit codes.',
      'in_progress', null, 3, 'Add rate limiting to /auth/verify-mfa', null, now, now],

    [9, 'No HTTP Security Headers', 'sca', 9,
      'A05:2021 - Security Misconfiguration', 'CWE-693',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N', 4.3,
      'Medium', 'server.js',
      'Missing helmet headers leave the app vulnerable to clickjacking and MIME-sniffing.',
      'resolved', null, 3, 'Install helmet middleware', null, now, now],

    [10, 'Session Cookie Missing secure Flag', 'sca', 12,
      'A02:2021 - Cryptographic Failures', 'CWE-614',
      'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 3.7,
      'Medium', 'server.js',
      'Session cookie transmitted over HTTP without secure flag; interceptable by MITM.',
      'open', null, 3, null, null, now, now],

    [11, 'Outdated express-session Dependency', 'sca', 11,
      'A06:2021 - Vulnerable and Outdated Components', 'CWE-1035',
      'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3,
      'Medium', 'package.json',
      'express-session version may have known CVEs; dependency should be updated.',
      'wont_fix', null, 4, 'Accepted risk for classroom demo; revisit before production use', null, now, now],

    [12, 'Audit Logging Defaults to OFF', 'sca', 5,
      'A09:2021 - Security Logging and Monitoring Failures', 'CWE-778',
      'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N', 2.7,
      'Low', 'config/database.js',
      'Audit logging is disabled by default; security events go unrecorded.',
      'open', null, 4, null, null, now, now]
  ];

  vmVulns.forEach(v => vmStmt.run(...v));

  console.log('Database seeded successfully!');
  console.log('Created:');
  console.log('  - 8 users (1 admin, 2 professors, 5 students)');
  console.log('  - 3 classes (CS101, CS201, CS301)');
  console.log('  - 36 sessions (12 per class)');
  console.log('  - 9 enrollments');
  console.log('  - 12 SCA findings');
  console.log('  - 6 DAST scenarios');
  console.log('  - 12 VM vulnerabilities');
}

module.exports = { seedDatabase };
