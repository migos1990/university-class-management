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

  console.log('Database seeded successfully!');
  console.log('Created:');
  console.log('  - 8 users (1 admin, 2 professors, 5 students)');
  console.log('  - 3 classes (CS101, CS201, CS301)');
  console.log('  - 36 sessions (12 per class)');
  console.log('  - 9 enrollments');
}

module.exports = { seedDatabase };
