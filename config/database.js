const path = require('path');
const fs = require('fs');

const dbDir = path.join(__dirname, '..', 'database');
const dbPath = path.join(dbDir, 'data.json');

// Ensure database directory exists
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// In-memory database structure
let db = {
  users: [],
  classes: [],
  sessions: [],
  enrollments: [],
  security_settings: [{ id: 1, mfa_enabled: 0, rbac_enabled: 1, encryption_at_rest: 0, field_encryption: 0, https_enabled: 0, audit_logging: 0, rate_limiting: 0 }],
  audit_logs: [],
  rate_limit_attempts: [],
  _counters: { users: 0, classes: 0, sessions: 0, enrollments: 0, audit_logs: 0, rate_limit_attempts: 0 }
};

// Load database from file if exists
function loadDatabase() {
  if (fs.existsSync(dbPath)) {
    try {
      const data = fs.readFileSync(dbPath, 'utf8');
      db = JSON.parse(data);
      console.log('Database loaded from file');
    } catch (error) {
      console.error('Error loading database:', error.message);
    }
  }
}

// Save database to file
function saveDatabase() {
  try {
    fs.writeFileSync(dbPath, JSON.stringify(db, null, 2), 'utf8');
  } catch (error) {
    console.error('Error saving database:', error.message);
  }
}

// Simple query interface to mimic SQL
const dbInterface = {
  prepare: (sql) => ({
    run: (...params) => {
      const result = executeSQL(sql, params);
      saveDatabase();
      return result;
    },
    get: (...params) => executeSQL(sql, params),
    all: (...params) => executeSQL(sql, params)
  }),
  exec: (sql) => {
    // For schema creation, just ignore (we use JSON structure)
    return;
  }
};

function executeSQL(sql, params = []) {
  sql = sql.trim();

  // SELECT queries
  if (sql.startsWith('SELECT')) {
    if (sql.includes('FROM users')) {
      if (sql.includes('WHERE username')) {
        return db.users.find(u => u.username === params[0]) || null;
      }
      if (sql.includes('WHERE id')) {
        return db.users.find(u => u.id === params[0]) || null;
      }
      if (sql.includes('WHERE role')) {
        return db.users.filter(u => u.role === params[0]);
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.users.length };
      }
      if (sql.includes('last_login')) {
        return db.users.filter(u => u.last_login).sort((a, b) => new Date(b.last_login) - new Date(a.last_login)).slice(0, 5);
      }
      return db.users;
    }

    if (sql.includes('FROM classes')) {
      if (sql.includes('WHERE id')) {
        const cls = db.classes.find(c => c.id === parseInt(params[0]));
        if (cls && sql.includes('u.username')) {
          const prof = db.users.find(u => u.id === cls.professor_id);
          return { ...cls, professor_name: prof ? prof.username : null };
        }
        return cls || null;
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.classes.length };
      }
      if (sql.includes('enrolled_count')) {
        return db.classes.map(c => ({
          ...c,
          enrolled_count: db.enrollments.filter(e => e.class_id === c.id).length
        }));
      }
      if (sql.includes('WHERE code')) {
        return db.classes.find(c => c.code === params[0]) || null;
      }
      return db.classes;
    }

    if (sql.includes('FROM sessions')) {
      if (sql.includes('WHERE id')) {
        const session = db.sessions.find(s => s.id === parseInt(params[0]));
        if (session && sql.includes('c.code')) {
          const cls = db.classes.find(c => c.id === session.class_id);
          return { ...session, class_code: cls?.code, class_name: cls?.name };
        }
        return session || null;
      }
      if (sql.includes('WHERE class_id')) {
        return db.sessions.filter(s => s.class_id === parseInt(params[0])).sort((a, b) => a.session_number - b.session_number);
      }
      return db.sessions;
    }

    if (sql.includes('FROM enrollments')) {
      if (sql.includes('WHERE student_id') && sql.includes('AND class_id')) {
        return db.enrollments.find(e => e.student_id === params[0] && e.class_id === params[1]) || null;
      }
      if (sql.includes('WHERE student_id')) {
        const studentId = params[0];
        return db.enrollments.filter(e => e.student_id === studentId).map(e => {
          const cls = db.classes.find(c => c.id === e.class_id);
          return { ...e, ...cls };
        });
      }
      if (sql.includes('WHERE class_id')) {
        const classId = params[0];
        return db.enrollments.filter(e => e.class_id === classId).map(e => {
          const user = db.users.find(u => u.id === e.student_id);
          return { ...e, ...user };
        });
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.enrollments.length };
      }
      return db.enrollments;
    }

    if (sql.includes('FROM security_settings')) {
      return db.security_settings[0] || null;
    }

    if (sql.includes('FROM audit_logs')) {
      if (sql.includes('LIMIT') && sql.includes('OFFSET')) {
        const limit = parseInt(params[0]);
        const offset = parseInt(params[1]);
        return db.audit_logs.slice().reverse().slice(offset, offset + limit);
      }
      if (sql.includes('COUNT(*)')) {
        return { count: db.audit_logs.length };
      }
      return db.audit_logs.slice().reverse();
    }

    if (sql.includes('FROM rate_limit_attempts')) {
      if (sql.includes('COUNT(*)') && sql.includes('WHERE')) {
        const ip = params[0];
        const since = params[1];
        return { count: db.rate_limit_attempts.filter(a => a.ip_address === ip && a.attempt_time > since && a.success === 0).length };
      }
      if (sql.includes('ORDER BY attempt_time')) {
        const ip = params[0];
        const since = params[1];
        const attempt = db.rate_limit_attempts.filter(a => a.ip_address === ip && a.attempt_time > since && a.success === 0)[0];
        return attempt || null;
      }
    }
  }

  // INSERT queries
  if (sql.startsWith('INSERT INTO')) {
    if (sql.includes('INTO users')) {
      const user = {
        id: ++db._counters.users,
        username: params[0],
        email: params[1],
        password: params[2],
        password_hash: null,
        password_is_hashed: 0,
        role: params[3],
        ssn: params[4] || null,
        ssn_encrypted: 0,
        mfa_enabled: 0,
        mfa_secret: null,
        mfa_backup_codes: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_login: null
      };
      db.users.push(user);
      return { lastID: user.id, changes: 1 };
    }

    if (sql.includes('INTO classes')) {
      const cls = {
        id: ++db._counters.classes,
        code: params[0],
        name: params[1],
        description: params[2],
        semester: params[3],
        professor_id: params[4],
        created_at: new Date().toISOString()
      };
      db.classes.push(cls);
      return { lastID: cls.id, changes: 1 };
    }

    if (sql.includes('INTO sessions')) {
      const session = {
        id: ++db._counters.sessions,
        class_id: params[0],
        session_number: params[1],
        title: params[2],
        description: params[3],
        content: params[4],
        date: params[5],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      db.sessions.push(session);
      return { lastID: session.id, changes: 1 };
    }

    if (sql.includes('INTO enrollments')) {
      const enrollment = {
        id: ++db._counters.enrollments,
        student_id: params[0],
        class_id: params[1],
        grade: params[2] || null,
        grade_encrypted: 0,
        enrolled_date: new Date().toISOString()
      };
      db.enrollments.push(enrollment);
      return { lastID: enrollment.id, changes: 1 };
    }

    if (sql.includes('INTO audit_logs')) {
      const log = {
        id: ++db._counters.audit_logs,
        user_id: params[0],
        username: params[1],
        role: params[2],
        action: params[3],
        resource_type: params[4] || null,
        resource_id: params[5] || null,
        ip_address: params[6] || null,
        user_agent: params[7] || null,
        details: params[8] || null,
        success: params[9] !== undefined ? params[9] : 1,
        timestamp: new Date().toISOString()
      };
      db.audit_logs.push(log);
      return { lastID: log.id, changes: 1 };
    }

    if (sql.includes('INTO rate_limit_attempts')) {
      const attempt = {
        id: ++db._counters.rate_limit_attempts,
        ip_address: params[0],
        username: params[1],
        attempt_time: new Date().toISOString(),
        success: params[2] || 0
      };
      db.rate_limit_attempts.push(attempt);
      return { lastID: attempt.id, changes: 1 };
    }
  }

  // UPDATE queries
  if (sql.startsWith('UPDATE')) {
    if (sql.includes('UPDATE users')) {
      const userId = params[params.length - 1];
      const user = db.users.find(u => u.id === userId);
      if (user) {
        if (sql.includes('password_hash')) {
          user.password_hash = params[0];
          user.password_is_hashed = params[1];
        }
        if (sql.includes('password_is_hashed')) {
          user.password_is_hashed = params[0];
          user.password_hash = null;
        }
        if (sql.includes('ssn =')) {
          user.ssn = params[0];
          user.ssn_encrypted = params[1];
        }
        if (sql.includes('mfa_enabled')) {
          if (sql.includes('mfa_secret')) {
            user.mfa_enabled = params[0];
            user.mfa_secret = params[1];
          } else {
            user.mfa_enabled = 0;
            user.mfa_secret = null;
            user.mfa_backup_codes = null;
          }
        }
        if (sql.includes('last_login')) {
          user.last_login = new Date().toISOString();
        }
        user.updated_at = new Date().toISOString();
      }
      return { changes: user ? 1 : 0 };
    }

    if (sql.includes('UPDATE sessions')) {
      const sessionId = params[params.length - 1];
      const session = db.sessions.find(s => s.id === sessionId);
      if (session) {
        session.title = params[0];
        session.description = params[1];
        session.content = params[2];
        session.updated_at = new Date().toISOString();
      }
      return { changes: session ? 1 : 0 };
    }

    if (sql.includes('UPDATE enrollments')) {
      const enrollmentId = params[params.length - 1];
      const enrollment = db.enrollments.find(e => e.id === enrollmentId);
      if (enrollment) {
        enrollment.grade = params[0];
        enrollment.grade_encrypted = params[1];
      }
      return { changes: enrollment ? 1 : 0 };
    }

    if (sql.includes('UPDATE security_settings')) {
      const settings = db.security_settings[0];
      if (sql.includes('mfa_enabled')) settings.mfa_enabled = params[0];
      if (sql.includes('rbac_enabled')) settings.rbac_enabled = params[0];
      if (sql.includes('encryption_at_rest')) settings.encryption_at_rest = params[0];
      if (sql.includes('field_encryption')) settings.field_encryption = params[0];
      if (sql.includes('https_enabled')) settings.https_enabled = params[0];
      if (sql.includes('audit_logging')) settings.audit_logging = params[0];
      if (sql.includes('rate_limiting')) settings.rate_limiting = params[0];
      settings.updated_at = new Date().toISOString();
      return { changes: 1 };
    }
  }

  // DELETE queries
  if (sql.startsWith('DELETE FROM')) {
    if (sql.includes('FROM users')) {
      db.users = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM classes')) {
      db.classes = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM sessions')) {
      db.sessions = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM enrollments')) {
      db.enrollments = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM audit_logs')) {
      db.audit_logs = [];
      return { changes: 1 };
    }
    if (sql.includes('FROM rate_limit_attempts')) {
      if (sql.includes('WHERE')) {
        const before = db.rate_limit_attempts.length;
        const since = params[0];
        db.rate_limit_attempts = db.rate_limit_attempts.filter(a => a.attempt_time >= since);
        return { changes: before - db.rate_limit_attempts.length };
      }
      db.rate_limit_attempts = [];
      return { changes: 1 };
    }
  }

  return null;
}

// Load database on startup
loadDatabase();

// Initialize database schema
function initializeDatabase() {
  // Just ensure the structure exists
  if (!db.security_settings || db.security_settings.length === 0) {
    db.security_settings = [{
      id: 1,
      mfa_enabled: 0,
      rbac_enabled: 1,
      encryption_at_rest: 0,
      field_encryption: 0,
      https_enabled: 0,
      audit_logging: 0,
      rate_limiting: 0,
      updated_at: new Date().toISOString()
    }];
  }
  saveDatabase();
  console.log('Database initialized successfully');
}

// Check if database has been seeded
function isDatabaseSeeded() {
  return db.users.length > 0;
}

module.exports = {
  db: dbInterface,
  initializeDatabase,
  isDatabaseSeeded
};
