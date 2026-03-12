# Testing Patterns

**Analysis Date:** 2026-03-12

## Test Framework

**Runner:**
- No standard test framework (no Jest, Vitest, or Mocha in `package.json`)
- Custom smoke test script: `scripts/smoke-test.js`
- Tests execute as a plain Node.js script making HTTP requests against a running server

**Assertion Library:**
- No formal assertion library (no chai, expect, assert imported)
- Custom pass/fail tracking via `addResult(category, name, passed, details)` function

**Run Commands:**
```bash
npm test              # Run smoke tests, generate HTML report (scripts/smoke-test.js)
npm run test:open     # Run smoke tests and open HTML report in browser
```

## Test File Organization

**Location:**
- Single test file at `scripts/smoke-test.js`
- Not co-located with source files; no per-module test files exist
- No `__tests__/` or `test/` directories

**Naming:**
- `smoke-test.js` is the only test file in the project

**Structure:**
```
scripts/
├── smoke-test.js         # Sole test runner (HTTP integration tests)
├── classroom-manager.js  # Not a test file
├── classroom-stop.js     # Not a test file
└── setup.js              # Not a test file

test-report.html          # Generated HTML report (not committed)
```

## Test Structure

**Suite Organization:**
```javascript
// Test configuration at top of scripts/smoke-test.js
const BASE_URL = process.env.TEST_URL || 'http://localhost:3001';
const REPORT_PATH = path.join(__dirname, '..', 'test-report.html');

// Test subjects defined as data arrays
const TEST_ACCOUNTS = [
  {
    username: 'admin',
    password: 'admin123',
    role: 'admin',
    expectedPages: ['/dashboard', '/admin/security', '/admin/audit-logs']
  },
  {
    username: 'prof_jones',
    password: 'prof123',
    role: 'professor',
    expectedPages: ['/dashboard']
  },
  {
    username: 'alice_student',
    password: 'student123',
    role: 'student',
    expectedPages: ['/dashboard']
  }
];

const PUBLIC_PAGES = [
  { path: '/', name: 'Login Page' }
];

// Results tracker
const results = {
  startTime: new Date(),
  endTime: null,
  passed: 0,
  failed: 0,
  tests: []
};
```

**Execution Flow:**
1. Define test accounts and expected pages
2. Execute HTTP requests (login, navigate, verify status codes)
3. Track results via `addResult(category, name, passed, details)`
4. Generate HTML report to `test-report.html`
5. Optionally open report in browser (`--open` flag)

**Result Tracking Pattern:**
```javascript
function addResult(category, name, passed, details = '') {
  results.tests.push({
    category,
    name,
    passed,
    details,
    timestamp: new Date()
  });

  if (passed) {
    results.passed++;
  } else {
    results.failed++;
  }
}
```

## HTTP Request Helper

**Custom HTTP client (from `scripts/smoke-test.js`):**
```javascript
function request(options) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.url);
    const protocol = url.protocol === 'https:' ? https : http;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      rejectUnauthorized: false // Allow self-signed certs
    };

    const req = protocol.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}
```

## Session Management in Tests

**Cookie Extraction Pattern:**
```javascript
function getSessionCookie(response) {
  const setCookie = response.headers['set-cookie'];
  if (!setCookie) return null;

  for (const cookie of setCookie) {
    if (cookie.includes('connect.sid')) {
      return cookie.split(';')[0];
    }
  }
  return null;
}
```

**Authentication Flow in Tests:**
1. POST to `/auth/login` with credentials
2. Extract `connect.sid` session cookie from response headers
3. Pass cookie in subsequent requests to access protected pages

## Mocking

**Framework:** None. No mocking library is used.

**Approach:**
- All tests are integration tests against a real running server
- Real database (JSON file) is used, auto-initialized with seed data
- Real authentication flow exercised (session cookies, bcrypt password comparison)
- Self-signed SSL certificates accepted for HTTPS testing

**What to Mock (if adding unit tests):**
- `config/database.js` - the db interface (prepare/run/get/all)
- `req.securitySettings` - injected by middleware
- `req.session` - Express session object
- External crypto operations (bcrypt, crypto module)

**What NOT to Mock:**
- Express routing/middleware chain (test through HTTP)
- View rendering (test via response body content)

## Fixtures and Factories

**Test Data:**
- Pre-seeded accounts defined in `utils/seedData.js`, loaded on first database initialization
- Three test user roles:
  - `admin` / `admin123` (admin role)
  - `prof_jones` / `prof123` (professor role)
  - `alice_student` / `student123` (student role)
- Additional seed data: classes, enrollments, SCA findings, DAST scenarios, vulnerabilities, pentest engagements

**Location:**
- Seed data logic: `utils/seedData.js`
- Test account definitions: hardcoded in `scripts/smoke-test.js`
- No separate fixtures directory

**Database Reset:**
- Delete `database/data.json` to reset all data
- Database auto-seeds on next startup via `isDatabaseSeeded()` check in `server.js`

## Coverage

**Requirements:**
- No coverage tool configured (no istanbul, c8, nyc)
- No coverage targets or thresholds enforced

**View Coverage:**
- Not available; no coverage reporting

## Test Types

**Unit Tests:**
- Not present. No unit test framework or files detected.
- No isolated function-level testing of utilities, middleware, or database logic.

**Integration Tests:**
- Custom smoke test (`scripts/smoke-test.js`) provides basic integration coverage:
  - Login flow for each role (admin, professor, student)
  - Session cookie persistence across requests
  - Role-based page access verification
  - Public page availability
  - Health check endpoint

**E2E Tests:**
- No dedicated E2E framework (no Playwright, Cypress, Puppeteer)
- Smoke test acts as minimal E2E coverage (full HTTP request/response cycle)

## Common Patterns

**Async Testing:**
```javascript
// All test operations use async/await with the custom request() helper
const loginResponse = await request({
  url: `${BASE_URL}/auth/login`,
  method: 'POST',
  body: `username=${account.username}&password=${account.password}`,
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
});

const sessionCookie = getSessionCookie(loginResponse);

const pageResponse = await request({
  url: `${BASE_URL}${page}`,
  headers: { Cookie: sessionCookie }
});
```

**Status Code Validation:**
- 200: successful page load
- 302: redirect (successful login redirects to dashboard)
- 403: access denied (RBAC blocks unauthorized role)
- 429: rate limited (too many failed login attempts)

**Test Categories:**
Tests are grouped by category in the HTML report:
- "Public Access" - unauthenticated page tests
- "Admin Access" - admin login and admin-only pages
- "Professor Access" - professor login and pages
- "Student Access" - student login and pages

## Test Execution Environment

**Prerequisites:**
- Server must be running before tests execute
- Default test target: `http://localhost:3001` (first team instance)
- Configurable via `TEST_URL` environment variable

**Example Usage:**
```bash
# Start server first
npm start

# In another terminal, run tests against default URL
npm test

# Or target a specific instance
TEST_URL=http://localhost:3005 npm test

# Test HTTPS endpoint
TEST_URL=https://localhost:3443 npm test
```

**Test Database:**
- Uses same database as running server (no test isolation)
- Auto-initialized with seed data on first run
- State persists between test runs
- Reset by deleting `database/data.json` and restarting server

## Report Output

**Format:** HTML file generated at project root as `test-report.html`

**Contents:**
- Summary: total tests, passed count, failed count, execution time
- Per-test table: category, test name, pass/fail status, details, timestamp
- Color-coded results (green = pass, red = fail)

**Opening:**
- `npm run test:open` automatically opens report in default browser
- Report path: `{project-root}/test-report.html`

## Gaps and Recommendations

**Missing:**
- No unit test framework for isolated function testing
- No test coverage measurement
- No test isolation (shared database between app and tests)
- No CI pipeline running tests automatically
- No mocking for external dependencies
- No snapshot testing for views/templates

**If adding tests, follow these patterns:**
- Place test files adjacent to source: `utils/passwordHash.test.js`
- Use Jest or Vitest (common for Node.js projects)
- Mock `config/database.js` db interface for unit tests
- Create test fixtures in a `__fixtures__/` directory
- Add `npm run test:unit` script separate from smoke tests

---

*Testing analysis: 2026-03-12*
