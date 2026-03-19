# Phase 8: Testing - Research

**Researched:** 2026-03-19
**Domain:** Node.js built-in test runner (`node:test`), HTTP integration testing, session-based auth testing
**Confidence:** HIGH

## Summary

Phase 8 adds integration tests for three security-critical behaviors: SCA review submission persistence (TEST-01), answer key role-gating (TEST-02), and API endpoint authentication (TEST-03). The user has locked all major decisions: use `node:test` + `node:assert` (zero new dependencies), create a `test/` directory with one file per requirement, share helpers via `test/helpers.js`, and run tests against a live server at `http://localhost:3001`.

The codebase already has a proven pattern for HTTP integration testing in `scripts/smoke-test.js` -- the `request()` and `getSessionCookie()` functions there are the template for `test/helpers.js`. Node.js v20.20.0 is installed and `node:test` with all required APIs (`describe`, `it`, `before`, `after`, `beforeEach`, `assert.strictEqual`, `assert.ok`, `assert.match`, `assert.deepStrictEqual`) is confirmed available. The `node --test` CLI runner supports `--test-reporter`, `--test-timeout`, `--test-concurrency`, and `--test-name-pattern` flags.

**Primary recommendation:** Build three test files following the locked CONTEXT.md structure, replicating the smoke-test.js HTTP helper pattern (not importing from it), and adding a minimal stub route at `GET /sca/answer-key` with role-gating for TEST-02.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions
- Use Node.js built-in test runner (`node:test` + `node:assert`) -- zero new dependencies, respects project constraint
- New `npm run test:integration` script -- existing `npm test` (smoke test) stays unchanged
- Console-only output (TAP/spec style) -- no HTML report generation
- Tests run via `node --test test/*.test.js`
- New top-level `test/` directory for integration tests
- One file per requirement: `test/sca-review.test.js` (TEST-01), `test/answer-key-gating.test.js` (TEST-02), `test/api-auth.test.js` (TEST-03)
- Shared helpers in `test/helpers.js` -- HTTP request(), getSessionCookie(), loginAs(role)
- Existing `scripts/smoke-test.js` left as-is (no refactor to shared helpers -- minimize risk to pre-class tool)
- Create a minimal stub route at `GET /sca/answer-key` in routes/sca.js
- Role-gated: `requireAuth, requireRole(['admin', 'professor'])`
- Returns JSON `{ placeholder: true, message: 'Answer key coming in Phase 12' }` for authorized users
- Students get 403 Forbidden (standard RBAC denial pattern)
- Phase 12 replaces the stub with real answer key content
- Rely on existing seed data -- no fresh database per run, no cleanup
- Test accounts: alice_student/student123 (student), prof_jones/prof123 (professor), admin/admin123 (admin)
- SCA review submission is idempotent (UPDATE if exists, INSERT if not) -- safe to re-run
- No database reset or backup/restore logic
- POST review via `/sca/findings/:id/review` as student, then GET `/sca/findings/:id` and verify response body contains submitted classification
- Requires a running server (same as smoke-test.js) -- no programmatic server startup
- Default target: `http://localhost:3001` (first team instance), configurable via TEST_URL env var
- Health check `/health` before running tests -- clear error message if server is down
- `test/helpers.js` exports: `request(options)`, `getSessionCookie(response)`, `loginAs(role)`
- `loginAs(role)` maps role to known credentials, POSTs login, returns session cookie
- Helpers extracted fresh (not imported from smoke-test.js to avoid coupling)

### Claude's Discretion
- Exact assertions and test case count per file
- Which SCA finding ID to use for TEST-01 review submission
- Error message wording for health check failure
- Whether to add a test:all script that runs both smoke and integration tests

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TEST-01 | Integration tests verify SCA review submission workflow (student submits classification, data persists) | POST `/sca/findings/:id/review` as student, verify via GET `/sca/findings/:id` that classification appears in response body. Route at `routes/sca.js` lines 189-223. Idempotent (UPDATE/INSERT). Use finding ID 1 (easy difficulty, always seeded). |
| TEST-02 | Integration tests verify answer key role-gating (student denied, instructor allowed) | Requires new stub route `GET /sca/answer-key` in `routes/sca.js` with `requireAuth, requireRole(['admin', 'professor'])`. Student gets 403 (rendered by `middleware/rbac.js` line 46), professor/admin get 200 with JSON. |
| TEST-03 | Integration tests verify /api/instructor-message and /api/summary require auth | Three endpoints in `server.js` lines 119-130 all use `requireAuth`. Unauthenticated requests get 302 redirect to `/?error=Please login first` (not 401). Test GET /api/instructor-message, POST /api/instructor-message, GET /api/summary without cookies. |

</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `node:test` | Built-in (Node 20) | Test runner with describe/it/before/after | Zero dependencies; stable in Node 20 LTS |
| `node:assert` | Built-in (Node 20) | Assertions (strictEqual, ok, match, deepStrictEqual) | Zero dependencies; pairs with node:test |
| `node:http` | Built-in | HTTP client for integration requests | Already used in smoke-test.js; zero dependencies |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| None | - | - | No additional dependencies needed |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| node:test | Jest/Mocha/Vitest | Would add dependencies -- violates project "no new dependencies" constraint |
| node:http | supertest/axios | Would add dependencies; supertest requires programmatic server startup which contradicts the "test against running server" decision |

**Installation:**
```bash
# No installation needed -- all built-in to Node.js 20
```

## Architecture Patterns

### Recommended Project Structure
```
test/
  helpers.js           # Shared HTTP helpers: request(), getSessionCookie(), loginAs()
  sca-review.test.js   # TEST-01: SCA review submission + persistence
  answer-key-gating.test.js  # TEST-02: Answer key role-gating (student denied, instructor allowed)
  api-auth.test.js     # TEST-03: API endpoints require authentication
routes/
  sca.js               # MODIFIED: Add GET /sca/answer-key stub route
package.json           # MODIFIED: Add test:integration script
```

### Pattern 1: Health Check Guard (before hook)
**What:** Before any test suite runs, verify the server is reachable via `/health`. If not, print a clear message and abort.
**When to use:** Every test file's top-level `before()` hook.
**Example:**
```javascript
// Source: Verified against codebase smoke-test.js pattern
const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, loginAs, BASE_URL } = require('./helpers');

describe('SCA Review Submission', () => {
  before(async () => {
    const res = await request({ url: `${BASE_URL}/health` }).catch(() => null);
    if (!res || res.statusCode !== 200) {
      console.error('Server not running. Start it first: npm start');
      process.exit(1);
    }
  });
});
```

### Pattern 2: loginAs(role) Helper
**What:** Maps role string to known seed credentials, performs POST login, returns session cookie string.
**When to use:** Any test that needs an authenticated session.
**Example:**
```javascript
// Source: Derived from smoke-test.js login pattern (lines 235-258)
const CREDENTIALS = {
  student:   { username: 'alice_student',  password: 'student123' },
  professor: { username: 'prof_jones',     password: 'prof123' },
  admin:     { username: 'admin',          password: 'admin123' }
};

async function loginAs(role) {
  const creds = CREDENTIALS[role];
  if (!creds) throw new Error(`Unknown role: ${role}`);
  const body = `username=${creds.username}&password=${creds.password}`;
  const res = await request({
    url: `${BASE_URL}/auth/login`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body).toString()
    },
    body
  });
  const cookie = getSessionCookie(res);
  if (!cookie) throw new Error(`Login failed for ${role}: status ${res.statusCode}`);
  return cookie;
}
```

### Pattern 3: Request Helper (replicated from smoke-test.js)
**What:** Promise-based HTTP request using `node:http` with timeout, returning `{ statusCode, headers, body }`.
**When to use:** Every HTTP call in the test suite.
**Critical detail:** The `request()` function in smoke-test.js (lines 54-93) is the exact template. Replicate it in `test/helpers.js` -- do NOT import from smoke-test.js.

### Pattern 4: Unauthenticated Request Assertion
**What:** `requireAuth` middleware returns a 302 redirect (NOT 401). Tests must check for `statusCode === 302`.
**When to use:** TEST-03 (API auth tests).
**Critical detail:** The middleware at `middleware/auth.js` line 8 does `res.redirect('/?error=Please login first')`, which is a 302 by default in Express. Tests should NOT follow redirects (the raw `node:http` request helper does not follow them, so this works naturally).

### Pattern 5: Role-Gating Assertion
**What:** `requireRole()` middleware returns 403 and renders an HTML error page with "Access Denied".
**When to use:** TEST-02 (answer key gating).
**Critical detail:** `middleware/rbac.js` line 46: `res.status(403).render('error', { message: 'Access Denied', ... })`. The student test should assert `statusCode === 403` and optionally check that the body contains "Access Denied".

### Anti-Patterns to Avoid
- **Importing from smoke-test.js:** Creates coupling between pre-class safety net and integration tests. CONTEXT.md explicitly says helpers are "extracted fresh".
- **Following redirects in the HTTP client:** The built-in `node:http` does NOT auto-follow 302s, which is exactly what TEST-03 needs. Do NOT add redirect-following logic.
- **Using programmatic server startup (supertest pattern):** CONTEXT.md locks the "running server" model. Tests assume the server is already running.
- **Database cleanup between tests:** CONTEXT.md explicitly says no cleanup. The review POST is idempotent (UPDATE if exists, INSERT if not), making re-runs safe.
- **Testing with `fetch()` instead of `node:http`:** Node 20 has global `fetch()`, but it auto-follows redirects by default, which would hide the 302 behavior TEST-03 needs to verify. Stick with `node:http`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP client | Custom fetch wrapper | Replicate smoke-test.js `request()` pattern | Proven pattern in this codebase, handles timeout, returns raw statusCode/headers/body |
| Session cookie extraction | Manual header parsing | Replicate smoke-test.js `getSessionCookie()` | Handles `set-cookie` array, `connect.sid` prefix extraction |
| Test framework | Custom test harness | `node:test` describe/it/before | Built-in, well-tested, exactly what CONTEXT.md specifies |

**Key insight:** The smoke-test.js file is a complete reference implementation for "HTTP integration testing against a running server with session-cookie auth" in this exact codebase. The helpers are simple enough (40 lines total) that fresh replication is safer than import coupling.

## Common Pitfalls

### Pitfall 1: Expecting 401 Instead of 302 for Unauthenticated API Requests
**What goes wrong:** Tests check for `statusCode === 401` on unauthenticated API calls, but the server returns 302.
**Why it happens:** `requireAuth` (middleware/auth.js) uses `res.redirect()`, not `res.status(401).json()`. This is standard for session-based Express apps -- the middleware was designed for browser users, not API clients.
**How to avoid:** Assert `statusCode === 302` in TEST-03. The redirect target is `/?error=Please login first`.
**Warning signs:** Tests fail with "expected 401, got 302".

### Pitfall 2: RBAC Bypass When security_settings.rbac_enabled is False
**What goes wrong:** `requireRole()` allows ALL roles through when `rbac_enabled` is 0 in security_settings.
**Why it happens:** `middleware/rbac.js` lines 13-16: if `req.securitySettings.rbac_enabled` is falsy, it sets `req.rbacBypass = true` and calls `next()`, skipping role checks entirely.
**How to avoid:** The default seed data has `rbac_enabled: 1` (database.js line 19). Tests rely on this being the default. Do not modify security settings in tests.
**Warning signs:** Student getting 200 instead of 403 on answer-key route.

### Pitfall 3: Content-Length Header Missing on POST Requests
**What goes wrong:** POST requests without `Content-Length` header may hang or fail silently.
**Why it happens:** The `node:http` module requires explicit `Content-Length` for POST bodies. The smoke-test.js pattern correctly includes it.
**How to avoid:** Always calculate and set `Content-Length: Buffer.byteLength(body).toString()` for POST requests.
**Warning signs:** Test hangs, times out on POST /auth/login or POST /sca/findings/:id/review.

### Pitfall 4: SCA Review POST Requires `action=submit` for Submitted Status
**What goes wrong:** POST to `/sca/findings/:id/review` creates a review with status `pending` instead of `submitted`.
**Why it happens:** Route at `routes/sca.js` line 198: `const isSubmit = action === 'submit'`. Without `action=submit` in the body, the review is saved as `pending` and `submitted_at` is null.
**How to avoid:** Include `action=submit` in the POST body along with `classification`.
**Warning signs:** GET `/sca/findings/:id` shows review but classification may not appear in rendered output for pending reviews.

### Pitfall 5: Finding Detail Page Shows Classification Differently for Student vs Instructor
**What goes wrong:** Verification step (GET /sca/findings/:id) doesn't find the submitted classification in the response body.
**Why it happens:** The finding detail page renders differently based on role. When logged in as student, `myReview` is populated; as instructor, `allReviews` is shown instead.
**How to avoid:** For TEST-01, log in as student, submit review, then GET the finding detail still as student. The rendered HTML will contain the classification value from `myReview`.
**Warning signs:** Test passes when checking as student but not when checking as a different role.

### Pitfall 6: Node --test Exit Code Behavior
**What goes wrong:** Test run exits 0 even when there are failures, or exits 1 when all tests pass.
**Why it happens:** `node --test` properly returns exit code 1 on failures in Node 20. However, the `process.exit(1)` call in the health check `before()` hook may not propagate correctly through the test runner.
**How to avoid:** Use `assert.fail()` instead of `process.exit(1)` for health check failures so the test runner handles it gracefully. Or throw an Error in the `before` hook.
**Warning signs:** `npm run test:integration` always exits 0, or health check failure produces confusing output.

## Code Examples

Verified patterns from the codebase and Node.js 20 APIs:

### test/helpers.js -- Complete Implementation Template
```javascript
// Source: Replicated from scripts/smoke-test.js (lines 54-108), adapted for test/helpers.js
const http = require('http');

const BASE_URL = process.env.TEST_URL || 'http://localhost:3001';
const REQUEST_TIMEOUT = 5000;

const CREDENTIALS = {
  student:   { username: 'alice_student',  password: 'student123' },
  professor: { username: 'prof_jones',     password: 'prof123' },
  admin:     { username: 'admin',          password: 'admin123' }
};

function request(options) {
  return new Promise((resolve, reject) => {
    const url = new URL(options.url);
    const reqOptions = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname + url.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };
    const timeout = options.timeout || REQUEST_TIMEOUT;
    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });
    req.setTimeout(timeout, () => { req.destroy(); reject(new Error(`Timeout after ${timeout}ms`)); });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function getSessionCookie(response) {
  const setCookie = response.headers['set-cookie'];
  if (!setCookie) return null;
  for (const cookie of setCookie) {
    if (cookie.includes('connect.sid')) return cookie.split(';')[0];
  }
  return null;
}

async function loginAs(role) {
  const creds = CREDENTIALS[role];
  if (!creds) throw new Error(`Unknown role: ${role}`);
  const body = `username=${creds.username}&password=${creds.password}`;
  const res = await request({
    url: `${BASE_URL}/auth/login`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body).toString()
    },
    body
  });
  const cookie = getSessionCookie(res);
  if (!cookie) throw new Error(`Login failed for role "${role}": status ${res.statusCode}`);
  return cookie;
}

module.exports = { request, getSessionCookie, loginAs, BASE_URL, REQUEST_TIMEOUT };
```

### test/sca-review.test.js -- TEST-01 Structure
```javascript
// Source: Based on routes/sca.js POST /sca/findings/:id/review (lines 189-223)
//         and GET /sca/findings/:id (lines 139-186)
const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, loginAs, BASE_URL } = require('./helpers');

describe('TEST-01: SCA Review Submission', () => {
  let studentCookie;

  before(async () => {
    // Health check
    const health = await request({ url: `${BASE_URL}/health` }).catch(() => null);
    assert.ok(health && health.statusCode === 200,
      'Server not running. Start it first: npm start');
    // Login as student
    studentCookie = await loginAs('student');
  });

  it('should submit a review classification and persist it', async () => {
    const findingId = 1; // Easy difficulty, always seeded
    const classification = 'confirmed';
    const body = `classification=${classification}&action=submit&student_notes=test+note`;

    // POST the review
    const postRes = await request({
      url: `${BASE_URL}/sca/findings/${findingId}/review`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body).toString(),
        'Cookie': studentCookie
      },
      body
    });
    // Expect redirect back to finding detail (302 or 303)
    assert.ok([302, 303].includes(postRes.statusCode),
      `Expected redirect, got ${postRes.statusCode}`);

    // GET the finding detail to verify persistence
    const getRes = await request({
      url: `${BASE_URL}/sca/findings/${findingId}`,
      headers: { 'Cookie': studentCookie }
    });
    assert.strictEqual(getRes.statusCode, 200);
    assert.ok(getRes.body.includes(classification),
      'Submitted classification not found in finding detail page');
  });
});
```

### test/api-auth.test.js -- TEST-03 Structure
```javascript
// Source: Based on server.js lines 119-130 (requireAuth on API endpoints)
//         and middleware/auth.js line 8 (302 redirect behavior)
const { describe, it, before } = require('node:test');
const assert = require('node:assert');
const { request, BASE_URL } = require('./helpers');

describe('TEST-03: API Endpoints Require Auth', () => {
  before(async () => {
    const health = await request({ url: `${BASE_URL}/health` }).catch(() => null);
    assert.ok(health && health.statusCode === 200,
      'Server not running. Start it first: npm start');
  });

  it('GET /api/instructor-message returns 302 without auth', async () => {
    const res = await request({ url: `${BASE_URL}/api/instructor-message` });
    assert.strictEqual(res.statusCode, 302);
  });

  it('POST /api/instructor-message returns 302 without auth', async () => {
    const body = JSON.stringify({ message: 'test' });
    const res = await request({
      url: `${BASE_URL}/api/instructor-message`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body).toString()
      },
      body
    });
    assert.strictEqual(res.statusCode, 302);
  });

  it('GET /api/summary returns 302 without auth', async () => {
    const res = await request({ url: `${BASE_URL}/api/summary` });
    assert.strictEqual(res.statusCode, 302);
  });
});
```

### Answer Key Stub Route -- routes/sca.js Addition
```javascript
// Source: CONTEXT.md decision -- stub for Phase 12
// Insert before module.exports in routes/sca.js

// --- GET /sca/answer-key --- Stub for Phase 12 (role-gated)
router.get('/answer-key', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  res.json({ placeholder: true, message: 'Answer key coming in Phase 12' });
});
```

### package.json Script Addition
```json
{
  "scripts": {
    "test:integration": "node --test test/*.test.js"
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `node:test` experimental | `node:test` stable | Node 18.17+ / Node 20 LTS | Full describe/it/before/after API stable; safe for production use |
| `--experimental-test-runner` flag | `--test` flag | Node 20 | No experimental flag needed |
| Manual TAP output parsing | Built-in `--test-reporter` | Node 20 | `spec`, `tap`, `dot` reporters available without packages |

**Deprecated/outdated:**
- `--experimental-test-runner` flag: no longer needed in Node 20, replaced by `--test`
- TAP-only output: Node 20 supports `--test-reporter=spec` for human-readable output

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, Node.js v20.20.0) |
| Config file | None needed -- uses CLI flags |
| Quick run command | `node --test test/*.test.js` |
| Full suite command | `npm run test:integration` (once script added) |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| TEST-01 | SCA review submission persists data | integration | `node --test --test-name-pattern="SCA Review" test/sca-review.test.js` | Wave 0 |
| TEST-02 | Answer key role-gating (student 403, instructor 200) | integration | `node --test --test-name-pattern="Answer Key" test/answer-key-gating.test.js` | Wave 0 |
| TEST-03 | API endpoints require auth (302 without cookie) | integration | `node --test --test-name-pattern="API.*Auth" test/api-auth.test.js` | Wave 0 |

### Sampling Rate
- **Per task commit:** `node --test test/*.test.js` (requires running server)
- **Per wave merge:** `npm run test:integration`
- **Phase gate:** All three test files pass green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `test/helpers.js` -- shared HTTP helpers (request, getSessionCookie, loginAs)
- [ ] `test/sca-review.test.js` -- covers TEST-01
- [ ] `test/answer-key-gating.test.js` -- covers TEST-02
- [ ] `test/api-auth.test.js` -- covers TEST-03
- [ ] `routes/sca.js` modification -- add `GET /sca/answer-key` stub route
- [ ] `package.json` modification -- add `test:integration` script
- [ ] No framework install needed (node:test is built-in)

## Open Questions

1. **Which SCA finding ID to use for TEST-01?**
   - What we know: 12 findings are seeded (IDs 1-12). Finding ID 1 is "easy" difficulty and always present.
   - What's unclear: Nothing unclear -- ID 1 is the simplest, most reliable choice.
   - Recommendation: Use finding ID 1. It is always seeded and easy difficulty.

2. **Should we add a `test:all` script?**
   - What we know: CONTEXT.md lists this as Claude's discretion. `npm test` runs smoke-test.js (requires all 13 ports). `npm run test:integration` runs against a single server.
   - What's unclear: Whether users would want to run both in sequence.
   - Recommendation: Add `"test:all": "npm test && npm run test:integration"` only if it does not confuse the smoke test (which needs all ports). Since smoke tests and integration tests target different servers/ports, a combined script may cause confusion. Skip `test:all` -- keep them separate.

3. **Review POST response: 302 vs JSON?**
   - What we know: `routes/sca.js` line 219 checks `req.headers.accept` for `application/json`. If Accept includes JSON, it returns `{ success: true }`. Otherwise, it redirects.
   - Recommendation: Use the form-encoded POST without `Accept: application/json` header (matching the browser form submission pattern). Expect 302 redirect. Then verify persistence via GET.

## Sources

### Primary (HIGH confidence)
- `scripts/smoke-test.js` -- Verified working HTTP integration test pattern with `request()` and `getSessionCookie()` functions
- `routes/sca.js` lines 189-223 -- POST `/sca/findings/:id/review` endpoint with UPDATE/INSERT idempotency
- `middleware/auth.js` lines 4-9 -- `requireAuth` redirects with 302 (not 401)
- `middleware/rbac.js` lines 7-54 -- `requireRole()` returns 403 with rendered error page; bypasses when rbac_enabled is false
- `server.js` lines 119-130 -- All three API endpoints use `requireAuth`
- `config/database.js` line 19 -- Default `rbac_enabled: 1` in security_settings
- `utils/seedData.js` lines 22-38 -- Seed accounts with known credentials
- Node.js v20.20.0 `node:test` API -- Verified locally: describe, it, before, after, beforeEach all available as functions

### Secondary (MEDIUM confidence)
- Node.js v20 `--test` CLI flags -- Verified via `node --help`: supports `--test-reporter`, `--test-timeout`, `--test-concurrency`, `--test-name-pattern`

### Tertiary (LOW confidence)
- None -- all findings verified against local codebase and runtime

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- node:test verified available in local Node 20.20.0 install; zero external dependencies
- Architecture: HIGH -- all patterns derived from existing codebase (smoke-test.js) and verified route implementations
- Pitfalls: HIGH -- all pitfalls confirmed by reading actual middleware code (auth.js returns 302, rbac.js checks rbac_enabled, sca.js requires action=submit)

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- built-in Node.js APIs, no external dependency versioning risk)
