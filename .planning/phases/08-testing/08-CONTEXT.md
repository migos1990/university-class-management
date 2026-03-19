# Phase 8: Testing - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Core user actions and security-critical paths have integration test coverage, catching regressions before they reach the classroom. Covers TEST-01 (SCA review submission), TEST-02 (answer key role-gating), and TEST-03 (API auth on /api/instructor-message and /api/summary).

</domain>

<decisions>
## Implementation Decisions

### Test framework
- Use Node.js built-in test runner (`node:test` + `node:assert`) — zero new dependencies, respects project constraint
- New `npm run test:integration` script — existing `npm test` (smoke test) stays unchanged
- Console-only output (TAP/spec style) — no HTML report generation
- Tests run via `node --test test/*.test.js`

### Test file structure
- New top-level `test/` directory for integration tests
- One file per requirement: `test/sca-review.test.js` (TEST-01), `test/answer-key-gating.test.js` (TEST-02), `test/api-auth.test.js` (TEST-03)
- Shared helpers in `test/helpers.js` — HTTP request(), getSessionCookie(), loginAs(role)
- Existing `scripts/smoke-test.js` left as-is (no refactor to shared helpers — minimize risk to pre-class tool)

### Answer key stub (TEST-02)
- Create a minimal stub route at `GET /sca/answer-key` in routes/sca.js
- Role-gated: `requireAuth, requireRole(['admin', 'professor'])`
- Returns JSON `{ placeholder: true, message: 'Answer key coming in Phase 12' }` for authorized users
- Students get 403 Forbidden (standard RBAC denial pattern)
- Phase 12 replaces the stub with real answer key content

### Test data & isolation
- Rely on existing seed data — no fresh database per run, no cleanup
- Test accounts: alice_student/student123 (student), prof_jones/prof123 (professor), admin/admin123 (admin)
- SCA review submission is idempotent (UPDATE if exists, INSERT if not) — safe to re-run
- No database reset or backup/restore logic

### Persistence verification (TEST-01)
- POST review via `/sca/findings/:id/review` as student, then GET `/sca/findings/:id` and verify response body contains submitted classification
- End-to-end verification that data actually persisted, not just success response

### Test execution model
- Requires a running server (same as smoke-test.js) — no programmatic server startup
- Default target: `http://localhost:3001` (first team instance), configurable via TEST_URL env var
- Health check `/health` before running tests — clear error message if server is down ("Start the server first: npm start")

### Shared test helpers
- `test/helpers.js` exports: `request(options)`, `getSessionCookie(response)`, `loginAs(role)`
- `loginAs(role)` maps role to known credentials, POSTs login, returns session cookie
- Helpers extracted fresh (not imported from smoke-test.js to avoid coupling)

### Claude's Discretion
- Exact assertions and test case count per file
- Which SCA finding ID to use for TEST-01 review submission
- Error message wording for health check failure
- Whether to add a test:all script that runs both smoke and integration tests

</decisions>

<specifics>
## Specific Ideas

- loginAs('student') pattern keeps tests readable: `const cookie = await loginAs('student')`
- Health check failure should print: "Server not running. Start it first: npm start"
- TEST-03 should test both GET and POST on /api/instructor-message plus GET on /api/summary — all three without auth should return 401/302

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/smoke-test.js`: Contains working `request()` and `getSessionCookie()` patterns to replicate in test/helpers.js
- `middleware/auth.js`: `requireAuth` middleware — already applied to the API endpoints (Phase 7)
- `middleware/rbac.js`: `requireRole()` middleware — used for answer key stub gating

### Established Patterns
- HTTP integration tests against running server (smoke-test.js pattern)
- Session cookie extraction via `connect.sid` from `set-cookie` header
- Role-based test accounts with known credentials hardcoded in seedData.js
- `requireRole(['admin', 'professor'])` for instructor-only routes (used 20+ times in codebase)

### Integration Points
- `routes/sca.js`: Add stub GET /sca/answer-key route with requireAuth + requireRole
- `package.json`: Add `test:integration` script
- `test/helpers.js`: New shared helper module
- `test/*.test.js`: Three new test files using node:test

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 08-testing*
*Context gathered: 2026-03-19*
