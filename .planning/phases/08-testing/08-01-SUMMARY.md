---
phase: 08-testing
plan: 01
subsystem: testing
tags: [node-test, integration-testing, http, rbac, auth]

# Dependency graph
requires:
  - phase: 02-shared-ui-translation
    provides: French i18n error pages (403 renders "Acces refuse")
  - phase: 05-sca-lab
    provides: SCA routes, student review submission, finding detail pages
provides:
  - Integration test infrastructure (test/helpers.js with HTTP client, login, session helpers)
  - TEST-01 coverage for SCA review submission persistence
  - TEST-02 coverage for answer key role-gating (student 403, professor/admin 200)
  - TEST-03 coverage for API endpoint auth enforcement (302 without cookies)
  - GET /sca/answer-key stub route (Phase 12 placeholder)
  - test:integration npm script for CI use
affects: [12-instructor-answer-key, 14-code-quality]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "node:test (describe/it/before) for integration tests"
    - "node:http-based request helper that does NOT follow redirects"
    - "Role-based login helper via loginAs(role) returning session cookie"

key-files:
  created:
    - test/helpers.js
    - test/sca-review.test.js
    - test/answer-key-gating.test.js
    - test/api-auth.test.js
  modified:
    - routes/sca.js
    - package.json

key-decisions:
  - "Used French assertion text (refus) instead of English (Access Denied) -- error template uses i18n"
  - "No new npm dependencies -- only built-in node:test, node:assert, node:http"

patterns-established:
  - "Integration test pattern: health check in before() hook, login via helpers, assert on status codes"
  - "test/ directory structure: helpers.js shared, *.test.js per feature"

requirements-completed: [TEST-01, TEST-02, TEST-03]

# Metrics
duration: 3min
completed: 2026-03-19
---

# Phase 08 Plan 01: Integration Testing Summary

**9 integration tests covering SCA review persistence, answer-key role-gating, and API auth enforcement using node:test against a live server**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-19T21:13:16Z
- **Completed:** 2026-03-19T21:17:00Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Created reusable test infrastructure (helpers.js) with HTTP client, session cookie extraction, and role-based login
- Added 9 integration tests across 3 test files covering security-critical behaviors
- Added GET /sca/answer-key stub route with requireAuth + requireRole(['admin', 'professor']) for Phase 12
- All tests pass via `npm run test:integration` with zero new dependencies

## Task Commits

Each task was committed atomically:

1. **Task 1: Create test infrastructure** - `1861a9f` (feat)
2. **Task 2 RED: Failing integration tests** - `7ece8f9` (test)
3. **Task 2 GREEN: All tests passing** - `cb07601` (feat)

_Note: Task 2 followed TDD flow with RED (failing tests without server) and GREEN (passing tests with live server) commits._

## Files Created/Modified
- `test/helpers.js` - Shared HTTP helpers: request(), getSessionCookie(), loginAs(), BASE_URL
- `test/sca-review.test.js` - TEST-01: SCA review submission persistence (2 tests)
- `test/answer-key-gating.test.js` - TEST-02: Answer key role-gating by role (4 tests)
- `test/api-auth.test.js` - TEST-03: API endpoint auth enforcement (3 tests)
- `routes/sca.js` - Added GET /sca/answer-key stub route with role-gating
- `package.json` - Added test:integration npm script

## Decisions Made
- Used French assertion text ("refus") instead of English ("Access Denied") because the error template renders via i18n in French. The rbac.js middleware passes "Access Denied" as the message parameter, but the error.ejs template ignores it and uses `t('errors.forbiddenTitle')` which renders "Acces refuse".
- No new npm dependencies: used only built-in node:test, node:assert, and node:http.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed TEST-02 assertion for French error page text**
- **Found during:** Task 2 (TDD GREEN phase)
- **Issue:** Plan specified `assert body includes 'Access Denied'` but error template renders French "Acces refuse" via i18n, not the English message passed from rbac.js
- **Fix:** Changed assertion to check for 'refus' which matches the French "Acces refuse" rendered by error.ejs
- **Files modified:** test/answer-key-gating.test.js
- **Verification:** Test passes -- student gets 403 with "Acces refuse" in body
- **Committed in:** cb07601 (Task 2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary correction -- plan assumed English error text but app renders French. No scope creep.

## Issues Encountered
None beyond the deviation documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Test infrastructure established -- future phases can add test files following the same pattern
- helpers.js provides reusable login and HTTP utilities for any new integration tests
- Answer key stub route ready for Phase 12 implementation

## Self-Check: PASSED

- All 4 created files exist on disk
- All 3 task commits verified in git history (1861a9f, 7ece8f9, cb07601)

---
*Phase: 08-testing*
*Completed: 2026-03-19*
