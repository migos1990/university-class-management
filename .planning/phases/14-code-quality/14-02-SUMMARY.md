---
phase: 14-code-quality
plan: 02
subsystem: infra
tags: [eslint, prettier, linting, formatting, dead-code, code-quality]

# Dependency graph
requires:
  - phase: 14-code-quality-01
    provides: "ESLint 9 flat config, Prettier 3 config, npm scripts (lint, format)"
provides:
  - "Zero ESLint errors across entire codebase (27 linted JS files)"
  - "Consistent Prettier formatting on all JS files (27 formatted)"
  - "Dead code removed (unused imports, variables, functions)"
  - "All 12 intentional vulnerabilities preserved per SECURITY-BOUNDARY.md"
affects: [15-css-extraction, 16-ctf-pentest-lab]

# Tech tracking
tech-stack:
  added: []
  patterns: [underscore-prefix-catch-vars, caughtErrorsIgnorePattern, pentest-excluded-from-lint-and-format]

key-files:
  created: []
  modified: [eslint.config.js, .prettierignore, server.js, config/database.js, middleware/audit.js, routes/auth.js, routes/dashboard.js, routes/dast.js, routes/sca.js, scripts/classroom-manager.js, scripts/smoke-test.js, utils/encryption.js, config/security.js, middleware/rateLimiter.js, middleware/rbac.js, routes/admin.js, routes/classes.js, routes/sessions.js, routes/vm.js, scripts/classroom-stop.js, test/helpers.js, test/answer-key-gating.test.js, test/api-auth.test.js, test/instructor-tools.test.js, test/sca-review.test.js, utils/backupManager.js, utils/i18n.js, utils/seedData.js]

key-decisions:
  - "caughtErrorsIgnorePattern added to no-unused-vars rule (catch clause vars need separate ESLint option)"
  - "routes/pentest.js excluded from both ESLint (eslint.config.js ignores) and Prettier (.prettierignore) -- Phase 16 replaces entirely"
  - "Dead hashPassword import removed from routes/auth.js (intentional vuln #4 uses plaintext comparison, not hashing)"
  - "Dead userId variable removed from routes/dashboard.js professor route (query does not filter by professor)"
  - "Dead sleep() function removed from scripts/smoke-test.js"

patterns-established:
  - "Underscore prefix for unused catch variables (_e, _tmpError) to satisfy caughtErrorsIgnorePattern"
  - "Underscore prefix for unused function params (_importedBy, _reject, _next, _sql) to satisfy argsIgnorePattern"
  - "pentest.js excluded from all code quality tooling (Phase 16 full replacement)"

requirements-completed: [QUAL-02, QUAL-03, QUAL-04]

# Metrics
duration: 5min
completed: 2026-03-21
---

# Phase 14 Plan 02: ESLint Fix and Prettier Format Summary

**Zero ESLint errors and consistent Prettier formatting across 27 JS files with dead code removed and all 12 intentional vulnerabilities preserved**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-21T18:28:53Z
- **Completed:** 2026-03-21T18:34:19Z
- **Tasks:** 2
- **Files modified:** 28

## Accomplishments
- Fixed all 17 ESLint errors across 12 files: prefixed unused catch variables and function params, removed dead code (unused import, unused variable, unused function)
- Formatted all 27 JS files with Prettier (pentest.js excluded) achieving consistent code style
- Added caughtErrorsIgnorePattern to ESLint config for underscore-prefixed catch clause variables
- Excluded routes/pentest.js from both ESLint and Prettier (Phase 16 replaces it entirely)
- Verified all 12 intentional vulnerabilities preserved per SECURITY-BOUNDARY.md

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix ESLint errors and remove dead code** - `e79d039` (fix)
2. **Task 2: Format codebase with Prettier and verify clean state** - `c190d50` (feat)

## Files Created/Modified
- `eslint.config.js` - Added caughtErrorsIgnorePattern, added routes/pentest.js to global ignores
- `.prettierignore` - Added routes/pentest.js exclusion
- `config/database.js` - Prefixed unused catch vars (_e, _tmpError), unused param (_sql), Prettier formatted
- `middleware/audit.js` - Prefixed unused param (_reject), Prettier formatted
- `routes/auth.js` - Removed dead hashPassword import, Prettier formatted
- `routes/dashboard.js` - Removed dead userId variable in professor route, Prettier formatted
- `routes/dast.js` - Prefixed unused param (_importedBy) and catch var (_e), Prettier formatted
- `routes/sca.js` - Prefixed unused param (_importedBy), Prettier formatted
- `scripts/classroom-manager.js` - Prefixed 3 unused catch vars (_e), Prettier formatted
- `scripts/smoke-test.js` - Prefixed unused catch var (_e), removed dead sleep() function, Prettier formatted
- `server.js` - Prefixed unused error handler param (_next), Prettier formatted
- `utils/encryption.js` - Prefixed unused catch var (_e), Prettier formatted
- `config/security.js` - Prettier formatted
- `middleware/rateLimiter.js` - Prettier formatted
- `middleware/rbac.js` - Prettier formatted
- `routes/admin.js` - Prettier formatted
- `routes/classes.js` - Prettier formatted
- `routes/sessions.js` - Prettier formatted
- `routes/vm.js` - Prettier formatted
- `scripts/classroom-stop.js` - Prettier formatted
- `test/helpers.js` - Prettier formatted
- `test/answer-key-gating.test.js` - Prettier formatted
- `test/api-auth.test.js` - Prettier formatted
- `test/instructor-tools.test.js` - Prettier formatted
- `test/sca-review.test.js` - Prettier formatted
- `utils/backupManager.js` - Prettier formatted
- `utils/i18n.js` - Prettier formatted
- `utils/seedData.js` - Prettier formatted

## Decisions Made
- Added caughtErrorsIgnorePattern to ESLint no-unused-vars rule because catch clause variables are not covered by argsIgnorePattern or varsIgnorePattern in ESLint 9
- Excluded routes/pentest.js from both ESLint ignores and .prettierignore to ensure zero modifications (Phase 16 replaces it entirely)
- Removed hashPassword import from routes/auth.js as dead code -- the auth route intentionally uses plaintext password comparison (vulnerability #4)
- Removed userId variable from professor dashboard route -- the query fetches all classes regardless of professor
- Removed sleep() helper from smoke-test.js -- defined but never called

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added caughtErrorsIgnorePattern to ESLint config**
- **Found during:** Task 1 (Fix ESLint errors)
- **Issue:** After prefixing catch variables with underscore, ESLint still reported them as unused. Catch clause variables require a separate `caughtErrorsIgnorePattern` option in the no-unused-vars rule (not covered by varsIgnorePattern).
- **Fix:** Added `caughtErrorsIgnorePattern: '^_'` to the no-unused-vars rule configuration in eslint.config.js
- **Files modified:** eslint.config.js
- **Verification:** `npm run lint` exits 0 with zero errors
- **Committed in:** e79d039 (Task 1 commit)

**2. [Rule 3 - Blocking] Added routes/pentest.js to .prettierignore**
- **Found during:** Task 2 (Format codebase with Prettier)
- **Issue:** Prettier formatted routes/pentest.js, but the verification criteria require zero modifications to that file. Plan only excluded it from ESLint, not Prettier.
- **Fix:** Reverted Prettier changes to pentest.js and added it to .prettierignore
- **Files modified:** .prettierignore, routes/pentest.js (reverted)
- **Verification:** `git diff routes/pentest.js` shows no changes; `npm run format:check` exits 0
- **Committed in:** c190d50 (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered
- Smoke test (`npm test`) and integration tests (`npm run test:integration`) require running server instances and fail with ECONNREFUSED when no instances are running. This is pre-existing behavior documented in 14-01-SUMMARY.md and is not related to code quality changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Codebase is lint-clean and consistently formatted
- ESLint and Prettier configs are stable and conflict-free
- Phase 15 (CSS Extraction) and Phase 16 (CTF Pentest Lab) can proceed
- Phase 16 will need to remove routes/pentest.js from ESLint ignores and .prettierignore after replacement

---
*Phase: 14-code-quality*
*Completed: 2026-03-21*
