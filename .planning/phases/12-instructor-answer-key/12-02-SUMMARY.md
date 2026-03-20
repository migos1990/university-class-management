---
phase: 12-instructor-answer-key
plan: 02
subsystem: ui
tags: [ejs, role-gating, answer-key, smoke-test, i18n]

requires:
  - phase: 12-instructor-answer-key (plan 01)
    provides: Answer key page route, i18n translations, finding classifications
provides:
  - Inline collapsible answer key on finding detail pages (instructor-only)
  - Smoke test Phase E covering answer key role-gating (3 checks)
  - Double-layer student exclusion (null data + EJS server-side conditional)
affects: [testing, documentation]

tech-stack:
  added: []
  patterns:
    - "Server-side EJS conditional to prevent HTML emission for unauthorized roles"
    - "Double protection pattern: null route data + template role check"

key-files:
  created: []
  modified:
    - routes/sca.js
    - views/sca/finding-detail.ejs
    - scripts/smoke-test.js

key-decisions:
  - "Hoisted studentCookie/profCookie to runTests() scope for Phase E access in smoke test"

patterns-established:
  - "Inline answer sections use <details> for collapsible UX with server-side role gating"

requirements-completed: [AKEY-04, AKEY-05, AKEY-06]

duration: 3min
completed: 2026-03-20
---

# Phase 12 Plan 02: Inline Answer Key + Smoke Test Summary

**Collapsible inline answer key on finding detail pages with server-side role exclusion and 3-check smoke test for answer key role-gating**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-20T01:43:46Z
- **Completed:** 2026-03-20T01:47:17Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Inline collapsible answer section on all 12 finding detail pages, visible only to instructors
- Answer key HTML completely absent from student page source (server-side EJS conditional, not CSS hide)
- Smoke test Phase E with 3 checks: professor access OK, student denied 403, no answer key leak in student page source

## Task Commits

Each task was committed atomically:

1. **Task 1: Add inline collapsible answer to finding detail page** - `4b45a25` (feat)
2. **Task 2: Extend smoke test with answer key checks** - `290bbb9` (feat)

**Plan metadata:** (pending) (docs: complete plan)

## Files Created/Modified
- `routes/sca.js` - Added answerKey data conditional pass-through in finding detail route (null for students, populated for instructors)
- `views/sca/finding-detail.ejs` - Added collapsible details section with classification badge, reasoning, and discussion prompt (server-side conditional prevents HTML emission for students)
- `scripts/smoke-test.js` - Added Phase E with 3 answer key role-gating checks; hoisted cookie variables for cross-phase access

## Decisions Made
- Hoisted studentCookie and profCookie declarations to top of runTests() function scope so Phase E can reference cookies obtained in Phase C and D

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Hoisted cookie variable declarations for cross-phase scope**
- **Found during:** Task 2 (smoke test Phase E)
- **Issue:** studentCookie (Phase C) and profCookie (Phase D) declared with `let` inside `else` blocks, not accessible in Phase E
- **Fix:** Added `let studentCookie = null; let profCookie = null;` at runTests() scope and removed inner declarations
- **Files modified:** scripts/smoke-test.js
- **Verification:** Node syntax check passes; variables accessible across all phases
- **Committed in:** 290bbb9 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Auto-fix necessary for correctness -- plan anticipated this issue and documented the solution.

## Issues Encountered
- npm test requires running server instances (smoke test); verified syntax and EJS compilation statically instead

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 12 (Instructor Answer Key) is fully complete: standalone answer key page (Plan 01) + inline finding answers (Plan 02)
- Ready for Phase 13 (Documentation)

## Self-Check: PASSED

All files found: routes/sca.js, views/sca/finding-detail.ejs, scripts/smoke-test.js, 12-02-SUMMARY.md
All commits found: 4b45a25, 290bbb9

---
*Phase: 12-instructor-answer-key*
*Completed: 2026-03-20*
