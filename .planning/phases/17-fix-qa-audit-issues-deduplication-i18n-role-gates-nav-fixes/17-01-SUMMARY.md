---
phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes
plan: 01
subsystem: database
tags: [seed-data, deduplication, json-db, sca, dast, vm, ctf]

# Dependency graph
requires:
  - phase: 16-ctf-pentest-lab
    provides: "CTF challenges and curriculum tables that need clearing on re-seed"
provides:
  - "seedDatabase() clears all 15 tables (6 core + 9 curriculum) before re-inserting"
  - "JSON DB adapter bulk DELETE handlers for 9 curriculum/student-data collections"
  - "No more 5x duplication on any curriculum page after multiple restarts"
affects: [17-02, 17-03, 18-01]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "DELETE-before-INSERT pattern applied to all curriculum collections in seedDatabase()"
    - "JSON DB adapter bulk DELETE handlers mirror seedData.js DELETE statements"

key-files:
  created: []
  modified:
    - utils/seedData.js
    - config/database.js

key-decisions:
  - "Added 9 DELETE statements for curriculum/student-data tables alongside existing 6 core table DELETEs"
  - "Added matching bulk DELETE handlers in JSON DB adapter for pattern-matched SQL"

patterns-established:
  - "All new seed collections must have corresponding DELETE in seedDatabase() and bulk DELETE handler in database.js"

requirements-completed: [ISSUE-001]

# Metrics
duration: 2min
completed: 2026-03-26
---

# Phase 17 Plan 01: Seed Data Deduplication Fix Summary

**Added DELETE statements for 9 curriculum/student-data tables to seedDatabase(), eliminating 5x record duplication on server restart**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-26T18:30:15Z
- **Completed:** 2026-03-26T18:32:33Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- seedData.js now contains 15 DELETE statements (6 original core + 9 new curriculum) ensuring all tables are cleared before re-seeding
- JSON DB adapter (config/database.js) has matching bulk DELETE handlers for all 9 curriculum collections
- After fix: sca_findings=12, dast_scenarios=6, vulnerabilities=12, ctf_challenges=12 (verified with fresh seed and re-seed)
- No duplication regardless of number of server restarts

## Task Commits

Each task was committed atomically:

1. **Task 1: Add missing DELETE statements to seedData.js and re-seed database** - `ef93b7e` (fix)
2. **Task 2: Verify deduplication fix with existing test suite** - no separate commit needed (verification-only task; 22/24 tests pass, 2 pre-existing answer-key-gating failures are out of scope)

**Plan metadata:** pending (docs: complete plan)

## Files Created/Modified
- `utils/seedData.js` - Added 9 DELETE statements for sca_findings, sca_student_reviews, dast_scenarios, dast_student_findings, vulnerabilities, vm_status_history, vm_comments, ctf_challenges, ctf_submissions
- `config/database.js` - Added bulk DELETE handlers in JSON DB adapter for all 9 curriculum/student-data collections

## Decisions Made
- Added 9 DELETE statements for curriculum/student-data tables alongside existing 6 core table DELETEs -- matches the DELETE-before-INSERT pattern already established for core tables
- Added matching bulk DELETE handlers in JSON DB adapter -- the JSON adapter uses SQL pattern matching, so each `DELETE FROM <table>` needs a handler that empties the corresponding array

## Deviations from Plan

None - plan executed exactly as written. The code change was committed in `ef93b7e` during a prior session; this execution verified the fix and created documentation artifacts.

## Issues Encountered
- 2 pre-existing test failures in answer-key-gating.test.js (tests assert "placeholder" text but the answer key page no longer contains that text). These failures pre-date Phase 17 and are documented in STATE.md as out of scope.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Deduplication fix complete, database seed is clean
- Ready for 17-02 (i18n translation) and 17-03 (role gates, nav fixes)
- All curriculum pages now show correct record counts

---
*Phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes*
*Completed: 2026-03-26*
