---
phase: 11-instructor-tools
plan: 01
subsystem: ui, api
tags: [ejs, polling, i18n, activity-tracking, instructor-dashboard]

# Dependency graph
requires:
  - phase: 06-inline-code-snippets
    provides: SCA instructor dashboard with stats cards and findings overview
provides:
  - In-memory student activity tracker (activityTracker, trackActivity)
  - Extended /sca/stats endpoint with students array and totalFindings
  - Student progress table on instructor dashboard with 30s live-polling
  - French i18n keys for student progress section (sca.instructor.progress.*)
  - Integration tests for instructor tools (test/instructor-tools.test.js)
affects: [12-instructor-answer-key]

# Tech tracking
tech-stack:
  added: []
  patterns: [in-memory activity tracking, JS aggregation instead of GROUP BY]

key-files:
  created:
    - test/instructor-tools.test.js
  modified:
    - routes/sca.js
    - views/sca/instructor.ejs
    - config/translations/fr.json
    - config/translations/en.json

key-decisions:
  - "Used in-memory activityTracker object (not DB) for real-time activity -- acceptable for classroom scale, resets on server restart"
  - "Refactored /sca/stats to use JS aggregation instead of GROUP BY/COUNT(DISTINCT) for DB adapter compatibility"
  - "Used parameterized query for student role filter to work with JSON DB adapter"

patterns-established:
  - "JS aggregation pattern: fetch raw arrays from DB, aggregate in JavaScript (avoids GROUP BY/COUNT(DISTINCT) limitations of JSON DB adapter)"
  - "French relative time helper: timeAgo() function for client-side il y a X min/h/j display"

requirements-completed: [INST-01, INST-02]

# Metrics
duration: 5min
completed: 2026-03-20
---

# Phase 11 Plan 01: Student Activity Tracking Summary

**In-memory activity tracker with per-student progress table on SCA instructor dashboard, 30s live-polling, three-state French status badges, and 6 integration tests**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-20T00:38:52Z
- **Completed:** 2026-03-20T00:44:13Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Extended /sca/stats endpoint with students array (id, username, submitted, lastActiveAt, currentFindingId, currentFindingTitle) and totalFindings
- Activity tracking fires on student GET /sca/, GET /sca/findings/:id, POST /sca/findings/:id/review
- Student progress table on instructor dashboard with progress bars, French time-ago, finding titles, and three-state status badges
- Table updates every 30s via existing polling mechanism (no extra fetch calls)
- i18n keys added for both French and English under sca.instructor.progress.*
- 6 integration tests covering stats response, activity tracking, submitted count, sort order, and regression

## Task Commits

Each task was committed atomically:

1. **Task 1: Backend activity tracking, stats extension, i18n keys, and integration tests** - `61f7384` (feat) -- TDD: RED + GREEN in single commit
2. **Task 2: Student progress table in instructor dashboard with live polling** - `3404f3e` (feat)

## Files Created/Modified
- `test/instructor-tools.test.js` - 6 integration tests for INST-01/INST-02
- `routes/sca.js` - activityTracker, trackActivity(), extended /sca/stats with students array
- `views/sca/instructor.ejs` - Student progress table HTML, timeAgo(), renderStudentTable(), status badges CSS
- `config/translations/fr.json` - French i18n keys for student progress section
- `config/translations/en.json` - English fallback keys for student progress section

## Decisions Made
- Used in-memory activityTracker object (not DB) for real-time activity tracking -- acceptable for classroom scale, resets on server restart
- Refactored /sca/stats from SQL GROUP BY/COUNT(DISTINCT) to JS aggregation -- JSON DB adapter cannot handle these SQL operations reliably
- Used parameterized query `WHERE role = ?` with `'student'` param instead of inline `WHERE role = 'student'` -- required for JSON DB adapter compatibility

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed SQL query for student role filter**
- **Found during:** Task 1 (backend implementation)
- **Issue:** Plan used `"SELECT * FROM users WHERE role = 'student'"` with value inline in SQL string, but JSON DB adapter only matches params via `params[0]`, not embedded string values
- **Fix:** Changed to parameterized query `db.prepare('SELECT * FROM users WHERE role = ?').all('student')`
- **Files modified:** routes/sca.js
- **Verification:** /sca/stats now returns non-empty students array
- **Committed in:** 61f7384 (Task 1 commit)

**2. [Rule 1 - Bug] Made test 4 (submitted count) self-contained**
- **Found during:** Task 1 (test execution)
- **Issue:** Test assumed alice_student had pre-existing submitted reviews from sca-review.test.js, but fresh server has no reviews
- **Fix:** Added review submission step within the test before asserting submitted count >= 1
- **Files modified:** test/instructor-tools.test.js
- **Verification:** Test passes independently on fresh database
- **Committed in:** 61f7384 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (2 bugs)
**Impact on plan:** Both auto-fixes necessary for correctness with the JSON DB adapter. No scope creep.

## Issues Encountered
None beyond the auto-fixed deviations above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Instructor dashboard now shows real-time student activity and progress
- Activity tracker is in-memory (resets on server restart) -- acceptable for classroom use
- Ready for Phase 12 (Instructor Answer Key) which builds on the SCA instructor dashboard

## Self-Check: PASSED

All 6 files verified present. Both commits (61f7384, 3404f3e) verified in git log.

---
*Phase: 11-instructor-tools*
*Completed: 2026-03-20*
