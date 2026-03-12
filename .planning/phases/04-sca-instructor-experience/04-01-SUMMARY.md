---
phase: 04-sca-instructor-experience
plan: 01
subsystem: ui, api
tags: [ejs, i18n, localize, express, sca, french]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: i18n utils (t, localize, languageMiddleware)
  - phase: 03-sca-student-experience
    provides: SCA student routes and translation keys
provides:
  - Localized instructor route handler (French findings for instructor.ejs)
  - Localized student-detail route handler (French findings for student-detail.ejs)
  - GET /sca/stats JSON endpoint for live class progress polling
  - Fully French student-detail.ejs template
  - confirmImport and importFailed translation keys in fr.json and en.json
affects: [04-02-sca-instructor-experience]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "localize() on findings array before passing to res.render in instructor routes"
    - "t(lang, key) for route-level title localization"
    - "Classification badge mapping via ternary chain in EJS"

key-files:
  created: []
  modified:
    - routes/sca.js
    - views/sca/student-detail.ejs
    - config/translations/fr.json
    - config/translations/en.json

key-decisions:
  - "Reused sca.instructor.submitted key for status display on student-detail (cross-reference acceptable since 'soumis' is universal)"
  - "Stats endpoint placed before /student/:studentId to avoid Express param matching conflict"

patterns-established:
  - "Classification badge label mapping: confirmed -> truePositive, false_positive -> falsePositive, needs_investigation -> needsInvestigation via sca.common.* keys"

requirements-completed: [TRAN-05, INST-01]

# Metrics
duration: 3min
completed: 2026-03-12
---

# Phase 4 Plan 1: SCA Instructor Experience - Route Localization and Stats Endpoint Summary

**French localized instructor and student-detail route handlers with classification badge i18n, plus GET /sca/stats endpoint for live class progress polling**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-12T17:32:07Z
- **Completed:** 2026-03-12T17:35:19Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Instructor GET handler now passes localized (French) findings and French title to instructor.ejs template
- Student-detail GET handler passes localized findings and French title; student-detail.ejs fully translated
- New GET /sca/stats endpoint returns live class progress JSON (studentsStarted, totalStudents, avgCompletion, pace)
- Added confirmImport and importFailed translation keys to both fr.json and en.json for Plan 02

## Task Commits

Each task was committed atomically:

1. **Task 1: Add localize() to route handlers, create /sca/stats endpoint, add missing translation keys** - `6bcac5b` (feat)
2. **Task 2: Wire student-detail.ejs with French translations and classification badge mapping** - `9b6e284` (feat)

## Files Created/Modified
- `routes/sca.js` - Added localize() in instructor and student-detail handlers, new /sca/stats endpoint
- `views/sca/student-detail.ejs` - All English strings replaced with t() calls, classification badges use French labels
- `config/translations/fr.json` - Added confirmImport and importFailed keys under sca.instructor
- `config/translations/en.json` - Added confirmImport and importFailed keys under sca.instructor

## Decisions Made
- Reused `sca.instructor.submitted` key ("soumis") for status display on student-detail page rather than creating a duplicate key
- Stats endpoint placed immediately after the root GET / route to avoid Express treating "stats" as a `:studentId` parameter

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- npm dependencies not installed; ran `npm install` before verification (not a code issue, just environment setup)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Instructor route now passes localized findings -- ready for Plan 02 to translate instructor.ejs template
- /sca/stats endpoint ready for Plan 02 live polling integration
- confirmImport and importFailed keys available for Plan 02 import button UI

## Self-Check: PASSED

- All 4 modified files exist on disk
- Commit 6bcac5b (Task 1) verified in git log
- Commit 9b6e284 (Task 2) verified in git log

---
*Phase: 04-sca-instructor-experience*
*Completed: 2026-03-12*
