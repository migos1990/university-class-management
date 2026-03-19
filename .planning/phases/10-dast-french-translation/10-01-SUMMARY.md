---
phase: 10-dast-french-translation
plan: 01
subsystem: i18n
tags: [i18n, french, quebec, dast, ejs, translation]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: i18n infrastructure (t(), localize(), languageMiddleware, fr.json/en.json)
provides:
  - dastLocalize() function for DAST scenario field overlay
  - ~70 DAST i18n keys in fr.json and en.json under dast.* namespace
  - Full French translation of all 3 DAST views (student-lab, scenario-detail, instructor)
  - French precondition endpoint messages via t() calls
affects: [dast-views, i18n, instructor-tools]

# Tech tracking
tech-stack:
  added: []
  patterns: [dastLocalize overlay pattern mirroring SCA localize(), EJS-embedded MSG_* constants for client-side i18n]

key-files:
  created: []
  modified:
    - utils/i18n.js
    - config/translations/fr.json
    - config/translations/en.json
    - routes/dast.js
    - views/dast/student-lab.ejs
    - views/dast/scenario-detail.ejs
    - views/dast/instructor.ejs

key-decisions:
  - "dastLocalize() as separate function (not parameterized localize()) -- cleaner separation of SCA vs DAST field sets"
  - "Unicode escape sequences for French accents in JSON -- reliable cross-platform encoding"
  - "68 t() calls across 3 views (18 + 23 + 27) -- zero hardcoded English remaining"

patterns-established:
  - "dastLocalize() overlay pattern: same as localize() but for DAST scenarios with steps JSON array handling"
  - "EJS-embedded MSG_* constants: reused from SCA pattern for client-side AJAX feedback i18n"

requirements-completed: [DAST-01, DAST-02]

# Metrics
duration: 7min
completed: 2026-03-19
---

# Phase 10 Plan 01: DAST French Translation Summary

**Full Quebec French translation of DAST lab: dastLocalize() function, ~70 i18n keys for 6 scenarios + view chrome, and all 3 EJS views translated with 68 t() calls**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-19T23:47:15Z
- **Completed:** 2026-03-19T23:53:45Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- Added dastLocalize() function to utils/i18n.js, overlaying title/description/steps/expected_finding from fr.json with JSON array handling for steps
- Added ~70 DAST i18n keys to fr.json covering all 6 scenarios, view chrome, form labels, precondition messages, and JS messages
- Added parallel English fallback keys to en.json under dast.* namespace
- Translated all 3 DAST EJS views: student-lab (18 t() calls), scenario-detail (23 t() calls), instructor (27 t() calls)
- Wired dastLocalize() in routes/dast.js for GET /, GET /scenarios/:id, and precondition endpoint
- All client-side JS strings translated via EJS-embedded MSG_* constants

## Task Commits

Each task was committed atomically:

1. **Task 1: Add dastLocalize() and all DAST i18n keys** - `f2dabca` (feat)
2. **Task 2: Wire dastLocalize() in routes and translate all 3 DAST views** - `9e17b15` (feat)

## Files Created/Modified
- `utils/i18n.js` - Added dastLocalize() function, updated exports
- `config/translations/fr.json` - Added dast.* namespace with ~70 keys (scenarios, view chrome, form labels, preconditions, JS messages)
- `config/translations/en.json` - Added parallel English fallback dast.* namespace
- `routes/dast.js` - Imported dastLocalize/t, localized scenarios in all route handlers, translated precondition messages
- `views/dast/student-lab.ejs` - Full French translation: page header, badges, form labels, buttons, JS feedback messages
- `views/dast/scenario-detail.ejs` - Full French translation: back link, headings, table headers, form fields, VM section
- `views/dast/instructor.ejs` - Full French translation: dashboard title, scenario table, submission tables, modal, JS messages

## Decisions Made
- Used dastLocalize() as a separate function rather than parameterizing localize() -- cleaner separation of SCA and DAST field sets (SCA has title/description/remediation, DAST has title/description/steps/expected_finding with JSON array handling)
- Used Unicode escape sequences for French accented characters in JSON for reliable cross-platform encoding
- Severity badges (Critical, High, Medium, Low) kept in English per locked decision
- OWASP categories and vulnerability type names kept in English per locked decision

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- DAST lab now has full French experience matching SCA lab
- All i18n infrastructure patterns established and reusable for future labs
- Ready for Phase 11 (Instructor Tools)

---
## Self-Check: PASSED
- All 7 modified files exist on disk
- Both task commits verified (f2dabca, 9e17b15)
- SUMMARY.md created at expected path

---
*Phase: 10-dast-french-translation*
*Completed: 2026-03-19*
