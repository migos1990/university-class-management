---
phase: 04-sca-instructor-experience
plan: 02
subsystem: ui
tags: [ejs, i18n, french, polling, fetch, stats, sca]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: i18n utils (t, localize, languageMiddleware)
  - phase: 04-sca-instructor-experience
    plan: 01
    provides: localized route handler, /sca/stats endpoint, confirmImport/importFailed keys
provides:
  - Fully French instructor.ejs dashboard (all headers, labels, badges, buttons)
  - Live stats bar with 30-second polling from /sca/stats endpoint
  - French client-side JS constants for VM import flow
affects: [05-verification-polish]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "EJS-embedded JS constants (MSG_*) for French client-side strings"
    - "setInterval + fetch polling for live dashboard stats refresh"
    - "toLocaleTimeString('fr-CA') for French timestamp formatting"

key-files:
  created: []
  modified:
    - views/sca/instructor.ejs

key-decisions:
  - "Stats bar uses inline styles matching existing template pattern rather than adding new CSS classes"
  - "Pace unit displayed as 'soumissions / 5 min' hardcoded in JS (not a t() key) since it appears only in client-side dynamic context"

patterns-established:
  - "EJS-baked MSG_* constants pattern for translating client-side JS strings without runtime i18n library"

requirements-completed: [TRAN-04, INST-01]

# Metrics
duration: 3min
completed: 2026-03-12
---

# Phase 4 Plan 2: SCA Instructor Experience - Dashboard Translation and Stats Bar Summary

**Fully French instructor.ejs with live stats bar (3 cards, 30s polling), translated VM import actions, and zero remaining English strings**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-12T17:38:30Z
- **Completed:** 2026-03-12T17:42:04Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments
- All static content in instructor.ejs translated to French via t() calls: page title, subtitle, section headings, table headers, badges, buttons
- Live stats bar with 3 cards (students started, avg completion, pace) using big 2.2rem numbers in HEC navy (#002855)
- Stats auto-refresh every 30 seconds via fetch('/sca/stats') + setInterval, with French "Mis a jour" timestamp
- VM import flow fully translated: French confirm dialog, loading state, success/error messages via EJS-baked MSG_* constants

## Task Commits

Each task was committed atomically:

1. **Task 1: Translate instructor.ejs static content** - `8827e9e` (feat)
2. **Task 2: Add stats bar with polling and translate client-side JS** - `7f364f7` (feat)

## Files Created/Modified
- `views/sca/instructor.ejs` - Complete French translation of all visible text, stats bar HTML with 3 cards, polling JS, translated VM import constants

## Decisions Made
- Stats bar uses inline styles consistent with existing template pattern (no new CSS classes added)
- Pace unit string "soumissions / 5 min" kept as hardcoded French in JS rather than a t() key, since it only appears in dynamic client-side rendering context

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Phase 4 (SCA Instructor Experience) is now complete -- both plans executed
- Instructor dashboard renders entirely in French with live class progress monitoring
- Ready for Phase 5 (Verification and Polish)

## Self-Check: PASSED

- views/sca/instructor.ejs exists on disk
- 04-02-SUMMARY.md exists on disk
- Commit 8827e9e (Task 1) verified in git log
- Commit 7f364f7 (Task 2) verified in git log

---
*Phase: 04-sca-instructor-experience*
*Completed: 2026-03-12*
