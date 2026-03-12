---
phase: 03-sca-student-experience
plan: 02
subsystem: i18n, sca, ui
tags: [localization, i18n, french, ejs, difficulty-badges, guided-hints, localStorage, ajax]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: "t() and localize() functions in utils/i18n.js"
  - phase: 02-shared-ui-translation
    provides: "Shared layout t() wiring and base SCA translation keys"
  - phase: 03-sca-student-experience (plan 01)
    provides: "Enriched fr.json/en.json descriptions, hint keys, DIFFICULTY_MAP, localize() in routes/sca.js"
provides:
  - "Fully French student-lab.ejs with intro banner, difficulty badges, translated AJAX feedback"
  - "Fully French finding-detail.ejs with difficulty badge, collapsible hints, translated forms"
  - "Complete student-facing SCA experience in French with pedagogical scaffolding"
affects: [phase-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "EJS-embedded JS constants for translated AJAX feedback (MSG_SAVING, MSG_SUBMITTED, etc.)"
    - "localStorage-based dismissible intro banner pattern"
    - "diffColors/diffLabel lookup objects for difficulty badge rendering"
    - "Collapsible hints section with toggleHints() vanilla JS toggle"
    - "Conditional hint3 rendering via t() key-echo detection"

key-files:
  created: []
  modified:
    - views/sca/student-lab.ejs
    - views/sca/finding-detail.ejs

key-decisions:
  - "Used EJS-embedded JS constants for AJAX messages rather than inline t() in string concatenation"
  - "Intro banner only shown for student role, hidden by default for instructors"
  - "hint3 conditional rendering uses t() key-echo detection (returns key string when not found)"

patterns-established:
  - "Translated AJAX feedback via const MSG_X = '<%= t(key) %>' pattern in script blocks"
  - "localStorage dismissal pattern for one-time banners"
  - "Role-gated UI sections (student-only banner, student-only hints)"

requirements-completed: [TRAN-02, TRAN-03, SCAC-02, SCAC-03]

# Metrics
duration: 3min
completed: 2026-03-12
---

# Phase 3 Plan 2: SCA Student Views Translation Summary

**Fully French student-lab and finding-detail EJS templates with dismissible intro banner, traffic-light difficulty badges, collapsible per-finding hints, and translated AJAX feedback**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-12T16:08:30Z
- **Completed:** 2026-03-12T16:11:02Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- All hardcoded English strings replaced with t() calls in both student-facing SCA views (student-lab.ejs and finding-detail.ejs)
- Dismissible blue intro banner ("Comment aborder cet exercice") with localStorage persistence for students
- Color-coded difficulty badges (green Facile, orange Moyen, red Avance) on both the lab list and finding detail pages
- Collapsible "Besoin d'aide ?" hints section with 2-3 guiding analysis questions per finding
- French classification dropdown (Vrai positif, Faux positif, Necessite une investigation) in both templates
- AJAX save/submit feedback messages in French via EJS-embedded JS constants

## Task Commits

Each task was committed atomically:

1. **Task 1: Wire student-lab.ejs with t() calls, intro banner, difficulty badges, and French AJAX feedback** - `329156d` (feat)
2. **Task 2: Wire finding-detail.ejs with t() calls, difficulty badge, and collapsible hints** - `e1571ab` (feat)

**Plan metadata:** (pending final commit)

## Files Created/Modified
- `views/sca/student-lab.ejs` - Full French translation, dismissible intro banner, difficulty badges, translated AJAX feedback
- `views/sca/finding-detail.ejs` - Full French translation, difficulty badge, collapsible hints section, translated VM/review sections

## Decisions Made
- Used EJS-embedded JS constants (MSG_SAVING, MSG_SAVED, etc.) for AJAX feedback rather than inline t() calls in script blocks
- Intro banner gated to student role only (instructors do not see pedagogical scaffolding)
- hint3 conditional rendering uses the fact that t() returns the key string when not found, comparing output to input key
- Translated confirm() dialog and alert() messages in importFinding script for instructor VM integration

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All 8 phase requirements (TRAN-02, TRAN-03, TRAN-09, TRAN-10, SCAC-01, SCAC-02, SCAC-03, SCAC-04) now addressed across Plans 01 + 02
- Phase 3 complete -- student-facing SCA experience is fully French with pedagogical scaffolding
- Phase 4 (instructor views) can proceed independently

## Self-Check: PASSED

- FOUND: views/sca/student-lab.ejs
- FOUND: views/sca/finding-detail.ejs
- FOUND: .planning/phases/03-sca-student-experience/03-02-SUMMARY.md
- FOUND: commit 329156d (Task 1)
- FOUND: commit e1571ab (Task 2)

---
*Phase: 03-sca-student-experience*
*Completed: 2026-03-12*
