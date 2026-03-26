---
phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes
plan: 02
subsystem: i18n
tags: [i18n, ejs, french, quebec-french, translations, dashboard, vm]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: "i18n infrastructure (t() function, fr.json/en.json, EJS integration)"
  - phase: 10-dast-french
    provides: "Established pattern for translating lab templates with t() calls"
provides:
  - "~60 new i18n keys in dashboard.student.*, dashboard.professor.*, dashboard.admin.*, vm.* namespaces"
  - "5 EJS templates fully translated to Quebec French (student/professor/admin dashboards, VM student-lab/instructor)"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "vm.* i18n namespace for Vulnerability Manager pages"
    - "dashboard.* sub-namespaces (student/professor/admin) for role-specific dashboard content"

key-files:
  created: []
  modified:
    - config/translations/fr.json
    - config/translations/en.json
    - views/student/dashboard.ejs
    - views/professor/dashboard.ejs
    - views/admin/dashboard.ejs
    - views/vm/student-lab.ejs
    - views/vm/instructor.ejs
    - views/mfa-verify.ejs

key-decisions:
  - "Unicode escape sequences for French accents in JSON (consistent with Phase 10 decision)"
  - "Severity/status badge values kept in English (DB-sourced, used for CSS class names)"
  - "vm.common.* namespace for shared VM labels reused across student-lab and instructor views"

patterns-established:
  - "vm.* i18n namespace: vm.studentLab.*, vm.instructor.*, vm.common.*, vm.table.*, vm.modal.*"
  - "Dashboard sub-namespaces: dashboard.student.*, dashboard.professor.*, dashboard.admin.*"

requirements-completed: [ISSUE-002]

# Metrics
duration: 2min
completed: 2026-03-22
---

# Phase 17 Plan 02: Dashboard & VM i18n Translation Summary

**88 t() calls across 5 EJS templates with ~60 new fr.json/en.json keys covering student/professor/admin dashboards and VM student-lab/instructor pages**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-22T18:38:00Z
- **Completed:** 2026-03-22T18:40:27Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Added ~60 new translation keys across dashboard.student.*, dashboard.professor.*, dashboard.admin.*, and vm.* namespaces in both fr.json and en.json
- Converted all 5 EJS templates to use t() calls -- zero hardcoded English strings remain in dashboards or VM pages
- VM pages (student-lab, instructor) received a complete new vm.* i18n namespace including common labels, table headers, filter controls, and modal form labels
- mfa-verify.ejs also translated as part of the same commit

## Task Commits

Each task was committed atomically (both tasks in a single commit since they are tightly coupled):

1. **Task 1: Add new translation keys to fr.json and en.json** - `135f7d1` (feat)
2. **Task 2: Convert 5 EJS templates from hardcoded English to t() calls** - `135f7d1` (feat)

## Files Created/Modified
- `config/translations/fr.json` - Added ~60 new keys: dashboard.student.*, dashboard.professor.*, dashboard.admin.*, vm.studentLab.*, vm.instructor.*, vm.common.*, vm.table.*, vm.modal.*
- `config/translations/en.json` - Added matching English keys for all new fr.json entries
- `views/student/dashboard.ejs` - Replaced all hardcoded English with t() calls (13 t() calls)
- `views/professor/dashboard.ejs` - Replaced all hardcoded English with t() calls (11 t() calls)
- `views/admin/dashboard.ejs` - Replaced all hardcoded English with t() calls (16 t() calls)
- `views/vm/student-lab.ejs` - Replaced all UI chrome strings with t() calls (17 t() calls)
- `views/vm/instructor.ejs` - Replaced all UI chrome and modal strings with t() calls (31 t() calls)
- `views/mfa-verify.ejs` - Translated MFA verification page strings

## Decisions Made
- Unicode escape sequences for French accents in JSON files (consistent with Phase 10 DAST convention)
- Severity and status badge values left in English since they come from DB and double as CSS class names
- Created vm.common.* namespace for labels shared between student-lab and instructor views (Total, Critical, High, Open, Resolved, In Progress, search/filter labels)
- vm.modal.* namespace for instructor-only "Add Vulnerability" modal form labels

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All dashboard and VM pages now display in Quebec French
- Plan 17-03 (role gates, /classes redirect, CTF error page, nav link fix) can proceed

## Self-Check: PASSED

All 8 modified files verified present on disk. Commit 135f7d1 verified in git history.

---
*Phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes*
*Completed: 2026-03-22*
