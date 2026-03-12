---
phase: 03-sca-student-experience
plan: 01
subsystem: i18n, sca
tags: [localization, i18n, difficulty-sort, hints, french, express]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: "t() and localize() functions in utils/i18n.js"
  - phase: 02-shared-ui-translation
    provides: "Shared layout t() wiring and base SCA translation keys"
provides:
  - "Enriched fr.json/en.json with business impact descriptions for all 12 findings"
  - "Per-finding hint keys (hint1/hint2/hint3) in both languages"
  - "DIFFICULTY_MAP and DIFFICULTY_ORDER constants in routes/sca.js"
  - "Student GET /sca returns localized, difficulty-tagged, Facile-first sorted findings"
  - "Finding-detail GET returns localized finding with difficulty field"
affects: [03-02-PLAN, phase-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "DIFFICULTY_MAP lookup for finding-to-difficulty assignment"
    - "enriched = findings.map(localize).sort(DIFFICULTY_ORDER) pattern"
    - "Business impact framing with 'Dans cette application...' phrasing"
    - "Per-finding numbered hint keys (hint1, hint2, hint3) for pedagogical scaffolding"

key-files:
  created: []
  modified:
    - config/translations/fr.json
    - config/translations/en.json
    - routes/sca.js

key-decisions:
  - "Used numbered hint keys (hint1, hint2, hint3) rather than array for simpler t() access"
  - "Difficulty assigned per plan: findings 1-4 easy, 6-8 medium, 5/9-12 advanced"
  - "Sorting via enriched.sort() on new array to avoid mutating original findings"

patterns-established:
  - "DIFFICULTY_MAP constant: finding ID to difficulty level lookup"
  - "Hint keys as sca.findings.X.hint1/hint2/hint3 in translation files"
  - "localize() + difficulty attachment pattern for student-facing routes"

requirements-completed: [SCAC-01, SCAC-04, TRAN-09, TRAN-10]

# Metrics
duration: 4min
completed: 2026-03-12
---

# Phase 3 Plan 1: SCA Content Enrichment Summary

**Enriched all 12 SCA finding descriptions with business impact context, added per-finding hint questions in fr/en, and wired localize/difficulty/sort logic in routes/sca.js**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-12T16:01:29Z
- **Completed:** 2026-03-12T16:05:42Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- All 12 finding descriptions enriched with "Dans cette application..." business impact sentences in both fr.json and en.json
- Per-finding hint keys (hint1, hint2, hint3) added for all 12 findings in both languages, calibrated to difficulty level
- Student GET /sca now returns French-localized findings with difficulty metadata, sorted easy-first
- Finding-detail GET returns localized finding with difficulty field for badge rendering

## Task Commits

Each task was committed atomically:

1. **Task 1: Enrich finding descriptions and add hint keys in fr.json and en.json** - `36c3e3a` (feat)
2. **Task 2: Wire routes/sca.js with localize(), difficulty map, and sorting** - `22d1b56` (feat)

**Plan metadata:** (pending final commit)

## Files Created/Modified
- `config/translations/fr.json` - Enriched descriptions + hint1/hint2/hint3 for all 12 findings
- `config/translations/en.json` - Matching English enriched descriptions + hint keys
- `routes/sca.js` - Added localize/t import, DIFFICULTY_MAP/ORDER constants, student handler localize+sort, detail handler localize+difficulty

## Decisions Made
- Used numbered hint keys (hint1, hint2, hint3) instead of arrays -- simpler for t() lookups in EJS templates
- Hints match difficulty level: direct questions for Facile, flow-based for Moyen, conceptual for Avance
- Created new `enriched` array via .map().sort() instead of mutating original `findings` array

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- node_modules not installed locally (Codespaces project) -- verification adapted to source-level checks instead of runtime require() -- no impact on correctness

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Plan 02 can now wire student-lab.ejs and finding-detail.ejs templates using the enriched findings data
- Templates will consume: difficulty badges via finding.difficulty, hints via t('sca.findings.X.hintN'), translated strings via t()
- localize() and DIFFICULTY_MAP are wired and returning data to views

## Self-Check: PASSED

- FOUND: config/translations/fr.json
- FOUND: config/translations/en.json
- FOUND: routes/sca.js
- FOUND: .planning/phases/03-sca-student-experience/03-01-SUMMARY.md
- FOUND: commit 36c3e3a (Task 1)
- FOUND: commit 22d1b56 (Task 2)

---
*Phase: 03-sca-student-experience*
*Completed: 2026-03-12*
