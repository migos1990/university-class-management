---
phase: 12-instructor-answer-key
plan: 01
subsystem: ui
tags: [ejs, i18n, rbac, answer-key, quebec-french, instructor-tools]

# Dependency graph
requires:
  - phase: 06-inline-code-snippets
    provides: SCA finding detail views and localize() i18n pattern
provides:
  - Standalone instructor answer key page at /sca/answer-key with 12 findings
  - Answer key i18n content in both FR and EN (sca.answerKey.* keys)
  - RBAC-bypass hardened route preventing student access even when RBAC disabled
  - Discoverable link from instructor dashboard
affects: [12-instructor-answer-key, documentation]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - RBAC-bypass hardening with secondary role check after requireRole middleware
    - Answer key i18n pattern with per-finding classification/reasoning/discussion keys

key-files:
  created:
    - views/sca/answer-key.ejs
  modified:
    - config/translations/fr.json
    - config/translations/en.json
    - routes/sca.js
    - views/sca/instructor.ejs

key-decisions:
  - "RBAC-bypass hardening: secondary req.session.user.role === 'student' check after requireRole to prevent student access when RBAC is disabled"
  - "Answer key content authored in Quebec French with proper accents throughout, matching existing sca.findings prose style"
  - "Finding 11 classified as 'Necessite une investigation' (all others as 'Vrai positif') per SOLUTION-GUIDE.md"

patterns-established:
  - "RBAC-bypass hardening: secondary role check for answer key routes that must never be visible to students"

requirements-completed: [AKEY-01, AKEY-02, AKEY-03, AKEY-04, AKEY-06]

# Metrics
duration: 4min
completed: 2026-03-20
---

# Phase 12 Plan 01: Instructor Answer Key Summary

**Standalone instructor answer key page with all 12 SCA finding classifications, pedagogical reasoning, and discussion prompts in Quebec French, role-gated with RBAC-bypass hardening**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-20T01:37:16Z
- **Completed:** 2026-03-20T01:41:11Z
- **Tasks:** 1
- **Files modified:** 5

## Accomplishments
- Created answer key page at /sca/answer-key with all 12 findings showing expected classification, reasoning, and discussion prompts
- Added ~60 i18n keys to both fr.json and en.json under sca.answerKey.* with proper Quebec French prose
- Implemented RBAC-bypass hardened route that blocks students even when RBAC is disabled via security panel
- Added discoverable "Corrige" link button to instructor dashboard header

## Task Commits

Each task was committed atomically:

1. **Task 1: Add answer key i18n content and create standalone answer key page** - `500be3b` (feat)

**Plan metadata:** pending (docs: complete plan)

## Files Created/Modified
- `views/sca/answer-key.ejs` - Standalone answer key page template (117 lines) with styled cards for each finding
- `config/translations/fr.json` - ~60 new i18n keys under sca.answerKey.* with Quebec French content
- `config/translations/en.json` - English equivalents of all answer key i18n keys
- `routes/sca.js` - GET /sca/answer-key route with requireRole + RBAC-bypass hardened student check
- `views/sca/instructor.ejs` - Added "Corrige" link button in page header

## Decisions Made
- RBAC-bypass hardening: Added secondary `req.session.user.role === 'student'` check after requireRole middleware to ensure answer key is never visible to students even when RBAC is disabled via security panel
- Finding 11 (express-session) classified as "Necessite une investigation" while all others are "Vrai positif (confirme)" -- consistent with SOLUTION-GUIDE.md
- All answer key text authored in Quebec French with proper accents (e with accent aigu, e with accent grave, cedilla, etc.), matching the prose style of existing sca.findings translations

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Answer key page is functional and accessible to professors/admins
- Ready for Phase 12 Plan 02 (inline answer key toggle in finding detail view)
- No blockers

## Self-Check: PASSED

All created files verified on disk. Commit 500be3b confirmed in git log.

---
*Phase: 12-instructor-answer-key*
*Completed: 2026-03-20*
