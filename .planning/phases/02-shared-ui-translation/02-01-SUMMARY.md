---
phase: 02-shared-ui-translation
plan: 01
subsystem: ui
tags: [ejs, i18n, french, translation, quebec-french]

# Dependency graph
requires:
  - phase: 01-translation-foundation
    provides: "t() function via i18n.js, languageMiddleware, base translation keys in fr.json/en.json"
provides:
  - "Fully French login page (login.ejs) with all strings via t() calls"
  - "Fully French sidebar navigation (header.ejs) with all nav links, section titles, role labels"
  - "French error page (error.ejs) with status-code-specific titles and guidance"
  - "21 new translation keys in both fr.json and en.json"
affects: [03-sca-lab-translation, 04-admin-security-translation, 05-classroom-deployment]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Status-code-based translation lookup in error.ejs (titleMap/guidanceMap pattern)"
    - "Role display via inline object lookup map in EJS: ({admin: t('nav.roleAdmin'), ...})[user.role]"

key-files:
  created: []
  modified:
    - config/translations/fr.json
    - config/translations/en.json
    - views/login.ejs
    - views/partials/header.ejs
    - views/error.ejs

key-decisions:
  - "Error page uses template-side status-code lookup instead of modifying server.js error handlers"
  - "Security badge values kept in English (MFA: ON/OFF, RBAC: ON/OFF) per user decision"
  - "Login error message always shows t('auth.invalidCredentials') instead of server-provided string"

patterns-established:
  - "Status-code-based error translation: var titleMap = {404: t('errors.notFoundTitle'), ...}"
  - "Role label translation: inline object lookup in EJS templates"

requirements-completed: [TRAN-06, TRAN-07, TRAN-08]

# Metrics
duration: 8min
completed: 2026-03-12
---

# Phase 2 Plan 1: Shared UI Translation Summary

**Login, sidebar, and error pages fully translated to Quebec French with 21 new i18n keys and status-code-based error messages**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-12T15:11:25Z
- **Completed:** 2026-03-12T15:19:06Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- Added 21 missing translation keys to both fr.json and en.json with proper French accents/cedillas
- Login page renders entirely in French: form labels, button, demo accounts, footer, browser tab title
- Sidebar navigation shows all section titles, nav links, role badges, and lab names in French
- Error page displays status-code-specific French titles and guidance (404, 403, 429, 500)
- All three templates declare lang="fr" on the html element

## Task Commits

Each task was committed atomically:

1. **Task 1: Add missing translation keys to fr.json and en.json** - `4128f69` (feat)
2. **Task 2: Wire login.ejs with t() calls and set lang="fr"** - `020f50d` (feat)
3. **Task 3: Wire header.ejs and error.ejs with t() calls and set lang="fr"** - `1211e80` (feat)

## Files Created/Modified
- `config/translations/fr.json` - Added 21 new French translation keys across nav, login, errors namespaces; overwrote nav.pentestLab
- `config/translations/en.json` - Added matching 21 English fallback keys across nav, login, errors namespaces
- `views/login.ejs` - Replaced all 13 hardcoded English strings with t() calls, set lang="fr"
- `views/partials/header.ejs` - Replaced all 25 hardcoded English strings with t() calls, set lang="fr", role lookup map
- `views/error.ejs` - Status-code-based French title/guidance lookup, translated back button, set lang="fr"

## Decisions Made
- Error page uses template-side status-code lookup maps instead of modifying server.js -- keeps changes additive and template-only
- Security badge values kept in English (MFA: ON/OFF, RBAC: ON/OFF, etc.) per user decision -- these are industry-standard terms
- Login error message uses translated string t('auth.invalidCredentials') instead of the server-provided English error string, since login only has one error type

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All shared UI shell (login, navigation, error pages) now renders in French
- Ready for Phase 3 (SCA lab translation) -- sidebar lab links already show French names
- The t() call pattern and status-code lookup pattern established here can be reused in subsequent phases

## Self-Check: PASSED

All 5 modified files exist on disk. All 3 task commits verified in git log.

---
*Phase: 02-shared-ui-translation*
*Completed: 2026-03-12*
