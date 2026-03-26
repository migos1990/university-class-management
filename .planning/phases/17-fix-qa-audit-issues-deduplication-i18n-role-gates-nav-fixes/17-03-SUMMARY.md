---
phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes
plan: 03
subsystem: routing
tags: [rbac, role-gates, navigation, error-handling, ctf, authorization]

# Dependency graph
requires:
  - phase: 17-01
    provides: "Clean seed data (no duplication) so dashboard/class pages show correct data"
  - phase: 17-02
    provides: "i18n keys available for error messages and nav labels"
  - phase: 12-instructor-answer-key
    provides: "requireRole middleware pattern established in middleware/rbac.js"
provides:
  - "requireRole middleware on dashboard sub-routes (student, professor, admin)"
  - "GET /classes redirect to /dashboard (fixes 404)"
  - "Rendered HTML error page for locked CTF challenges (replaces raw JSON)"
  - "Corrected 'Mes inscriptions' sidebar link pointing to /classes"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "requireRole(['role']) middleware chained after requireAuth on role-specific routes"
    - "Redirect-based route handler for /classes (no separate view, delegates to dashboard)"

key-files:
  created: []
  modified:
    - routes/dashboard.js
    - routes/classes.js
    - routes/pentest.js
    - views/partials/header.ejs

key-decisions:
  - "Dashboard role gates use requireRole middleware (not secondary role checks) -- when RBAC disabled, all users can access all dashboards (intentional for DAST lab)"
  - "GET /classes redirects to /dashboard rather than creating a new view (student/professor dashboards already show class lists)"
  - "Locked CTF challenge renders error template with French message and 403 status (not JSON)"
  - "'Mes inscriptions' points to /classes for semantic correctness (redirects to /dashboard currently, but will point to dedicated view if created later)"

patterns-established:
  - "All role-specific dashboard routes gated with requireRole after requireAuth"

requirements-completed: [ISSUE-003, ISSUE-004, ISSUE-005, ISSUE-006]

# Metrics
duration: 2min
completed: 2026-03-22
---

# Phase 17 Plan 03: Role Gates, /classes 404, CTF Error Page, Nav Link Fix Summary

**Added requireRole middleware to 3 dashboard sub-routes, fixed /classes 404 with redirect, replaced locked CTF JSON error with rendered HTML, corrected Mes inscriptions nav link**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-22T14:38:00Z
- **Completed:** 2026-03-22T14:40:32Z
- **Tasks:** 3 (2 implementation + 1 verification)
- **Files modified:** 4

## Accomplishments
- Dashboard sub-routes now enforce role gates: `/dashboard/student` requires student role, `/dashboard/professor` requires professor or admin, `/dashboard/admin` requires admin only
- GET /classes no longer returns 404 -- redirects to /dashboard which shows class lists by role
- Locked CTF challenges return a rendered HTML error page with French message ("Challenge verrouille") instead of raw JSON
- "Mes inscriptions" sidebar link for students now points to /classes instead of looping back to /dashboard

## Task Commits

Each task was committed atomically (all changes in a single focused commit):

1. **Task 1: Add role gates to dashboard routes and fix /classes 404** - `a74e049` (fix)
2. **Task 2: Fix locked CTF JSON error and "Mes inscriptions" nav link** - `a74e049` (fix)
3. **Task 3: Verification** - no separate commit (verification-only task; all checks pass)

## Files Created/Modified
- `routes/dashboard.js` - Added requireRole middleware to /student (student), /professor (professor, admin), /admin (admin) routes
- `routes/classes.js` - Added GET / handler that redirects to /dashboard (placed before GET /:id)
- `routes/pentest.js` - Changed locked challenge response from `res.status(403).json(...)` to `res.status(403).render('error', ...)` with French message
- `views/partials/header.ejs` - Changed student "Mes inscriptions" link href from /dashboard to /classes

## Decisions Made
- Dashboard role gates use requireRole middleware only (no secondary role checks). When RBAC is disabled, all users can access all dashboards -- this is acceptable and consistent with the DAST lab's educational purpose.
- GET /classes redirects to /dashboard rather than creating a new view, because both student and professor dashboards already display class lists. This avoids view duplication and maintenance burden.
- Locked CTF challenge error uses `res.render('error', { message: ..., error: { status: 403, details: ... } })` pattern consistent with other 403 pages in the app.
- "Mes inscriptions" points to /classes for semantic correctness. Currently redirects to /dashboard, but if a dedicated /classes view is ever created, this link will automatically point to the right place.

## Deviations from Plan

None - plan executed exactly as written. The code changes were committed in `a74e049` during a prior session; this execution verified the fixes and created documentation artifacts.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All 6 QA audit issues (ISSUE-001 through ISSUE-006) are now resolved across Plans 01, 02, and 03
- Phase 17 is complete
- Phase 18 (Security & Env Hardening) can proceed (already completed separately)

## Self-Check: PASSED

All 4 modified files verified present on disk. Commit a74e049 verified in git history.

---
*Phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes*
*Completed: 2026-03-22*
