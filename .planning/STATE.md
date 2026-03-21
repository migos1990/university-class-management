---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Polish & Pedagogy
status: in-progress
stopped_at: Completed 15-01-PLAN.md
last_updated: "2026-03-21T19:09:59Z"
last_activity: 2026-03-21 -- Completed Phase 15 Plan 1 (CSS stylesheet extraction + SCA/DAST cleanup)
progress:
  total_phases: 11
  completed_phases: 9
  total_plans: 14
  completed_plans: 13
  percent: 93
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-12)

**Core value:** The SCA lab must work flawlessly end-to-end in French -- from Codespace boot to student submission to instructor review -- with zero friction for non-technical students.
**Current focus:** Phase 15 in progress -- CSS Extraction (Plan 1 of 2 complete)

## Current Position

Phase: 15 of 16 (CSS Extraction)
Plan: 1 of 2 (15-01 complete)
Status: Phase 15 in progress (CSS Extraction)
Last activity: 2026-03-21 -- Completed Phase 15 Plan 1 (CSS stylesheet extraction + SCA/DAST cleanup)

Progress: [█████████░] 93%

## Performance Metrics

**Velocity:**
- Total plans completed: 8 (v1.0)
- Average duration: carried from v1.0
- Total execution time: carried from v1.0

**By Phase (v1.1):**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 6. Inline Code Snippets | 2/2 | 6min | 3min |
| 7. Quick Wins | 1/1 | 4min | 4min |
| 8. Testing | 1/1 | 3min | 3min |
| 9. Security Boundary Doc | 1/1 | 2min | 2min |
| 10. DAST French | 1/1 | 7min | 7min |
| 11. Instructor Tools | 1/? | 5min | 5min |
| 12. Instructor Answer Key | 0/2 | - | - |
| 13. Documentation | 0/? | - | - |
| 14. Code Quality | 2/2 | 7min | 3.5min |
| 15. CSS Extraction | 1/2 | 8min | 8min |
| 16. CTF Pentest Lab | 0/? | - | - |

*Updated after each plan completion*
| Phase 06 P01 | 4min | 2 tasks | 10 files |
| Phase 06 P02 | 2min | 2 tasks | 1 files |
| Phase 07 P01 | 4min | 3 tasks | 7 files |
| Phase 08 P01 | 3min | 2 tasks | 6 files |
| Phase 09 P01 | 2min | 2 tasks | 2 files |
| Phase 10 P01 | 7min | 2 tasks | 7 files |
| Phase 11 P01 | 5min | 2 tasks | 5 files |
| Phase 12 P01 | 4min | 1 tasks | 5 files |
| Phase 12 P02 | 3min | 2 tasks | 3 files |
| Phase 13 P01 | 3min | 2 tasks | 2 files |
| Phase 14 P01 | 2min | 2 tasks | 4 files |
| Phase 14 P02 | 5min | 2 tasks | 28 files |
| Phase 15 P01 | 8min | 2 tasks | 10 files |

## Accumulated Context

### Decisions

See PROJECT.md Key Decisions table for full list with outcomes.

Recent decisions affecting current work:
- v1.1 roadmap expanded: 11 phases (6-16) derived from 40 requirements across 11 categories, informed by product review (2026-03-19)
- Phase ordering follows product review wave order: Quick Wins → Tests → Security Docs → DAST French → Instructor Tools → Answer Key → Documentation → Code Quality → CSS Extraction → CTF Pentest Lab
- Answer Key (was Phase 7) renumbered to Phase 12; plans preserved and renumbered
- [Phase 06]: Vendored Prism.js locally for offline Codespace reliability
- [Phase 06]: Conditional asset loading via needsPrism flag to avoid Prism on non-SCA pages
- [Phase 06]: Code preview scoped to student-lab cards only -- instructor views unchanged
- [Phase 07]: Used AMF (Authentification multifacteur) for MFA badge -- standard Quebec French security terminology
- [Phase 07]: Accepted classroom-manager broadcast breakage from requireAuth -- explicit per QWIN-04 requirement
- [Phase 07]: Prev/next navigation reuses DIFFICULTY_MAP/DIFFICULTY_ORDER for consistency with student-lab sort
- [Phase 08]: Used French assertion text ("refus") in tests -- error template renders via i18n, not raw English message
- [Phase 08]: Zero new npm dependencies -- only built-in node:test, node:assert, node:http
- [Phase 09]: No code snippets in SECURITY-BOUNDARY.md -- file:line references only (per user decision)
- [Phase 09]: English language for SECURITY-BOUNDARY.md (per user decision)
- [Phase 09]: Real findings listed without severity rating -- status only (Open / Accepted Risk)
- [Phase 10]: dastLocalize() as separate function (not parameterized localize()) -- cleaner SCA vs DAST field set separation
- [Phase 10]: Unicode escape sequences for French accents in JSON -- reliable cross-platform encoding
- [Phase 10]: Severity badges and OWASP categories kept in English per locked decision
- [Phase 11]: In-memory activityTracker for real-time student activity (not DB) -- acceptable for classroom scale
- [Phase 11]: JS aggregation instead of GROUP BY/COUNT(DISTINCT) for JSON DB adapter compatibility
- [Phase 11]: Parameterized queries required for JSON DB adapter (inline SQL values not matched)
- [Phase 12]: RBAC-bypass hardening: secondary role check for answer key to prevent student access when RBAC disabled
- [Phase 12]: Finding 11 classified as Needs Investigation; all others as True Positive per SOLUTION-GUIDE.md
- [Phase 12]: Hoisted studentCookie/profCookie to runTests() scope for cross-phase smoke test access
- [Phase 13]: Used v3.1 (not v1.1) for version history entry, continuing existing README version scheme
- [Phase 13]: Collapsed v1.2-v1.9 into single milestone line; added Instructor Tools subsection under For Instructors; answer key as usage-focused paragraph
- [Phase 14]: CommonJS flat config for ESLint 9 (project has no type:module)
- [Phase 14]: eslint-config-prettier/flat as last config entry to disable conflicting rules
- [Phase 14]: EJS templates excluded from Prettier via .prettierignore (breaks template syntax)
- [Phase 14]: no-console disabled globally (console output is teaching experience)
- [Phase 14]: caughtErrorsIgnorePattern added to no-unused-vars (catch clause vars need separate ESLint option)
- [Phase 14]: routes/pentest.js excluded from ESLint and Prettier (Phase 16 replaces entirely)
- [Phase 14]: Dead hashPassword import removed from routes/auth.js (intentional vuln #4 uses plaintext)
- [Phase 15]: Included VM/Pentest/Admin page-specific CSS in styles.css upfront so Plan 02 only needs to delete style blocks
- [Phase 15]: Section comment headers (/* ===== Section Name ===== */) for CSS organization

### Roadmap Evolution

- 2026-03-19: Roadmap expanded from 4 to 11 phases based on product review. Original phases 7-9 renumbered to 12-14. Added: Quick Wins (7), Testing (8), Security Boundary Doc (9), DAST French (10), Instructor Tools (11), CSS Extraction (15), CTF Pentest Lab (16)

### Pending Todos

None.

### Blockers/Concerns

- 12-instance memory footprint untested with 30 concurrent students (carried from v1.0)
- 4 minor tech debt items from v1.0 audit (see milestones/v1.0-MILESTONE-AUDIT.md)
- RESOLVED: Prism.js vendored locally (not CDN, not CSS-only) -- decided during Phase 6 Plan 1
- RESOLVED: Seed data modified directly in seedDatabase() -- decided during Phase 6 Plan 1

## Session Continuity

Last session: 2026-03-21T19:09:59Z
Stopped at: Completed 15-01-PLAN.md
Resume file: None
