---
phase: 15-css-extraction
plan: 01
subsystem: ui
tags: [css, stylesheet, ejs, templates, static-assets]

# Dependency graph
requires:
  - phase: 06-inline-code-snippets
    provides: Prism.js conditional loading pattern in header.ejs
provides:
  - public/styles.css containing all shared and page-specific CSS (707 lines)
  - header.ejs linking external stylesheet instead of 400-line inline block
  - 8 SCA/DAST templates cleaned of inline style blocks
affects: [15-css-extraction plan 02]

# Tech tracking
tech-stack:
  added: []
  patterns: [external stylesheet via Express static middleware, section-commented CSS organization]

key-files:
  created: [public/styles.css]
  modified: [views/partials/header.ejs, views/sca/student-lab.ejs, views/sca/finding-detail.ejs, views/sca/instructor.ejs, views/sca/answer-key.ejs, views/sca/student-detail.ejs, views/dast/student-lab.ejs, views/dast/scenario-detail.ejs, views/dast/instructor.ejs]

key-decisions:
  - "Included VM/Pentest/Admin page-specific CSS in styles.css so Plan 02 only needs to delete style blocks"
  - "Used section comment headers (/* ===== Section Name ===== */) for CSS organization"

patterns-established:
  - "All shared CSS in public/styles.css, served via Express static middleware"
  - "Template files use classes from styles.css, no inline <style> blocks"

requirements-completed: [CSS-01]

# Metrics
duration: 8min
completed: 2026-03-21
---

# Phase 15 Plan 01: CSS Extraction Summary

**707-line shared stylesheet extracting CSS from header.ejs and all 16 templates, with 8 SCA/DAST templates cleaned of inline style blocks**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-21T19:01:20Z
- **Completed:** 2026-03-21T19:09:59Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments
- Created public/styles.css (707 lines) containing all shared and page-specific CSS from 16+ template files
- Replaced 400-line inline style block in header.ejs with single `<link>` tag
- Removed inline `<style>` blocks from all 8 SCA and DAST template files
- Preserved Prism.js conditional block unchanged in header.ejs

## Task Commits

Each task was committed atomically:

1. **Task 1: Create public/styles.css and update header.ejs** - `b031365` (feat)
2. **Task 2: Remove inline style blocks from SCA and DAST templates** - `1b6be4b` (refactor)

## Files Created/Modified
- `public/styles.css` - Shared stylesheet with all CSS organized into 20+ named sections
- `views/partials/header.ejs` - Replaced inline styles with `<link rel="stylesheet" href="/styles.css">`
- `views/sca/student-lab.ejs` - Removed 16-line inline style block
- `views/sca/finding-detail.ejs` - Removed 10-line inline style block
- `views/sca/instructor.ejs` - Removed 22-line inline style block
- `views/sca/answer-key.ejs` - Removed 73-line inline style block
- `views/sca/student-detail.ejs` - Removed 11-line inline style block
- `views/dast/student-lab.ejs` - Removed 13-line inline style block
- `views/dast/scenario-detail.ejs` - Removed 10-line inline style block
- `views/dast/instructor.ejs` - Removed 13-line inline style block

## Decisions Made
- Included all VM, Pentest, and Admin page-specific CSS in styles.css upfront so Plan 02 only needs to delete style blocks (no CSS migration needed in Plan 02)
- Used `/* ===== Section Name ===== */` comment headers for clear CSS organization by feature area
- Preserved Prism.js conditional 3-line override inline in header.ejs (page-specific conditional rendering)

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- public/styles.css already contains CSS for VM, Pentest, and Admin templates
- Plan 02 only needs to delete inline `<style>` blocks from the remaining 8 templates (VM, Pentest, Admin)
- All pages will render identically since the same CSS classes are now served via the external stylesheet

## Self-Check: PASSED

- FOUND: public/styles.css
- FOUND: 15-01-SUMMARY.md
- FOUND: b031365 (Task 1 commit)
- FOUND: 1b6be4b (Task 2 commit)
- FOUND: stylesheet link in header.ejs
- FOUND: sev-Critical in styles.css
- PASS: No `<style>` tags in any SCA/DAST template

---
*Phase: 15-css-extraction*
*Completed: 2026-03-21*
