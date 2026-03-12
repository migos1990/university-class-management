---
phase: 06-inline-code-snippets
plan: 01
subsystem: ui
tags: [prism.js, syntax-highlighting, ejs, seed-data, code-display]

# Dependency graph
requires:
  - phase: none
    provides: n/a
provides:
  - Multi-line code snippets with snippet_start_line for all 12 SCA findings
  - Vendored Prism.js v1.29.0 with One Dark theme for syntax highlighting
  - Prism.js-powered code display with line numbers and vulnerable-line callout
  - Conditional Prism asset loading via needsPrism flag
affects: [06-02-inline-code-snippets, 07-instructor-answer-key]

# Tech tracking
tech-stack:
  added: [prism.js-1.29.0, prism-themes-one-dark-1.9.0]
  patterns: [conditional-asset-loading-via-needsPrism, vendored-js-in-public-vendor]

key-files:
  created:
    - public/vendor/prism/prism.min.js
    - public/vendor/prism/prism-one-dark.css
    - public/vendor/prism/prism-line-numbers.css
    - public/vendor/prism/prism-line-highlight.css
  modified:
    - utils/seedData.js
    - config/database.js
    - views/sca/finding-detail.ejs
    - views/partials/header.ejs
    - views/partials/footer.ejs
    - routes/sca.js

key-decisions:
  - "Vendored Prism.js locally instead of CDN for offline Codespace reliability"
  - "Used escaped EJS output (<%= %>) for code_snippet to prevent XSS"
  - "Conditional asset loading via locals.needsPrism to avoid loading Prism on non-SCA pages"
  - "Updated finding line numbers to match actual codebase line numbers"

patterns-established:
  - "Conditional asset loading: pass needsPrism (or similar flag) in render call, check locals.needsPrism in header/footer"
  - "Vendor directory: third-party JS/CSS goes in public/vendor/<library>/"

requirements-completed: [SNIP-01, SNIP-02, SNIP-03, SNIP-04]

# Metrics
duration: 4min
completed: 2026-03-12
---

# Phase 6 Plan 1: Inline Code Snippets Summary

**Prism.js-powered syntax-highlighted code blocks with line numbers and vulnerable-line callout on SCA finding detail pages**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-12T20:06:38Z
- **Completed:** 2026-03-12T20:10:51Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments
- All 12 SCA findings enriched with 5-15 line multi-line code snippets extracted from the actual codebase
- Prism.js v1.29.0 vendored locally (core + JS + JSON + line-numbers + line-highlight plugins + One Dark theme)
- Finding detail pages now display syntax-colored code with accurate line numbers and highlighted vulnerable line
- Prism assets conditionally loaded only on finding-detail pages via needsPrism flag

## Task Commits

Each task was committed atomically:

1. **Task 1: Expand seed data and update DB adapter for multi-line code snippets** - `a97cdfb` (feat)
2. **Task 2: Vendor Prism.js and update templates for syntax-highlighted code display** - `7973831` (feat)

## Files Created/Modified
- `public/vendor/prism/prism.min.js` - Concatenated Prism.js bundle (core + JSON + line-numbers + line-highlight)
- `public/vendor/prism/prism-one-dark.css` - One Dark syntax theme
- `public/vendor/prism/prism-line-numbers.css` - Line numbers plugin styles
- `public/vendor/prism/prism-line-highlight.css` - Line highlight plugin styles
- `utils/seedData.js` - Multi-line code snippets and snippet_start_line for all 12 findings
- `config/database.js` - Updated INSERT handler to map snippet_start_line field
- `views/sca/finding-detail.ejs` - Prism.js-powered code block replacing plain pre
- `views/partials/header.ejs` - Conditional Prism CSS loading and line-highlight style override
- `views/partials/footer.ejs` - Conditional Prism JS loading
- `routes/sca.js` - needsPrism: true in finding-detail render call

## Decisions Made
- Vendored Prism.js locally rather than using CDN -- ensures offline availability in GitHub Codespaces
- Used escaped EJS output (`<%= %>`) for code_snippet to prevent XSS -- Prism reads textContent which correctly reverses HTML entity encoding
- Updated some finding line_number values to match actual codebase locations (e.g., finding 10 updated from line 435 to line 509 to match actual backup download route location)
- Chose rgba(224, 108, 117, 0.15) background with #e06c75 left border for vulnerable line highlight -- consistent with One Dark theme's red accent

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected finding line numbers to match actual codebase**
- **Found during:** Task 1
- **Issue:** Several finding line_number values in the plan did not match actual codebase locations (e.g., finding 10 listed line 435 but backup download is at line 509; finding 5 listed line 18 but audit_logging is at line 19)
- **Fix:** Updated line_number and snippet_start_line to reflect actual file positions after reading source files
- **Files modified:** utils/seedData.js
- **Verification:** Verification script confirmed all vulnIdx values are within snippet range
- **Committed in:** a97cdfb (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix)
**Impact on plan:** Line number correction was necessary for accuracy. No scope creep.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Prism.js vendored and conditionally loaded -- ready for any future syntax highlighting needs
- snippet_start_line field available in all findings for accurate line number display
- Plan 02 (if it exists) can build on this foundation for additional code display enhancements

## Self-Check: PASSED

All 10 created/modified files verified on disk. Both task commits (a97cdfb, 7973831) confirmed in git log.

---
*Phase: 06-inline-code-snippets*
*Completed: 2026-03-12*
