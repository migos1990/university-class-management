---
phase: 14-code-quality
plan: 01
subsystem: infra
tags: [eslint, prettier, linting, formatting, code-quality, devtools]

# Dependency graph
requires: []
provides:
  - "ESLint 9 flat config with recommended rules and Node.js globals"
  - "Prettier 3 config matching existing code style (singleQuote, semi, 100-width)"
  - "npm scripts: lint, lint:fix, format, format:check"
  - "eslint-config-prettier integration to avoid rule conflicts"
affects: [14-code-quality]

# Tech tracking
tech-stack:
  added: [eslint@9, "@eslint/js@9", globals, eslint-config-prettier, prettier@3]
  patterns: [eslint-flat-config, prettier-json-config, eslint-prettier-integration]

key-files:
  created: [eslint.config.js, .prettierrc, .prettierignore]
  modified: [package.json]

key-decisions:
  - "CommonJS flat config for ESLint 9 (project has no type:module)"
  - "eslint-config-prettier/flat as last config entry to disable conflicting rules"
  - "EJS templates excluded from Prettier via .prettierignore (breaks template syntax)"
  - "no-console disabled globally (console output is teaching experience)"

patterns-established:
  - "ESLint flat config: standalone ignores object for global excludes"
  - "Underscore prefix pattern for unused Express middleware params (_req, _next)"
  - "Prettier targets JS files only, EJS excluded"

requirements-completed: [QUAL-01, QUAL-04]

# Metrics
duration: 2min
completed: 2026-03-21
---

# Phase 14 Plan 01: Linting and Formatting Tooling Summary

**ESLint 9 flat config and Prettier 3 with npm scripts for lint, lint:fix, format, and format:check**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-21T18:24:06Z
- **Completed:** 2026-03-21T18:26:43Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Installed ESLint 9, Prettier 3, and three supporting packages as devDependencies
- Created ESLint 9 flat config with recommended preset, Node.js globals, no-console off, underscore-prefix unused var ignore, and eslint-config-prettier integration
- Created Prettier config matching existing code conventions and ignore file excluding EJS templates, vendor, and data directories
- Added four npm scripts (lint, lint:fix, format, format:check) alongside existing scripts

## Task Commits

Each task was committed atomically:

1. **Task 1: Install devDependencies and add npm scripts** - `f167674` (chore)
2. **Task 2: Create ESLint, Prettier, and ignore configuration files** - `3c8570f` (feat)

## Files Created/Modified
- `package.json` - Added 5 devDependencies and 4 npm scripts
- `eslint.config.js` - ESLint 9 CommonJS flat config with recommended preset, global ignores, node globals, no-console off, underscore unused vars
- `.prettierrc` - Prettier 3 JSON config: singleQuote, semi, printWidth 100, tabWidth 2, no trailing comma, lf
- `.prettierignore` - Excludes EJS templates, public/vendor, database, backups, instances, .planning, docs

## Decisions Made
- CommonJS format for eslint.config.js (project uses require/module.exports, no type:module)
- eslint-config-prettier/flat as last array entry to disable conflicting formatting rules
- EJS templates excluded from Prettier via .prettierignore (Prettier breaks <% %> syntax)
- no-console rule disabled globally per user decision (console output is part of teaching)
- Underscore prefix pattern (argsIgnorePattern: ^_) for Express middleware unused params

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- package-lock.json is in .gitignore so it was not committed (not an issue, just noted)
- npm test (smoke test) requires running server instances and exits 1 when none are running; this is pre-existing behavior unrelated to tooling changes

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- ESLint reports errors in several files (unused vars, etc.) -- Plan 02 will fix these
- Prettier reports 27 files need formatting -- Plan 02 will run format:fix
- All tooling infrastructure is in place for Plan 02 to clean the codebase

## Self-Check: PASSED

All files verified present. All commits verified in git log.

---
*Phase: 14-code-quality*
*Completed: 2026-03-21*
