# Phase 14: Code Quality - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Add ESLint 9 and Prettier 3 tooling with npm scripts (`npm run lint`, `npm run format`), clean up dead code (unused vars, unreachable code, commented-out blocks), while preserving all 12 intentional SCA vulnerabilities and the SQL pattern-matching DB adapter unchanged.

</domain>

<decisions>
## Implementation Decisions

### Linting strictness
- Use `eslint:recommended` preset only — catches real bugs without style noise
- Prettier handles all formatting — no ESLint style rules
- Lint scope: all JS files (routes, middleware, utils, config, test, scripts)
- Manual npm scripts only (`npm run lint`, `npm run format`) — no pre-commit hooks, no CI
- Intentional vulnerabilities: inline `// eslint-disable-next-line` comments on the ~12 specific lines
- DB adapter (config/database.js): same inline eslint-disable approach on specific flagged patterns

### Console statement policy
- Disable `no-console` rule entirely — console output is part of the teaching experience
- No additional code comments on intentional vulnerability console.log (already documented in SECURITY-BOUNDARY.md)

### Formatting style
- Single quotes, semicolons: `singleQuote: true, semi: true` — matches existing code style
- Line width: 100 characters — comfortable for Express route handlers, avoids aggressive wrapping
- JS files only — do NOT format EJS templates (Prettier can break template syntax)
- Prettier config in `.prettierrc` or `prettier.config.js`

### Dead code scope
- ESLint-driven: remove whatever `no-unused-vars` and `no-unreachable` flag
- Remove commented-out code blocks (git history preserves them)
- Leave pentest module untouched — Phase 16 replaces it entirely
- No manual audit for unused exports beyond what ESLint catches

### Claude's Discretion
- ESLint flat config structure (eslint.config.js)
- Prettier config format (.prettierrc vs prettier.config.js)
- Exact eslint-disable comments and which rules to suppress per vulnerability line
- Whether to add a `lint:fix` convenience script
- Tab width (2 vs 4) — match existing indentation

</decisions>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `package.json`: Already has `test` and `test:integration` scripts — add `lint` and `format` alongside
- `.gitignore`: Already ignores node_modules, IDE files — no changes needed

### Established Patterns
- CommonJS (`require`) throughout — no ES modules
- Single quotes + semicolons consistently used
- `const`/`let` only — no `var` usage found
- 73 console statements (intentional for teaching/logging)
- ~7,230 lines of JS across 20 files

### Integration Points
- `package.json`: Add `lint`, `format` scripts + `eslint`/`prettier` devDependencies
- `eslint.config.js`: New flat config file (ESLint 9)
- `.prettierrc` or equivalent: New Prettier config
- Specific intentional vulnerability lines in: server.js, utils/encryption.js, routes/auth.js, middleware/rateLimiter.js, config/database.js
- SECURITY-BOUNDARY.md: Reference for which lines are intentional (no code changes needed there)

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 14-code-quality*
*Context gathered: 2026-03-21*
