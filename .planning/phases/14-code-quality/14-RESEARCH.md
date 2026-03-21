# Phase 14: Code Quality - Research

**Researched:** 2026-03-21
**Domain:** ESLint 9 + Prettier 3 tooling for a CommonJS Express.js educational platform
**Confidence:** HIGH

## Summary

Phase 14 adds code quality tooling (ESLint 9 + Prettier 3) to a ~7,700-line CommonJS Express.js application with 30 JS files. The project has no existing lint/format configuration. The codebase already follows consistent conventions (2-space indentation, single quotes, semicolons, `const`/`let` only), so Prettier formatting changes should be minimal. The primary challenge is configuring ESLint to pass cleanly while preserving the 12 intentional SCA vulnerabilities and the SQL pattern-matching database adapter (`config/database.js`).

ESLint 9 uses the flat config format (`eslint.config.js`). Since this is a CommonJS project (no `"type": "module"` in package.json), the config file uses `require()`/`module.exports`. The `@eslint/js` recommended preset catches real bugs without style noise. Prettier 3 handles all formatting via a separate `.prettierrc` config. The `eslint-config-prettier` package disables any residual formatting rules from ESLint that could conflict.

**Primary recommendation:** Install `eslint@9`, `@eslint/js@9`, `globals`, `eslint-config-prettier`, and `prettier` as devDependencies. Create `eslint.config.js` with flat config (CommonJS format), `.prettierrc` for formatting rules, and `.prettierignore` to exclude EJS templates and vendored files. Add `npm run lint` and `npm run format` scripts. Use inline `// eslint-disable-next-line` comments on the ~12 intentional vulnerability lines.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Use `eslint:recommended` preset only -- catches real bugs without style noise
- Prettier handles all formatting -- no ESLint style rules
- Lint scope: all JS files (routes, middleware, utils, config, test, scripts)
- Manual npm scripts only (`npm run lint`, `npm run format`) -- no pre-commit hooks, no CI
- Intentional vulnerabilities: inline `// eslint-disable-next-line` comments on the ~12 specific lines
- DB adapter (config/database.js): same inline eslint-disable approach on specific flagged patterns
- Disable `no-console` rule entirely -- console output is part of the teaching experience
- No additional code comments on intentional vulnerability console.log (already documented in SECURITY-BOUNDARY.md)
- Single quotes, semicolons: `singleQuote: true, semi: true` -- matches existing code style
- Line width: 100 characters -- comfortable for Express route handlers, avoids aggressive wrapping
- JS files only -- do NOT format EJS templates (Prettier can break template syntax)
- Prettier config in `.prettierrc` or `prettier.config.js`
- ESLint-driven dead code removal: remove whatever `no-unused-vars` and `no-unreachable` flag
- Remove commented-out code blocks (git history preserves them)
- Leave pentest module untouched -- Phase 16 replaces it entirely

### Claude's Discretion
- ESLint flat config structure (eslint.config.js)
- Prettier config format (.prettierrc vs prettier.config.js)
- Exact eslint-disable comments and which rules to suppress per vulnerability line
- Whether to add a `lint:fix` convenience script
- Tab width (2 vs 4) -- match existing indentation

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| QUAL-01 | ESLint 9 and Prettier 3 are configured with npm scripts (`npm run lint`, `npm run format`) | Standard Stack section: exact packages, versions, config files, npm scripts |
| QUAL-02 | Codebase passes ESLint and Prettier with zero errors/warnings | Architecture Patterns: eslint-disable strategy for intentional vulnerabilities; no-console disabled globally |
| QUAL-03 | Dead code and unused variables removed | Common Pitfalls: ESLint-driven detection via no-unused-vars/no-unreachable; commented-out code manual removal |
| QUAL-04 | Intentional vulnerabilities and SQL pattern-matching DB adapter preserved unchanged | Architecture Patterns: inline eslint-disable approach; Vulnerability Inventory section maps exact locations |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| eslint | ^9.39 | JavaScript linter (bug detection) | User requirement specifies ESLint 9; latest 9.x series |
| @eslint/js | ^9.39 | `recommended` rule preset for ESLint 9 flat config | Official ESLint recommended rules package for flat config |
| prettier | ^3.8 | Code formatter (whitespace, quotes, semis) | User requirement specifies Prettier 3; latest 3.x |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| globals | ^16.0 | Provides Node.js global variable definitions for ESLint | Required for `globals.node` in flat config languageOptions |
| eslint-config-prettier | ^10.0 | Disables ESLint rules that conflict with Prettier | Safety net -- placed last in ESLint config array |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| ESLint 9 | ESLint 10 (just released Feb 2026) | User requirement explicitly says ESLint 9; v10 removes deprecated formatting rules entirely but is too new |
| eslint-config-prettier | Nothing (ESLint 9 recommended has no formatting rules) | Costs nothing to include; prevents future breakage if rules are added |
| eslint-plugin-prettier | eslint-config-prettier only | Plugin runs Prettier as an ESLint rule -- unnecessary overhead; separate tools is cleaner |

**Installation:**
```bash
npm install --save-dev eslint@9 @eslint/js@9 globals eslint-config-prettier prettier
```

## Architecture Patterns

### New Files to Create
```
project-root/
  eslint.config.js       # ESLint 9 flat config (CommonJS)
  .prettierrc            # Prettier config (JSON)
  .prettierignore        # Exclude EJS, vendored, generated files
```

### Pattern 1: ESLint 9 Flat Config (CommonJS)

**What:** Single `eslint.config.js` using `require()`/`module.exports` because the project has no `"type": "module"` in package.json.

**Example:**
```javascript
// eslint.config.js
const js = require('@eslint/js');
const globals = require('globals');
const eslintConfigPrettier = require('eslint-config-prettier/flat');

module.exports = [
  // Global ignores (must be standalone object with only ignores key)
  {
    ignores: [
      'node_modules/',
      'database/',
      'backups/',
      'instances/',
      'public/vendor/**',
    ],
  },
  // Main config
  {
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',              // Console output is part of teaching experience
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',         // Allow _prefixed unused params (Express middleware)
        varsIgnorePattern: '^_',
      }],
    },
  },
  // Prettier compat (must be last)
  eslintConfigPrettier,
];
```

**Source:** [ESLint Configuration Files docs](https://eslint.org/docs/latest/use/configure/configuration-files)

### Pattern 2: Prettier Configuration

**What:** JSON config matching existing code style conventions.

**Example:**
```json
{
  "singleQuote": true,
  "semi": true,
  "printWidth": 100,
  "tabWidth": 2,
  "trailingComma": "none",
  "endOfLine": "lf"
}
```

**Rationale:**
- `tabWidth: 2` -- matches existing 2-space indentation throughout codebase
- `singleQuote: true` -- matches existing convention
- `semi: true` -- matches existing convention
- `printWidth: 100` -- user decision; accommodates Express route handlers
- `trailingComma: "none"` -- matches existing code style (no trailing commas found in codebase)
- `.prettierrc` (JSON) over `prettier.config.js` -- simpler for a project with no programmatic config needs

### Pattern 3: .prettierignore

**What:** Exclude non-JS files that Prettier would mangle.

**Example:**
```
# EJS templates (Prettier breaks template syntax)
**/*.ejs

# Vendored libraries
public/vendor/

# Generated/data directories
database/
backups/
instances/

# Planning docs (not code)
.planning/
docs/
```

### Pattern 4: eslint-disable for Intentional Vulnerabilities

**What:** Inline comments to suppress ESLint errors on specific intentional vulnerability lines.

**When to use:** Only on the ~12 intentional vulnerability lines documented in SECURITY-BOUNDARY.md.

**Example pattern:**
```javascript
// eslint-disable-next-line no-unused-vars -- INTENTIONAL: SCA Finding #2 (CWE-321)
const DEFAULT_ENCRYPTION_KEY = 'university-app-secret-key-32!';
```

**Key insight:** Most vulnerability lines will NOT trigger ESLint errors with `eslint:recommended`. The vulnerabilities are logic/security issues (hardcoded secrets, missing checks, plaintext comparison), not JavaScript syntax errors. Only lines that happen to also violate an `eslint:recommended` rule need `eslint-disable` comments. This must be determined empirically by running `npm run lint` and examining the output.

### Pattern 5: npm Scripts

**What:** Add lint and format scripts to package.json.

```json
{
  "scripts": {
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "format": "prettier --write \"**/*.js\"",
    "format:check": "prettier --check \"**/*.js\""
  }
}
```

**Notes:**
- `lint` runs ESLint against all JS files (respects `ignores` in flat config)
- `lint:fix` auto-fixes what it can (convenience script -- Claude's discretion)
- `format` applies Prettier formatting
- `format:check` verifies formatting without changing files (useful for success criteria check)
- Prettier glob `"**/*.js"` ensures only JS files are formatted (not EJS)

### Anti-Patterns to Avoid
- **Running Prettier on EJS templates:** Prettier will break EJS `<% %>` syntax. Use `.prettierignore` to exclude `**/*.ejs`.
- **Using eslint-plugin-prettier:** Runs Prettier inside ESLint, making linting slow. Keep them separate.
- **Adding `eslint-disable` everywhere preemptively:** Only add after running lint and seeing actual errors. Many vulnerability patterns are invisible to ESLint.
- **Formatting then linting:** Always lint first, then format. Linting can introduce fixes that Prettier needs to reformat.

## Intentional Vulnerability Inventory

These are the 12 SCA vulnerabilities from SECURITY-BOUNDARY.md. For each, assessment of whether `eslint:recommended` rules will flag them:

| # | Description | Location | ESLint Risk | Likely Rule |
|---|-------------|----------|-------------|-------------|
| 1 | Hardcoded session secret | `server.js:46` | NONE | String literal in config is valid JS |
| 2 | Hardcoded AES key | `utils/encryption.js:6` | NONE | String literal assignment is valid JS |
| 3 | Plaintext credentials logged | `server.js:~141` (seed data ref) | NONE | console.log is disabled |
| 4 | Plaintext password comparison | `routes/auth.js:38` | NONE | `===` comparison is valid JS |
| 5 | Audit logging defaults OFF | `config/database.js:19` | NONE | Object property assignment |
| 6 | IDOR: no ownership check | `routes/classes.js:39` | NONE | Logic absence, not syntax |
| 7 | No CSRF protection | `server.js:1` (absence) | NONE | Missing middleware, not syntax |
| 8 | Rate limiting only on login | `middleware/rateLimiter.js:9` | NONE | Logic scope, not syntax |
| 9 | No HTTP security headers | `server.js:17` (absence) | NONE | Missing middleware, not syntax |
| 10 | Path traversal in backup download | `routes/admin.js:509` | NONE | `req.params` usage is valid JS |
| 11 | Outdated express-session | `package.json:24` | NONE | ESLint does not lint JSON |
| 12 | Session cookie missing secure flag | `server.js:51` | NONE | Object config is valid JS |

**Key finding:** None of the 12 intentional vulnerabilities are likely to trigger `eslint:recommended` rules. They are security issues (hardcoded secrets, missing controls, logic flaws), not JavaScript syntax errors. The `eslint-disable` comments may not even be needed for these specific lines -- this must be verified by running `npm run lint` after initial configuration.

The `config/database.js` SQL pattern-matching adapter (the `executeSQL` function, ~300 lines) uses complex conditional logic that is syntactically valid JavaScript. It may have some unused variable warnings or other issues that need `eslint-disable` on specific lines, but this should be determined empirically.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Code formatting | Custom style enforcement logic | Prettier 3 | Opinionated formatter handles all whitespace, quotes, semis consistently |
| Bug detection rules | Custom rule definitions | `@eslint/js` recommended preset | Community-vetted rule set, maintained by ESLint core team |
| ESLint/Prettier conflict resolution | Manual rule toggling | `eslint-config-prettier` | Automatically disables conflicting rules, stays updated |
| Node.js global definitions | Manual `/* global */` comments | `globals` npm package | Comprehensive, up-to-date Node.js globals list |

**Key insight:** The entire tooling chain is standard -- no custom configuration beyond the project-specific rule overrides (`no-console: off`, `argsIgnorePattern`).

## Common Pitfalls

### Pitfall 1: Prettier Destroying EJS Templates
**What goes wrong:** Running Prettier on `.ejs` files breaks `<% %>` template syntax.
**Why it happens:** Prettier tries to parse EJS as HTML and reformats/breaks the embedded JavaScript.
**How to avoid:** Add `**/*.ejs` to `.prettierignore`. Use JS-only glob in the format script: `prettier --write "**/*.js"`.
**Warning signs:** EJS templates rendering broken HTML after formatting.

### Pitfall 2: Vendored Files Causing Lint Errors
**What goes wrong:** ESLint processes `public/vendor/prism/prism.min.js` (25KB minified) and reports hundreds of errors.
**Why it happens:** Minified vendor code violates every formatting and naming convention.
**How to avoid:** Add `public/vendor/**` to ESLint `ignores` in flat config.
**Warning signs:** Hundreds of errors from a single file you didn't write.

### Pitfall 3: `no-unused-vars` on Express Middleware Parameters
**What goes wrong:** Express error handlers use the pattern `(err, req, res, next)` where `next` (or `err`) may be unused but the 4-parameter signature is required by Express.
**Why it happens:** `no-unused-vars` flags parameters that are declared but never referenced.
**How to avoid:** Configure `argsIgnorePattern: '^_'` or use `'no-unused-vars': ['error', { args: 'none' }]` to ignore all unused function arguments. The `argsIgnorePattern` approach is better because it forces explicit marking of intentionally unused params with `_` prefix.
**Warning signs:** Errors on `(req, res, next)` in middleware where `next` is not called.

### Pitfall 4: Breaking the Smoke Test
**What goes wrong:** Code quality changes (dead code removal, variable renaming) break existing functionality.
**Why it happens:** Removing "unused" code that is actually used through dynamic patterns, or reformatting code in ways that change behavior.
**How to avoid:** Run `npm test` (smoke test) before AND after every code quality change. Prettier is safe (whitespace only) but ESLint `--fix` and manual dead code removal can break things.
**Warning signs:** `npm test` fails after changes.

### Pitfall 5: ESLint Flat Config Ignores Must Be Standalone
**What goes wrong:** Adding `ignores` alongside other config keys creates a file-level filter, not a global ignore.
**Why it happens:** In flat config, `ignores` only acts as a global ignore when it is the ONLY key in the config object (besides `name`).
**How to avoid:** Use a dedicated config object with only `{ ignores: [...] }` as the first element in the config array.
**Warning signs:** Ignored files still being linted.

### Pitfall 6: CommonJS Config File Format
**What goes wrong:** Using `import`/`export` syntax in `eslint.config.js` for a CommonJS project.
**Why it happens:** Most ESLint 9 docs show ESM examples. Project has no `"type": "module"` in package.json.
**How to avoid:** Use `const x = require('...')` and `module.exports = [...]` in `eslint.config.js`.
**Warning signs:** `SyntaxError: Cannot use import statement outside a module` when running lint.

### Pitfall 7: Dead Code Removal Touching Pentest Module
**What goes wrong:** Removing "unused" code in `routes/pentest.js` that Phase 16 will replace entirely.
**Why it happens:** Pentest module has dead code that ESLint will flag.
**How to avoid:** User decision: leave pentest module untouched. Either add eslint-disable comments or accept warnings from that file. Better: suppress specific rules for that file in the ESLint config.
**Warning signs:** Changes to `routes/pentest.js` or related pentest files.

## Code Examples

### Complete eslint.config.js (CommonJS)
```javascript
// Source: ESLint 9 flat config docs + project-specific requirements
const js = require('@eslint/js');
const globals = require('globals');
const eslintConfigPrettier = require('eslint-config-prettier/flat');

module.exports = [
  // Global ignores
  {
    ignores: [
      'node_modules/',
      'database/',
      'backups/',
      'instances/',
      'public/vendor/**',
    ],
  },

  // Main configuration
  {
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
    rules: {
      'no-console': 'off',
      'no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
    },
  },

  // Disable ESLint rules that conflict with Prettier
  eslintConfigPrettier,
];
```

### Complete .prettierrc
```json
{
  "singleQuote": true,
  "semi": true,
  "printWidth": 100,
  "tabWidth": 2,
  "trailingComma": "none",
  "endOfLine": "lf"
}
```

### Complete .prettierignore
```
**/*.ejs
public/vendor/
database/
backups/
instances/
.planning/
docs/
node_modules/
```

### package.json scripts addition
```json
{
  "lint": "eslint .",
  "lint:fix": "eslint . --fix",
  "format": "prettier --write \"**/*.js\"",
  "format:check": "prettier --check \"**/*.js\""
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `.eslintrc.json` + `.eslintignore` | `eslint.config.js` flat config | ESLint 9 (Apr 2024) | eslintrc deprecated; flat config is default |
| `env: { node: true }` | `globals: { ...globals.node }` | ESLint 9 | Environment key removed; use `globals` package |
| ESLint formatting rules | Prettier (separate tool) | ESLint 9 deprecated formatting rules | Formatting rules deprecated in v9, removed in v10 |
| `eslint-plugin-prettier` | Separate lint + format scripts | Community consensus 2024+ | Running Prettier inside ESLint is slow; keep tools separate |
| ESLint 9 | ESLint 10 released Feb 2026 | Feb 2026 | User requirement locks to ESLint 9; v10 removes formatting rules entirely |

**Deprecated/outdated:**
- `.eslintrc.json`/`.eslintrc.js`: Deprecated in ESLint 9, use flat config
- `.eslintignore`: Deprecated, use `ignores` key in flat config
- `env` key: Removed, use `globals` package
- `eslint-plugin-prettier`: Still works but community consensus favors separate tools

## Open Questions

1. **Which specific lines will ESLint actually flag?**
   - What we know: The 12 intentional vulnerabilities are unlikely to trigger `eslint:recommended` rules (they are security issues, not syntax errors). The database adapter uses complex pattern matching that is syntactically valid.
   - What's unclear: There may be genuine unused variables, unreachable code, or other issues across the ~7,700 lines that only running ESLint will reveal.
   - Recommendation: Run `npm run lint` immediately after initial config setup, then address findings iteratively. Do NOT preemptively add eslint-disable comments.

2. **Pentest module dead code handling**
   - What we know: User decided to leave pentest module untouched (Phase 16 replaces it).
   - What's unclear: How many lint errors the pentest files will produce and whether to suppress them globally for those files or line-by-line.
   - Recommendation: Add a file-level override in eslint.config.js to relax rules for `routes/pentest.js` and `views/pentest/*.ejs` (EJS already excluded). Or simply add eslint-disable-file comment at top of pentest files.

3. **Trailing comma preference**
   - What we know: Existing code does not use trailing commas consistently.
   - What's unclear: Whether `"none"` or `"es5"` better matches the existing style.
   - Recommendation: Use `"none"` to minimize formatting changes (matches most existing code).

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Node.js built-in test runner (node:test) + custom smoke test |
| Config file | None (no config file needed for node:test) |
| Quick run command | `npm test` (smoke test -- 13 ports health + auth journey) |
| Full suite command | `npm run test:integration` (node --test test/*.test.js) |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| QUAL-01 | ESLint + Prettier configured with npm scripts | smoke | `npm run lint && npm run format:check` | N/A -- scripts ARE the test |
| QUAL-02 | Zero errors/warnings from lint + format | smoke | `npm run lint && npm run format:check` | N/A -- clean output IS the test |
| QUAL-03 | No dead code / unused vars | smoke | `npm run lint` (no-unused-vars rule) | N/A -- lint clean IS the test |
| QUAL-04 | 12 vulnerabilities + DB adapter preserved | integration | `npm test` (existing smoke test) | Yes -- scripts/smoke-test.js |

### Sampling Rate
- **Per task commit:** `npm run lint && npm run format:check && npm test`
- **Per wave merge:** `npm run lint && npm run format:check && npm test && npm run test:integration`
- **Phase gate:** All four commands green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `npm run lint` script -- does not exist yet (QUAL-01 creates it)
- [ ] `npm run format` script -- does not exist yet (QUAL-01 creates it)
- [ ] `eslint.config.js` -- does not exist yet (QUAL-01 creates it)
- [ ] `.prettierrc` -- does not exist yet (QUAL-01 creates it)
- [ ] `.prettierignore` -- does not exist yet (QUAL-01 creates it)
- [ ] devDependencies (eslint, prettier, etc.) -- not installed yet

*(All gaps are addressed by the phase implementation itself -- no separate Wave 0 needed)*

## Sources

### Primary (HIGH confidence)
- [ESLint Configuration Files docs](https://eslint.org/docs/latest/use/configure/configuration-files) -- flat config format, CommonJS usage, ignores, defineConfig
- [ESLint Migration Guide](https://eslint.org/docs/latest/use/configure/migration-guide) -- eslintrc to flat config migration patterns
- [Prettier Configuration docs](https://prettier.io/docs/configuration) -- .prettierrc format, options
- [Prettier Ignoring Code docs](https://prettier.io/docs/ignore) -- .prettierignore syntax and behavior
- [eslint-config-prettier GitHub](https://github.com/prettier/eslint-config-prettier) -- flat config integration via `/flat` import path

### Secondary (MEDIUM confidence)
- [ESLint Deprecating Formatting Rules](https://eslint.org/blog/2023/10/deprecating-formatting-rules/) -- formatting rules deprecated in v9
- [ESLint v10.0.0 released](https://eslint.org/blog/2026/02/eslint-v10.0.0-released/) -- v10 removes formatting rules; confirms v9 is appropriate for this project
- [globals npm package](https://www.npmjs.com/package/globals) -- Node.js globals definitions

### Tertiary (LOW confidence)
- None -- all findings verified against official sources

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- exact packages and versions verified against npm registry and official docs
- Architecture: HIGH -- flat config patterns verified against official ESLint 9 documentation
- Pitfalls: HIGH -- based on known Express.js + ESLint integration issues, verified with official docs
- Vulnerability inventory: MEDIUM -- vulnerability ESLint risk assessment is reasoned from rule definitions; actual behavior must be verified by running lint

**Research date:** 2026-03-21
**Valid until:** 2026-04-21 (stable tooling, no fast-moving changes expected)
