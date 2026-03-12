# Technology Stack -- v1.1 Additions

**Project:** HEC Montreal SCA Lab -- v1.1 Polish & Pedagogy
**Researched:** 2026-03-12
**Confidence:** HIGH -- recommendations verified against codebase analysis, CDN availability, and project constraints

## Scope

This document covers ONLY the new technologies needed for v1.1 features:
1. Syntax-highlighted inline code snippets with vulnerable line callout
2. Code quality tooling (ESLint + Prettier)

The existing validated stack (Express 4.18, EJS 3.1, Node.js 22, JSON DB, i18n infrastructure) is NOT re-documented here. See prior v1.0 STACK.md for that context.

## Recommended Stack Additions

### Syntax Highlighting: Prism.js via CDN (NO npm dependency)

| Item | Value | Notes |
|------|-------|-------|
| Library | Prism.js | CDN-loaded, not added to package.json |
| Version | 1.29.0 | Latest stable on cdnjs |
| Core JS | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js` | ~2 KB core |
| Theme CSS | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css` | Dark theme matching existing `#282c34` code blocks |
| Language: JS | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js` | All 12 SCA snippets are JavaScript |
| Language: JSON | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js` | Finding #11 references package.json |
| Plugin: Line Highlight | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-highlight/prism-line-highlight.min.js` | Built-in `data-line` attribute for vulnerable line callout |
| Plugin: Line Highlight CSS | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-highlight/prism-line-highlight.min.css` | Styling for highlighted line |
| Plugin: Line Numbers | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.js` | Shows line numbers in gutter |
| Plugin: Line Numbers CSS | `https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.css` | Gutter styling |

**Why Prism.js over highlight.js:**
- Prism.js has a native `data-line` attribute for highlighting specific lines. This maps directly to the existing `finding.line_number` field in the database. With highlight.js, you need a separate plugin (highlightjs-line-numbers.js) plus custom CSS for line highlighting.
- Prism.js core is ~2 KB vs highlight.js at ~40 KB (with auto-detection). Since we know all snippets are JavaScript, we do not need auto-detection.
- Prism.js line-numbers plugin uses `data-start` attribute to set the starting line number, so we can show `line 44` instead of `line 1` -- matching the actual file location.

**Why CDN and not npm:**
- The PROJECT.md constraint says "No new dependencies -- Express/EJS/vanilla JS." A CDN `<script>` tag is not a dependency -- it does not change package.json, does not affect `npm install`, and does not increase the Codespaces boot time.
- Codespaces runs in a browser with internet access. CDN assets load from the browser, not from the Node.js server.
- Total CDN payload: ~15 KB across all files (core + theme + 2 languages + 2 plugins). Negligible.

### Code Quality Tooling: ESLint 9 + Prettier 3 (dev dependencies)

| Technology | Version | Purpose | Why This Version |
|------------|---------|---------|------------------|
| eslint | ^9.0.0 | Linting: catch bugs, enforce patterns | Latest major with flat config as default. Node 22 compatible. |
| prettier | ^3.4.0 | Formatting: consistent code style | Stable, widely used, no breaking changes expected |
| eslint-config-prettier | ^10.0.0 | Disables ESLint rules that conflict with Prettier | Required to prevent ESLint/Prettier conflicts |
| globals | ^15.0.0 | Provides Node.js/browser global definitions for ESLint flat config | Replaces `env: { node: true }` from legacy config |

**Why these are acceptable as dependencies:**
- They are `devDependencies`, not `dependencies`. They do not ship to production, do not run during `npm start`, and do not affect students.
- The devcontainer.json already includes `dbaeumer.vscode-eslint` and `esbenp.prettier-vscode` VS Code extensions -- these extensions expect config files and packages to exist. Adding the packages completes an already-intended setup.
- "AI-driven code quality optimization" is an explicit v1.1 milestone goal. You cannot optimize code quality without tooling to enforce it.

**Why NOT TypeScript, why NOT additional plugins:**
- The codebase is ~11,800 LOC of vanilla JavaScript + EJS. Adding TypeScript is a rewrite, not an optimization.
- No React/Vue plugins needed -- this is server-rendered EJS.
- No import/export ordering plugins needed -- the codebase uses CommonJS `require()`.

## Integration Points

### Prism.js Integration in finding-detail.ejs

Current code snippet rendering (line 53 of `views/sca/finding-detail.ejs`):
```html
<pre style="background:#282c34; color:#abb2bf; padding:1rem; border-radius:6px; overflow-x:auto; font-size:0.9rem; margin-bottom:1rem;"><%= finding.code_snippet %></pre>
```

Target rendering with Prism.js:
```html
<pre class="line-numbers" data-start="<%= finding.snippet_start_line %>" data-line="<%= finding.vulnerable_line_offset %>"><code class="language-javascript"><%- finding.code_snippet %></code></pre>
```

Key changes:
1. Wrap content in `<code class="language-javascript">` inside the `<pre>`
2. Add `data-start` to show real line numbers from the file
3. Add `data-line` to highlight the vulnerable line (relative offset within snippet)
4. Switch from `<%= %>` (escaped) to `<%- %>` (unescaped) since code snippets contain `<`, `>`, and `&` that Prism needs as-is -- BUT the snippets come from seed data (trusted), not user input
5. Remove inline styles (Prism theme handles colors)

### Seed Data Changes Required

The current `code_snippet` field stores a single line of code per finding. For the inline snippet feature, this needs to expand to 5-10 lines with context. Two new fields are needed in the seed data:

| Field | Type | Purpose | Example |
|-------|------|---------|---------|
| `code_snippet` | string | Multi-line snippet (~5-10 lines surrounding the vulnerable code) | Full function context |
| `snippet_start_line` | integer | The line number in the real file where the snippet begins | `40` |
| `vulnerable_line_offset` | integer | Which line within the snippet is vulnerable (1-indexed, for `data-line`) | `5` |

The existing `line_number` field remains as-is (used in the location display). The `snippet_start_line` can be derived from `line_number - vulnerable_line_offset + 1`.

**Alternative (simpler):** Keep one field. Store multi-line snippets in `code_snippet`. Use `line_number` for the `data-start` calculation. Add only `vulnerable_line_in_snippet` (1-indexed offset). This avoids a schema migration.

### CDN Tags in header.ejs

Add to `views/partials/header.ejs` inside `<head>`:
```html
<!-- Prism.js syntax highlighting (CDN, no npm dependency) -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-highlight/prism-line-highlight.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.css">
```

Add before `</body>` in `views/partials/footer.ejs`:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-highlight/prism-line-highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/line-numbers/prism-line-numbers.min.js"></script>
```

**Performance note:** These CDN files load on every page, not just finding-detail. At ~15 KB total (gzipped), this is acceptable. If optimization is desired later, conditionally include them only on finding-detail.ejs using a `locals.needsPrism` flag from the route.

### ESLint Flat Config File

Create `eslint.config.js` at project root (CommonJS -- project has no `"type": "module"` in package.json):

```javascript
const globals = require('globals');
const eslintConfigPrettier = require('eslint-config-prettier');

module.exports = [
  {
    files: ['**/*.js'],
    ignores: ['node_modules/**'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      }
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-console': 'off',        // Console logging is intentional in this app
      'eqeqeq': ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'warn',
    }
  },
  eslintConfigPrettier,  // Must be last: disables formatting rules
];
```

### Prettier Config File

Create `.prettierrc` at project root:

```json
{
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 120,
  "tabWidth": 2,
  "semi": true
}
```

**Why these settings:**
- `singleQuote: true` -- matches existing codebase convention (verified by reading routes/sca.js, server.js)
- `trailingComma: "es5"` -- safe for Node.js, helps with git diffs
- `printWidth: 120` -- the EJS templates have long lines; 80 would reformat aggressively and produce noisy diffs
- `semi: true` -- matches existing codebase convention

### package.json Script Additions

```json
{
  "scripts": {
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "format": "prettier --write \"**/*.{js,json,ejs}\"",
    "format:check": "prettier --check \"**/*.{js,json,ejs}\""
  }
}
```

## What NOT to Add

| Technology | Why NOT |
|------------|---------|
| highlight.js (npm) | CDN Prism.js is lighter, has better line highlighting, avoids npm dependency |
| highlight.js (CDN) | No built-in `data-line` attribute -- requires separate plugin + custom CSS for the vulnerable-line callout feature |
| CodeMirror | Full editor library (~300 KB). We need read-only display, not editing. Massive overkill. |
| Monaco Editor | VS Code's editor (~5 MB). Absurdly heavy for displaying 5-10 line snippets. |
| Shiki | Requires Node.js runtime for TextMate grammar parsing. Cannot run in browser from CDN without bundling. |
| TypeScript | Rewrite of ~11,800 LOC for no classroom benefit. Students never see the server code. |
| eslint-plugin-security | Interesting but ironic -- the app intentionally has vulnerabilities for teaching. Would flag the seed data. |
| husky / lint-staged | Git hooks are useful for team projects. This is a solo instructor project. Run `npm run lint` manually. |
| Tailwind CSS | The codebase uses inline styles consistently. Adding a CSS framework would require touching every template. |
| Any CSS framework (Bootstrap, etc.) | Same reason. Inline styles are the convention. Adding a framework is a rewrite. |

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Syntax highlighting | Prism.js via CDN | highlight.js via CDN | No native line-highlight attribute; larger core; auto-detect unneeded |
| Syntax highlighting | Prism.js via CDN | Pre-tokenized HTML in seed data | Fragile, tedious for 12 findings, unmaintainable, no theme support |
| Syntax highlighting | Prism.js via CDN | CSS-only approaches (ft-syntax-highlight, cssyn) | Require manually wrapping every token in `<span>` classes. Impractical for real code. |
| Vulnerable line callout | Prism line-highlight plugin | Custom CSS `:nth-child` targeting | Brittle, no `data-line` declarative API, breaks when snippet length changes |
| Code quality | ESLint 9 flat config | ESLint 8 legacy config | ESLint 9 is current, flat config is simpler, legacy config is deprecated |
| Formatting | Prettier 3 | ESLint formatting rules | Prettier is faster, more consistent, and the devcontainer already expects it |
| Formatting | Prettier 3 | Manual formatting | 11,800 LOC -- manual formatting is not "AI-driven code quality optimization" |

## Installation

### CDN (Prism.js) -- No installation needed

Add `<link>` and `<script>` tags to header.ejs and footer.ejs as described in Integration Points above. Zero npm commands.

### Dev Dependencies (Code Quality)

```bash
npm install -D eslint@^9 prettier@^3 eslint-config-prettier@^10 globals@^15
```

This adds ~8 MB to `node_modules` (dev only). Does not affect production runtime or Codespaces boot time since `npm start` does not invoke these tools.

## Confidence Assessment

| Decision | Confidence | Basis |
|----------|------------|-------|
| Prism.js via CDN for syntax highlighting | HIGH | Direct codebase analysis (existing `<pre>` block, dark theme, line_number field); Prism.js is the industry standard for read-only code display; CDN avoids dependency constraint |
| Prism okaidia theme | HIGH | Visual match to existing `#282c34` background in finding-detail.ejs |
| Line-highlight plugin for vulnerable line | HIGH | Direct match to requirement ("vulnerable line called out"); `data-line` attribute maps to `finding.line_number` |
| ESLint 9 + Prettier 3 as devDependencies | HIGH | devcontainer.json already declares VS Code extensions for both; v1.1 milestone explicitly includes code quality optimization |
| Flat config format for ESLint | HIGH | ESLint 9 default; project uses CommonJS (`require()`); no `"type": "module"` in package.json |
| printWidth: 120 for Prettier | MEDIUM | Based on reading existing code style (long EJS lines), but may need adjustment during formatting pass |

## Sources

- Prism.js official site: https://prismjs.com/
- Prism.js line-highlight plugin: https://prismjs.com/plugins/line-highlight/
- Prism.js line-numbers plugin: https://prismjs.com/plugins/line-numbers/
- Prism.js cdnjs: https://cdnjs.com/libraries/prism
- highlight.js vs Prism comparison: https://github.com/highlightjs/highlight.js/issues/3625
- ESLint flat config docs: https://eslint.org/docs/latest/use/configure/configuration-files
- Prettier docs: https://prettier.io/docs/en/options.html
- Direct codebase analysis: `views/sca/finding-detail.ejs`, `utils/seedData.js`, `routes/sca.js`, `package.json`, `.devcontainer/devcontainer.json`
