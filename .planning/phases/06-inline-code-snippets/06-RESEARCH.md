# Phase 6: Inline Code Snippets - Research

**Researched:** 2026-03-12
**Domain:** Syntax highlighting, code display, seed data enrichment, XSS prevention in EJS
**Confidence:** HIGH

## Summary

Phase 6 adds multi-line syntax-highlighted code snippets to the SCA finding detail page and a compact one-line code preview to student-lab cards. The implementation involves four coordinated changes: (1) expanding the seed data from single-line to 5-10 line code snippets with a new `snippet_start_line` field, (2) updating the JSON DB adapter to store the new field, (3) vendoring Prism.js locally with line-numbers and line-highlight plugins for syntax coloring and vulnerable-line callout, and (4) updating two EJS templates (finding-detail.ejs and student-lab.ejs).

The most critical technical detail is the interaction between Prism.js's `data-line` attribute (line-highlight plugin) and `data-start` attribute (line-numbers plugin). The `data-line` attribute uses **displayed** line numbers (absolute), while `data-line-offset` is the corresponding offset for line-highlight calculations. When using both plugins together, both `data-start` and `data-line-offset` must be set on the `<pre>` element, and their values differ by 1 (`data-start = snippet_start_line`, `data-line-offset = snippet_start_line - 1`). The `data-line` value should be the actual file line number (e.g., `finding.line_number`).

XSS is a real concern. Prism.js does NOT auto-escape HTML entities. Since EJS's `<%= %>` tag auto-escapes, using it inside the `<code>` block is the safe and correct approach. Using `<%- %>` (unescaped) would create an XSS vector. The prior STACK.md research incorrectly suggested switching to `<%- %>` -- this must NOT be done.

**Primary recommendation:** Vendor Prism.js v1.30.0 locally in `public/vendor/prism/`, use the One Dark theme from prism-themes, and rely on EJS `<%= %>` escaping for XSS safety. Use `data-line` with the absolute `finding.line_number` and set both `data-start` and `data-line-offset` for correct plugin interop.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Expand seedData.js to replace single-line `code_snippet` with multi-line (5-10 line) strings for all 12 findings
- Add a new `snippet_start_line` field to each finding so templates can calculate which line to highlight
- Use existing `line_number` field as the vulnerable line -- offset from `snippet_start_line` determines the highlight position
- Replace the old single-line `code_snippet` field (not keep both) -- card preview extracts the vulnerable line from the multi-line snippet at render time
- Always include 5-10 lines of surrounding context, even for comment-based or config-line findings
- Vendor Prism.js into `public/vendor/prism/` -- no CDN, no npm dependency, works offline in Codespaces
- Include three Prism components: core (`prism.js`), line-numbers plugin, line-highlight plugin
- One Dark theme (`#282c34` background, matches existing finding-detail code block)
- Use `language-javascript` for JS findings, `language-json` for package.json finding (#11)
- Line numbers rendered by Prism line-numbers plugin using `data-start` attribute set to `snippet_start_line`
- Vulnerable line highlighted by Prism line-highlight plugin using `data-line` attribute set to `line_number`
- Warm red/amber glow: `background: rgba(224, 108, 117, 0.15)`, `border-left: 3px solid #e06c75`
- No text label or tooltip -- just the visual highlight (background + left border)
- Show the vulnerable line itself (extracted from multi-line snippet using line_number - snippet_start_line offset) in student-lab cards
- Placed below the existing `file_path:line_number` line in each finding card
- Light inline style: monospace font, `#f1f3f5` background, `3px solid #e06c75` left border, text truncated with ellipsis
- Student-lab cards only -- not on instructor views (instructor.ejs, student-detail.ejs)

### Claude's Discretion
- DB schema changes needed for `snippet_start_line` (database.js executeSQL handler updates)
- Exact Prism.js file versions and download source
- How to handle XSS escaping of code snippets in EJS (angle brackets as text, not HTML)
- Template structure for Prism.js script/CSS loading (header partial vs page-specific)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SNIP-01 | Student can see 5-10 lines of relevant source code in the finding detail view | Seed data enrichment pattern (expand `code_snippet`), Prism.js `<pre><code>` block with `data-start` |
| SNIP-02 | Vulnerable line is visually called out within the code snippet (background highlight + left border) | Prism line-highlight plugin with `data-line` attribute + custom CSS override for warm red/amber glow |
| SNIP-03 | Code snippet displays line numbers corresponding to actual file line numbers | Prism line-numbers plugin with `data-start` attribute set to `snippet_start_line` |
| SNIP-04 | Code snippet has syntax coloring via Prism.js (keywords, strings, comments differentiated) | Vendored Prism.js v1.30.0 with One Dark theme from prism-themes, `language-javascript`/`language-json` classes |
| SNIP-05 | Student-lab card shows a compact one-line preview of the vulnerable code | EJS template logic to extract vulnerable line from multi-line snippet via offset calculation |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Prism.js core | 1.30.0 | Syntax highlighting engine | Latest stable (released 2025-03-10). Lightweight (~7 KB core). Industry standard for read-only code display. |
| Prism.js line-numbers plugin | 1.30.0 | Line number gutter | Built-in `data-start` attribute for custom starting line numbers -- maps directly to `snippet_start_line` |
| Prism.js line-highlight plugin | 1.30.0 | Vulnerable line callout | Built-in `data-line` attribute for highlighting specific lines -- maps directly to `finding.line_number` |
| prism-one-dark.css | 1.9.0 (prism-themes) | One Dark color theme | Background `#282c34` matches existing finding-detail code block. Colors: keywords #c678dd, strings #98c379, comments #5c6370 |
| prism-javascript component | 1.30.0 | JavaScript tokenization | Required for 11 of 12 SCA findings (JS source files) |
| prism-json component | 1.30.0 | JSON tokenization | Required for finding #11 (package.json) |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| EJS (existing) | 3.1.9 | Template escaping via `<%= %>` | XSS prevention -- use `<%= %>` (NOT `<%- %>`) for all code snippet output |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Vendored Prism.js | CDN Prism.js | CDN breaks offline Codespaces; user locked vendored approach |
| One Dark (prism-themes) | Okaidia (built-in) | Okaidia is close but One Dark is exact color match to existing `#282c34` blocks and user-specified colors |
| highlight.js | Prism.js | No native `data-line` for line highlighting; larger core with auto-detect overhead |

**Installation:**
No npm install. Download files from prismjs.com/download.html and cdnjs, place in `public/vendor/prism/`.

## Architecture Patterns

### Recommended File Structure for Vendored Assets
```
public/
  vendor/
    prism/
      prism.js              # Core + JS + JSON components (minified bundle from download page)
      prism-line-numbers.js  # Line numbers plugin
      prism-line-highlight.js # Line highlight plugin
      prism-one-dark.css     # Theme from prism-themes repo
      prism-line-numbers.css # Line numbers plugin CSS
      prism-line-highlight.css # Line highlight plugin CSS
```

Alternative (simpler, fewer files):
```
public/
  vendor/
    prism/
      prism.min.js           # All-in-one: core + JS + JSON + line-numbers + line-highlight
      prism.css              # Combined: one-dark theme + plugin CSS
```

**Recommendation:** Use the simpler approach -- download a single custom bundle from prismjs.com/download.html that includes core + JavaScript + JSON + line-numbers + line-highlight, then combine CSS manually. Fewer files = fewer script tags = simpler template. The One Dark theme CSS must be sourced separately from prism-themes since it is not a built-in theme.

### Pattern 1: Seed Data Schema Extension
**What:** Add `snippet_start_line` to the SCA findings INSERT statement and JSON DB adapter
**When to use:** When a finding needs context about where its multi-line snippet begins in the source file

The INSERT statement changes from 12 columns to 13:
```javascript
// seedData.js - INSERT statement
const scaStmt = db.prepare(`
  INSERT INTO sca_findings (id, title, file_path, line_number, code_snippet, snippet_start_line, category, cwe, severity, description, tool, remediation, false_positive_reason)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
```

The JSON DB adapter (database.js) `INTO sca_findings` handler adds the new field:
```javascript
// database.js - executeSQL INSERT handler for sca_findings
if (sql.includes('INTO sca_findings')) {
  const finding = {
    id: params[0],
    title: params[1],
    file_path: params[2],
    line_number: params[3],
    code_snippet: params[4],
    snippet_start_line: params[5],  // NEW
    category: params[6],            // shifted from params[5]
    cwe: params[7],                 // shifted from params[6]
    severity: params[8],            // shifted from params[7]
    description: params[9],         // shifted from params[8]
    tool: params[10],               // shifted from params[9]
    remediation: params[11],        // shifted from params[10]
    false_positive_reason: params[12] || null,  // shifted from params[11]
    created_at: new Date().toISOString()
  };
  // ...
}
```

### Pattern 2: Prism.js Code Block in finding-detail.ejs
**What:** Replace the existing `<pre>` block with Prism.js-powered syntax-highlighted block
**When to use:** Finding detail page

```html
<!-- finding-detail.ejs: Replace existing code snippet block (lines 52-53) -->
<h3 style="margin-bottom:0.5rem;"><%= t('sca.findingDetail.codeSnippet') %></h3>
<pre class="line-numbers"
     data-start="<%= finding.snippet_start_line %>"
     data-line="<%= finding.line_number %>"
     data-line-offset="<%= finding.snippet_start_line - 1 %>"
     style="border-radius:6px; margin-bottom:1rem;"><code class="language-<%= finding.id === 11 ? 'json' : 'javascript' %>"><%= finding.code_snippet %></code></pre>
```

Key points:
- `data-start` tells line-numbers plugin to start numbering at `snippet_start_line`
- `data-line` tells line-highlight plugin which line to highlight (absolute file line number)
- `data-line-offset` tells line-highlight plugin the offset for position calculation (must be `snippet_start_line - 1` -- one less than `data-start`)
- `<%= %>` auto-escapes `<`, `>`, `&` preventing XSS
- `language-json` for finding #11 (package.json), `language-javascript` for all others

### Pattern 3: Card Preview Line Extraction in student-lab.ejs
**What:** Extract and display the vulnerable line from the multi-line snippet
**When to use:** Student-lab finding cards

```html
<!-- student-lab.ejs: Add below the file_path:line_number display -->
<%
  const snippetLines = f.code_snippet.split('\n');
  const vulnLineIndex = f.line_number - f.snippet_start_line;
  const vulnLine = snippetLines[vulnLineIndex] || snippetLines[0];
%>
<div style="font-family:monospace; font-size:0.8rem; padding:4px 8px; background:#f1f3f5; border-left:3px solid #e06c75; border-radius:3px; margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#333;">
  <%= vulnLine.trim() %>
</div>
```

### Pattern 4: Custom CSS Override for Vulnerable Line
**What:** Override Prism line-highlight default styling with the user-specified warm red/amber glow
**When to use:** On pages that include Prism.js

```css
/* Override Prism line-highlight default yellow with warm red/amber */
.line-highlight {
  background: rgba(224, 108, 117, 0.15) !important;
  border-left: 3px solid #e06c75;
}
```

This can be placed as a `<style>` block in finding-detail.ejs (page-specific) or as an inline override in the combined Prism CSS file.

### Anti-Patterns to Avoid
- **Using `<%- %>` (unescaped) for code snippets:** Creates XSS vulnerability. The prior STACK.md research incorrectly suggested this. Use `<%= %>` which auto-escapes `<`, `>`, `&` to HTML entities. Prism.js works correctly with HTML entities inside `<code>` blocks -- it tokenizes the text content, not the HTML.
- **Translating code_snippet via localize():** Code is actual source code and must NOT be translated. The existing `localize()` function only overlays `title`, `description`, `remediation` -- leave it unchanged.
- **Loading Prism.js on every page via header/footer:** The finding-detail.ejs is the only page that uses syntax highlighting. Loading Prism.js globally wastes bandwidth on every page load (dashboard, classes, admin, etc.). Use page-specific loading instead.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Syntax highlighting | Custom tokenizer with regex + spans | Prism.js | JavaScript tokenization has dozens of edge cases (template literals, regex, comments in strings). Prism.js handles them all. |
| Line numbers | Manual `<span>` per line with counter | Prism line-numbers plugin | Plugin handles `data-start` offset, CSS alignment, and line wrapping correctly |
| Line highlighting | CSS `:nth-child()` targeting | Prism line-highlight plugin | Plugin handles absolute positioning, offset math, and CSS overlay generation |
| HTML escaping in code | Custom escape function | EJS `<%= %>` tag | EJS's built-in escaping handles `<`, `>`, `&`, `"`, `'` correctly. No custom code needed. |

**Key insight:** Prism.js's line-numbers and line-highlight plugins are specifically designed for the exact use case of showing file excerpts with custom starting line numbers and highlighted lines. Hand-rolling any of this is high effort with many edge cases.

## Common Pitfalls

### Pitfall 1: XSS via Unescaped Code Output
**What goes wrong:** Using `<%- finding.code_snippet %>` (unescaped EJS) allows `<script>` tags or HTML in code snippets to execute in the browser.
**Why it happens:** Developers assume Prism.js needs raw HTML or that code snippets are "trusted" seed data. But seed data could be modified, or the pattern could be copied to a page with user-generated content.
**How to avoid:** Always use `<%= finding.code_snippet %>` (escaped). Prism.js tokenizes text content from the DOM, not HTML source. The `&lt;` entities in the DOM are seen as `<` by Prism.js's tokenizer.
**Warning signs:** Code snippets render as HTML instead of displaying as text. `<script>` tags disappear from display.

### Pitfall 2: data-line-offset / data-start Off-By-One
**What goes wrong:** The vulnerable line highlight appears on the wrong line (one line above or below).
**Why it happens:** `data-start` and `data-line-offset` differ by 1. `data-start` is the first displayed line number. `data-line-offset` is the count subtracted from `data-line` to find the physical line position. If `snippet_start_line` is 40, then `data-start="40"` but `data-line-offset="39"`.
**How to avoid:** Always set both attributes when using both plugins together. Formula: `data-start = snippet_start_line`, `data-line-offset = snippet_start_line - 1`.
**Warning signs:** Highlight bar visually covers the wrong line of code. Test with at least 3 different findings that have different `snippet_start_line` values.

### Pitfall 3: One Dark Theme Not a Built-In Prism Theme
**What goes wrong:** Downloading from prismjs.com/download.html and selecting a theme -- One Dark is not in the list.
**Why it happens:** prismjs.com includes only 8 built-in themes (Default, Dark, Funky, Okaidia, Twilight, Coy, Solarized Light, Tomorrow Night). One Dark is in the separate `prism-themes` package.
**How to avoid:** Source the One Dark CSS from the prism-themes repository (https://github.com/PrismJS/prism-themes/blob/master/themes/prism-one-dark.css) or cdnjs (https://cdnjs.cloudflare.com/ajax/libs/prism-themes/1.9.0/prism-one-dark.min.css). Download and vendor it alongside the Prism core files.
**Warning signs:** Code block has wrong background color or Okaidia colors instead of One Dark colors.

### Pitfall 4: Prism.js Not Running on Dynamic Content
**What goes wrong:** Code block appears with correct classes but no syntax highlighting.
**Why it happens:** Prism.js runs `Prism.highlightAll()` on DOMContentLoaded. If the code block is injected after that (e.g., via AJAX), it won't be processed.
**How to avoid:** For finding-detail.ejs, the content is server-rendered (not AJAX), so this is not an issue. The student-lab.ejs inline forms toggle visibility with `display:none/block` -- the code preview is a plain `<div>` (not Prism-processed), so this is also fine. No action needed, but be aware if future changes add AJAX-loaded code blocks.
**Warning signs:** Classes are present but text is uncolored.

### Pitfall 5: Seed Data Multi-line Strings with Template Literals
**What goes wrong:** JavaScript template literals (backticks) inside code snippet strings cause syntax errors or unexpected interpolation.
**Why it happens:** If using template literal syntax for multi-line strings in seedData.js, backticks inside the snippet content conflict with the outer template literal.
**How to avoid:** Use regular strings with `\n` for line breaks, or escape backticks inside the snippet with `\``. Regular string concatenation is safest for seed data.
**Warning signs:** Node.js syntax errors when seedData.js loads. Template literal `${...}` expressions being evaluated instead of stored as literal text.

## Code Examples

### Example 1: Full Prism.js Block for Finding #1 (Hardcoded Session Secret)
```html
<!-- Snippet starts at line 42, vulnerable line is 45 -->
<pre class="line-numbers"
     data-start="42"
     data-line="45"
     data-line-offset="41"
     style="border-radius:6px; margin-bottom:1rem;"><code class="language-javascript"><%= finding.code_snippet %></code></pre>
```

Where `finding.code_snippet` contains:
```
// Session configuration -- set secure cookie at startup if HTTPS is enabled
const startupSecuritySettings = getSecuritySettings();
app.use(session({
  secret: 'university-class-management-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    secure: !!startupSecuritySettings.https_enabled
  }
}));
```

### Example 2: Seed Data Array Entry with New Field
```javascript
// Finding #1: Hardcoded Session Secret
[1, 'Hardcoded Session Secret', 'server.js', 45,
  '// Session configuration -- set secure cookie at startup if HTTPS is enabled\n' +
  'const startupSecuritySettings = getSecuritySettings();\n' +
  'app.use(session({\n' +
  '  secret: \'university-class-management-secret-key-change-in-production\',\n' +
  '  resave: false,\n' +
  '  saveUninitialized: false,\n' +
  '  cookie: {\n' +
  '    maxAge: 1000 * 60 * 60 * 24, // 24 hours\n' +
  '    httpOnly: true,\n' +
  '    secure: !!startupSecuritySettings.https_enabled\n' +
  '  }\n' +
  '}));',
  42,  // snippet_start_line (NEW field)
  'Hardcoded Credentials', 'CWE-798', 'Critical',
  'The Express session secret is hardcoded in source code...',
  'Semgrep', 'Move the secret to an environment variable...', null],
```

### Example 3: Student-Lab Card Preview
```html
<div style="font-size:0.85rem; color:#666; margin-top:2px;">
  <code><%= f.file_path %>:<%= f.line_number %></code>
</div>
<%
  const snippetLines = f.code_snippet.split('\n');
  const vulnIdx = f.line_number - f.snippet_start_line;
  const vulnLine = (snippetLines[vulnIdx] || snippetLines[0]).trim();
%>
<div style="font-family:monospace; font-size:0.8rem; padding:4px 8px; background:#f1f3f5; border-left:3px solid #e06c75; border-radius:3px; margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#333;">
  <%= vulnLine %>
</div>
```

### Example 4: Prism.js Loading (Page-Specific in finding-detail.ejs)
```html
<!-- Before closing </body> or at end of finding-detail.ejs before footer include -->
<link rel="stylesheet" href="/vendor/prism/prism-one-dark.css">
<link rel="stylesheet" href="/vendor/prism/prism-line-numbers.css">
<link rel="stylesheet" href="/vendor/prism/prism-line-highlight.css">
<style>
  /* Override Prism line-highlight default with warm red/amber glow */
  .line-highlight {
    background: rgba(224, 108, 117, 0.15) !important;
    border-left: 3px solid #e06c75;
  }
</style>
<script src="/vendor/prism/prism.min.js"></script>
```

Note: CSS `<link>` tags should be in the `<head>` for proper rendering. Since the header partial is shared, two options:
1. Add all Prism CSS to header.ejs (loads on every page, ~5 KB wasted on non-SCA pages)
2. Use a `locals.needsPrism` flag from the route, conditionally include in header.ejs

**Recommendation:** Option 2 is cleaner. Pass `needsPrism: true` from the finding-detail route, and wrap Prism CSS includes in `<% if (locals.needsPrism) { %>` in header.ejs. Scripts go before `</body>` in footer.ejs with the same conditional.

### Example 5: Conditional Prism Loading in Header/Footer
```html
<!-- header.ejs: inside <head>, after existing <style> block -->
<% if (locals.needsPrism) { %>
<link rel="stylesheet" href="/vendor/prism/prism-one-dark.css">
<link rel="stylesheet" href="/vendor/prism/prism-line-numbers.css">
<link rel="stylesheet" href="/vendor/prism/prism-line-highlight.css">
<style>
  .line-highlight {
    background: rgba(224, 108, 117, 0.15) !important;
    border-left: 3px solid #e06c75;
  }
</style>
<% } %>
```

```html
<!-- footer.ejs: before </body> -->
<% if (locals.needsPrism) { %>
<script src="/vendor/prism/prism.min.js"></script>
<% } %>
```

```javascript
// routes/sca.js: finding detail route
res.render('sca/finding-detail', {
  // ...existing locals...
  needsPrism: true
});
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Prism.js v1.29.0 | v1.30.0 | 2025-03-10 | Minor fix (script tag validation). No API changes. Prior research referenced v1.29.0 but v1.30.0 is current. |
| CDN loading | Vendored local files | User decision | Enables offline Codespaces use. No network dependency. |
| prism-okaidia (built-in) | prism-one-dark (prism-themes) | User decision | Exact `#282c34` match. Must source from prism-themes repo, not Prism download page. |

**Deprecated/outdated:**
- The prior STACK.md research recommended CDN loading. User has overridden this with vendored local files.
- The prior STACK.md suggested using `<%- %>` (unescaped) for code output. This is INCORRECT and creates XSS risk. Use `<%= %>`.
- The prior ARCHITECTURE.md research proposed CSS-only syntax highlighting. User has overridden this with Prism.js.

## Discretion Recommendations

The following items were left to Claude's discretion in CONTEXT.md. Here are the research-backed recommendations:

### 1. DB Schema Changes for `snippet_start_line`
**Recommendation:** Add `snippet_start_line` as `params[5]` in the `INTO sca_findings` handler in database.js. Shift all subsequent params indices by 1. Also update the INSERT SQL in seedData.js to include the new column.

This is the minimal change. No migration needed -- the JSON DB is re-seeded from seedData.js on each fresh start. Existing data.json files get re-created when the app detects an empty/missing database.

### 2. Exact Prism.js File Versions and Download Source
**Recommendation:**
- Prism.js core v1.30.0 (latest stable, released 2025-03-10)
- Use the custom download page at prismjs.com/download.html to generate a single JS bundle containing: core + JavaScript + JSON languages + line-numbers plugin + line-highlight plugin
- Select "Minified version" for smaller file size
- One Dark theme CSS: download from cdnjs at `https://cdnjs.cloudflare.com/ajax/libs/prism-themes/1.9.0/prism-one-dark.min.css`
- Plugin CSS files: download from cdnjs at `https://cdnjs.cloudflare.com/ajax/libs/prism/1.30.0/plugins/line-numbers/prism-line-numbers.min.css` and `https://cdnjs.cloudflare.com/ajax/libs/prism/1.30.0/plugins/line-highlight/prism-line-highlight.min.css`

Note: If v1.30.0 is not yet on cdnjs, use v1.29.0 for the plugin CSS files (plugins have not changed between versions).

### 3. XSS Escaping Approach
**Recommendation:** Use `<%= %>` (escaped EJS output) for ALL code snippet rendering. Do NOT use `<%- %>`.

**Why this works:** EJS `<%= %>` converts `<` to `&lt;`, `>` to `&gt;`, `&` to `&amp;`. When the browser renders the page, the `<code>` element's `textContent` property returns the unescaped characters. Prism.js reads `textContent` (not `innerHTML`), so it receives the original code with proper `<`, `>`, `&` characters and tokenizes them correctly.

**Verification test:** After implementation, view page source and confirm `<` appears as `&lt;` in the HTML. Then confirm the rendered code block displays `<` correctly (not the entity).

### 4. Template Structure for Prism Loading
**Recommendation:** Conditional loading using a `locals.needsPrism` flag.

- Route passes `needsPrism: true` to finding-detail.ejs render call
- header.ejs conditionally includes Prism CSS when `locals.needsPrism` is truthy
- footer.ejs conditionally includes Prism JS when `locals.needsPrism` is truthy
- All other pages (dashboard, classes, admin, student-lab, etc.) load zero Prism assets

This approach follows the existing pattern in the codebase where routes pass page-specific locals (`title`, `currentPath`, etc.).

## Open Questions

1. **Prism.js v1.30.0 on download page vs cdnjs**
   - What we know: v1.30.0 was released 2025-03-10. cdnjs typically mirrors within days.
   - What's unclear: Whether prismjs.com/download.html has been updated to v1.30.0 yet.
   - Recommendation: Check the download page during implementation. If it still shows v1.29.0, use v1.29.0 for the JS bundle -- the difference is a minor script-tag validation fix, not relevant to our use case.

2. **Seed data snippet accuracy**
   - What we know: The 12 findings reference real files (server.js, routes/auth.js, etc.) at specific line numbers.
   - What's unclear: Whether the actual code at those line numbers has shifted since v1.0 due to any modifications.
   - Recommendation: During implementation, verify each snippet against the actual source file. The existing `line_number` values in seed data should be confirmed against the current codebase.

## Sources

### Primary (HIGH confidence)
- Prism.js official download page: https://prismjs.com/download.html -- themes, languages, plugins available
- Prism.js line-highlight plugin docs: https://prismjs.com/plugins/line-highlight/ -- `data-line`, `data-line-offset` attributes
- Prism.js line-numbers plugin docs: https://prismjs.com/plugins/line-numbers/ -- `data-start` attribute
- Prism.js GitHub releases: https://github.com/PrismJS/prism/releases -- v1.30.0 confirmed as latest
- Prism.js line-highlight source code: confirmed `data-line` uses absolute line numbers, `data-line-offset` subtracted for positioning
- PrismJS/prism-themes repo: https://github.com/PrismJS/prism-themes -- One Dark theme CSS
- cdnjs prism-themes: https://cdnjs.com/libraries/prism-themes -- version 1.9.0 with One Dark
- GitHub issue #2714: https://github.com/PrismJS/prism/issues/2714 -- data-start vs data-line-offset off-by-one documentation

### Secondary (MEDIUM confidence)
- WebSearch verified: Prism.js does NOT auto-escape HTML entities. Developers must pre-escape. Confirmed by multiple sources including official Prism.js issue tracker and CVE history.
- EJS escaping behavior: `<%= %>` escapes `<`, `>`, `&`, `"`, `'` -- standard EJS behavior confirmed by existing codebase usage patterns.

### Tertiary (LOW confidence)
- None. All critical findings verified against multiple sources.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- Prism.js version, plugins, and theme verified against official sources
- Architecture: HIGH -- data-line/data-start interaction confirmed by source code analysis; EJS escaping verified against existing codebase patterns
- Pitfalls: HIGH -- XSS concern verified by CVE history; off-by-one issue confirmed by GitHub issue #2714; One Dark availability confirmed

**Research date:** 2026-03-12
**Valid until:** 2026-04-12 (30 days -- Prism.js is very stable, last 4 releases span 14 months)
