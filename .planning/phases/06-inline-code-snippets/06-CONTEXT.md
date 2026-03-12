# Phase 6: Inline Code Snippets - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Students see 5-10 lines of real, syntax-highlighted source code in the finding detail view, with the vulnerable line visually called out. The student-lab overview page shows a compact one-line code preview per finding. This phase covers SNIP-01 through SNIP-05.

</domain>

<decisions>
## Implementation Decisions

### Snippet data source
- Expand seedData.js to replace single-line `code_snippet` with multi-line (5-10 line) strings for all 12 findings
- Add a new `snippet_start_line` field to each finding so templates can calculate which line to highlight
- Use existing `line_number` field as the vulnerable line — offset from `snippet_start_line` determines the highlight position
- Replace the old single-line `code_snippet` field (not keep both) — card preview extracts the vulnerable line from the multi-line snippet at render time
- Always include 5-10 lines of surrounding context, even for comment-based or config-line findings (e.g., finding #7 "No CSRF middleware" still shows the middleware setup block)

### Syntax highlighting
- Vendor Prism.js into `public/vendor/prism/` — no CDN, no npm dependency, works offline in Codespaces
- Include three Prism components: core (`prism.js`), line-numbers plugin, line-highlight plugin
- One Dark theme (`#282c34` background, matches existing finding-detail code block)
- Use `language-javascript` for JS findings, `language-json` for package.json finding (#11)
- Line numbers rendered by Prism line-numbers plugin using `data-start` attribute set to `snippet_start_line`
- Vulnerable line highlighted by Prism line-highlight plugin using `data-line` attribute set to `line_number`

### Vulnerable line callout
- Warm red/amber glow: `background: rgba(224, 108, 117, 0.15)`, `border-left: 3px solid #e06c75`
- No text label or tooltip — just the visual highlight (background + left border)
- Students already see the line number above the snippet in the location section

### Card preview in student-lab
- Show the vulnerable line itself (extracted from multi-line snippet using line_number - snippet_start_line offset)
- Placed below the existing `file_path:line_number` line in each finding card
- Light inline style: monospace font, `#f1f3f5` background, `3px solid #e06c75` left border, text truncated with ellipsis
- Student-lab cards only — not on instructor views (instructor.ejs, student-detail.ejs)

### Claude's Discretion
- DB schema changes needed for `snippet_start_line` (database.js executeSQL handler updates)
- Exact Prism.js file versions and download source
- How to handle XSS escaping of code snippets in EJS (angle brackets as text, not HTML)
- Template structure for Prism.js script/CSS loading (header partial vs page-specific)

</decisions>

<specifics>
## Specific Ideas

- One Dark theme colors: keywords #c678dd (purple), strings #98c379 (green), comments #5c6370 (gray), functions #61afef (blue), numbers #d19a66 (orange)
- Card preview styling: `font-size: 0.8rem`, `padding: 4px 8px`, `border-radius: 3px`, `overflow: hidden; text-overflow: ellipsis; white-space: nowrap`
- Prism.js `data-start` attribute for custom starting line numbers — built into the line-numbers plugin

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `finding-detail.ejs:52-53`: Existing code snippet `<pre>` block with `#282c34` background — will be replaced with Prism.js block
- `student-lab.ejs:97-100`: Existing inline review form code snippet display — will be updated
- `routes/sca.js`: Finding detail route (line 139) and student lab route (line 51) already pass finding data including `code_snippet` to templates

### Established Patterns
- Inline styles throughout EJS templates (no external CSS files except potential shared partials)
- `localize()` function overlays title/description/remediation but passes code fields through unchanged
- `public/` serves static files via `express.static()` — ready for `vendor/prism/` directory

### Integration Points
- `utils/seedData.js` line 174-253: SCA findings INSERT — schema change needed (add `snippet_start_line`, expand `code_snippet`)
- `config/database.js`: executeSQL handler for `sca_findings` table — may need schema update for new column
- `views/partials/header.ejs`: Could load Prism.js CSS globally, or load per-page
- `views/sca/finding-detail.ejs`: Primary template for multi-line snippet with highlighting
- `views/sca/student-lab.ejs`: Card template for one-line preview

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-inline-code-snippets*
*Context gathered: 2026-03-12*
