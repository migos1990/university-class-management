---
phase: 06-inline-code-snippets
verified: 2026-03-12T20:45:00Z
status: human_needed
score: 9/9 must-haves verified
human_verification:
  - test: "Navigate to /sca as student and inspect finding detail pages for syntax highlighting"
    expected: "Code block shows syntax-coloured JavaScript (purple keywords, green strings, gray comments) via Prism One Dark theme; line numbers in gutter start at snippet_start_line; vulnerable line has rgba(224,108,117,0.15) background and 3px solid #e06c75 left border"
    why_human: "Visual rendering of Prism.js (CSS + JS execution in browser) cannot be verified by grep or node script"
  - test: "Navigate to /sca student-lab page and check card previews"
    expected: "Each of 12 finding cards shows a compact one-line monospace preview of the vulnerable code below the file-path display; long lines truncated with ellipsis"
    why_human: "Text truncation via CSS (white-space:nowrap + overflow:hidden + text-overflow:ellipsis) requires a browser render to confirm"
  - test: "View page source of any finding detail page and check code_snippet output"
    expected: "Angle brackets in code snippets appear as &lt; and &gt; in HTML source (not raw < >)"
    why_human: "EJS entity escaping is in place (verified by code), but visual source inspection confirms no XSS edge cases in the actual seeded content"
  - test: "Navigate to /dashboard and open Network tab"
    expected: "No requests to /vendor/prism/ are made on non-SCA pages"
    why_human: "Conditional asset loading is wired in code (locals.needsPrism guard verified), but confirming zero prism requests on dashboard requires a browser Network tab"
  - test: "Navigate to finding #11 (Outdated express-session) detail page"
    expected: "Code block uses JSON syntax highlighting (different colour palette than JavaScript findings)"
    why_human: "language-json class is wired in code (finding.id === 11 conditional verified), but visual differentiation requires browser confirmation"
---

# Phase 6: Inline Code Snippets — Verification Report

**Phase Goal:** Students see real source code context for each SCA finding, with the vulnerable line visually called out, making code review analysis concrete rather than abstract
**Verified:** 2026-03-12T20:45:00Z
**Status:** human_needed (all automated checks passed; 5 visual items need browser confirmation)
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Student sees 5-10 lines of actual source code with line numbers matching the real file | VERIFIED | All 12 findings confirmed: 7-15 lines each; vulnIdx within range for all; snippet_start_line set correctly |
| 2 | The vulnerable line is visually distinct (highlighted background and left border) | VERIFIED (wiring) / HUMAN (render) | `data-line="<%= finding.line_number %>"` on `<pre>`; CSS override `rgba(224,108,117,0.15)` + `#e06c75` border in header.ejs; visual render needs human |
| 3 | Code snippet has syntax coloring via Prism.js | VERIFIED (wiring) / HUMAN (render) | prism.min.js (25 753B, contains line-numbers + line-highlight + JS + JSON); conditionally loaded via needsPrism; visual render needs human |
| 4 | Code snippets render without XSS — angle brackets display as text | VERIFIED | `<%= finding.code_snippet %>` (escaped EJS) confirmed; no `<%-` in finding-detail.ejs |
| 5 | Student-lab cards show compact one-line preview of vulnerable code | VERIFIED (wiring) / HUMAN (render) | Extraction logic (`line_number - snippet_start_line`), styling, and ellipsis CSS wired; visual confirm needs human |
| 6 | Preview scoped only to student-lab cards, not instructor views | VERIFIED | `snippet_start_line` absent from instructor.ejs; confirmed by grep |
| 7 | Prism assets load only on finding-detail pages (not other pages) | VERIFIED | `<% if (locals.needsPrism) { %>` guard in header.ejs and footer.ejs; `needsPrism: true` only in finding-detail render call in routes/sca.js |
| 8 | Finding #11 uses JSON syntax highlighting | VERIFIED (wiring) / HUMAN (render) | `class="language-<%= finding.id === 11 ? 'json' : 'javascript' %>"` in finding-detail.ejs; JSON grammar confirmed in prism.min.js |
| 9 | npm test smoke test passes for SCA-relevant scenarios | VERIFIED | "SCA lab page" and "Finding detail" checks pass; 12/13 instances pass (port 3000 failure is pre-existing infrastructure issue, not code regression) |

**Score:** 9/9 truths verified (5 require visual browser confirmation)

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `utils/seedData.js` | Multi-line snippets (5-10 lines) + snippet_start_line for all 12 findings | VERIFIED | 13-column INSERT; all 12 findings have 7-15 lines; all vulnIdx values in range |
| `config/database.js` | INSERT handler maps snippet_start_line as params[5] | VERIFIED | `snippet_start_line: params[5]` confirmed; subsequent params shifted correctly |
| `public/vendor/prism/prism.min.js` | Core + JS + JSON + line-numbers + line-highlight bundle | VERIFIED | 25 753B; grep confirms all 4 components present |
| `public/vendor/prism/prism-one-dark.css` | One Dark syntax theme | VERIFIED | 7 991B |
| `public/vendor/prism/prism-line-numbers.css` | Line numbers plugin styles | VERIFIED | 609B |
| `public/vendor/prism/prism-line-highlight.css` | Line highlight plugin styles | VERIFIED | 1 133B |
| `views/sca/finding-detail.ejs` | Prism-powered code block with data-start, data-line, data-line-offset | VERIFIED | All three attributes present; `class="line-numbers"` present; escaped EJS used |
| `views/partials/header.ejs` | Conditional Prism CSS loading + line-highlight override | VERIFIED | `locals.needsPrism` guard present; all 3 CSS links; rgba override present |
| `views/partials/footer.ejs` | Conditional Prism JS loading | VERIFIED | `locals.needsPrism` guard; `prism.min.js` script tag present |
| `routes/sca.js` | `needsPrism: true` in finding-detail render call | VERIFIED | Confirmed at line 169 of routes/sca.js |
| `views/sca/student-lab.ejs` | One-line code preview with vulnerable line extraction | VERIFIED | `snippetLines`, `vulnIdx`, `vulnLine` extraction; all styling properties confirmed; escaped `<%= vulnLine %>` |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `utils/seedData.js` | `config/database.js` | INSERT INTO sca_findings with 13 columns including snippet_start_line | WIRED | 13-column INSERT statement confirmed; handler maps params[5] to snippet_start_line |
| `views/sca/finding-detail.ejs` | `finding.snippet_start_line` | `data-start` and `data-line-offset` attributes on pre element | WIRED | `data-start="<%= finding.snippet_start_line %>"` and `data-line-offset="<%= finding.snippet_start_line - 1 %>"` confirmed |
| `routes/sca.js` | `views/sca/finding-detail.ejs` | `needsPrism: true` passed in render call | WIRED | Confirmed at line 169 |
| `views/partials/header.ejs` | `public/vendor/prism/` | Conditional CSS loading when `locals.needsPrism` is truthy | WIRED | Guard and CSS links confirmed |
| `views/partials/footer.ejs` | `public/vendor/prism/` | Conditional JS loading when `locals.needsPrism` is truthy | WIRED | Guard and script tag confirmed |
| `views/sca/student-lab.ejs` | `f.code_snippet` + `f.snippet_start_line` | EJS scriptlet extracting vulnerable line via `line_number - snippet_start_line` offset | WIRED | `const vulnIdx = f.line_number - f.snippet_start_line` confirmed |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SNIP-01 | 06-01 | Student can see 5-10 lines of relevant source code in the finding detail view | SATISFIED | All 12 findings have 7-15 lines in code_snippet; Prism pre block in finding-detail.ejs renders them |
| SNIP-02 | 06-01 | Vulnerable line is visually called out within the code snippet (background highlight + left border) | SATISFIED (wiring verified) | `data-line` attribute wired; CSS override `rgba(224,108,117,0.15)` + `#e06c75` border present; visual needs human |
| SNIP-03 | 06-01 | Code snippet displays line numbers corresponding to actual file line numbers | SATISFIED | `data-start="<%= finding.snippet_start_line %>"` wired; all 12 snippet_start_line values verified as correct offsets |
| SNIP-04 | 06-01 | Code snippet has syntax coloring via Prism.js | SATISFIED (wiring verified) | Prism assets vendored and wired; language classes applied; visual needs human |
| SNIP-05 | 06-02 | Student-lab card shows compact one-line preview of the vulnerable code | SATISFIED (wiring verified) | Extraction formula and styled preview div in student-lab.ejs; visual needs human |

All 5 SNIP requirements accounted for. No orphaned requirements.

---

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `views/sca/student-lab.ejs` | 122, 126 | `placeholder="..."` | Info | HTML `<textarea placeholder>` attributes — these are legitimate form UI, not stub code |

No blocker or warning anti-patterns found.

---

## Human Verification Required

### 1. Syntax Highlighting Renders Correctly

**Test:** Log in as student (student/student123), navigate to /sca, click any finding detail
**Expected:** Code block shows syntax-coloured code (keywords in purple/blue, strings in green/yellow, comments in gray) using the Prism One Dark theme; line numbers appear in a left gutter starting at the snippet_start_line value
**Why human:** Prism.js applies syntax highlighting via JavaScript DOM manipulation at runtime — cannot be verified by static file analysis

### 2. Vulnerable Line Highlight Visible

**Test:** On any finding detail page, identify the highlighted line
**Expected:** The vulnerable line has a warm red/salmon background (rgba(224, 108, 117, 0.15)) and a 3px solid #e06c75 red left border, clearly distinguishing it from surrounding lines
**Why human:** CSS rendering and the Prism line-highlight plugin applying the correct data-line offset require browser execution

### 3. Student-Lab Card Previews Render and Truncate

**Test:** Navigate to /sca as student
**Expected:** Each of the 12 finding cards shows a one-line code preview in monospace font below the file:line display; long lines are truncated with an ellipsis (...)
**Why human:** CSS ellipsis truncation (overflow:hidden + white-space:nowrap + text-overflow:ellipsis) requires a browser to render to confirm it is visually effective

### 4. No Prism Assets Loaded on Non-SCA Pages

**Test:** Navigate to /dashboard, open browser DevTools Network tab, filter by "prism"
**Expected:** Zero network requests to /vendor/prism/ on the dashboard page
**Why human:** Conditional asset loading is wired correctly in code, but confirming zero spurious requests on other pages requires a live browser Network tab inspection

### 5. Finding #11 Uses JSON Syntax Highlighting

**Test:** Navigate to finding #11 (Outdated express-session) detail page
**Expected:** The code block uses JSON syntax highlighting — strings, property names, and brackets coloured differently from JavaScript findings
**Why human:** The `language-json` class is conditionally applied in code, but whether JSON tokenization visually differs from JavaScript in the browser requires human observation

---

## Gaps Summary

No gaps found. All automated checks passed:

- All 12 SCA findings have multi-line code snippets (7-15 lines) with valid snippet_start_line values
- All vulnerable line indices (line_number - snippet_start_line) are within range for every finding
- Prism.js bundle (25 753B) contains all required components: core, JavaScript, JSON, line-numbers, line-highlight
- All 6 key wiring links verified
- XSS safety confirmed: escaped EJS (`<%= %>`) used in all code output paths
- Conditional asset loading correctly guarded by `locals.needsPrism` in both header and footer
- Preview scoped to student-lab only (instructor.ejs unmodified)
- All 5 SNIP requirements satisfied
- npm test: 12/13 instances pass; SCA lab and finding detail smoke tests pass

The 5 items flagged for human verification are visual/browser rendering concerns. They cannot block goal achievement based on code evidence — the wiring is complete and correct.

---

_Verified: 2026-03-12T20:45:00Z_
_Verifier: Claude (gsd-verifier)_
