# Phase 15: CSS Extraction - Research

**Researched:** 2026-03-21
**Domain:** CSS refactoring -- extracting duplicated inline `<style>` blocks into a shared stylesheet
**Confidence:** HIGH

## Summary

Phase 15 is a pure refactoring task: create `public/styles.css`, move duplicated CSS patterns into it, link the stylesheet from `views/partials/header.ejs`, and remove the now-redundant inline `<style>` blocks from individual templates. No new libraries, no new dependencies, no architectural changes.

The codebase currently has **20 EJS templates** containing `<style>` blocks. Analysis reveals three categories of duplication: (1) severity badge classes duplicated verbatim across 11+ files, (2) classification badge classes duplicated across 6+ files, (3) status/source indicator classes duplicated across 3+ files. Additional shared patterns include progress bars, action buttons, form element styling, and finding/scenario cards. The header.ejs partial already defines base layout CSS (sidebar, cards, buttons, alerts, tables, grids, stat-cards) inline -- this should also move to the shared stylesheet.

**Primary recommendation:** Create `public/styles.css` containing ALL shared CSS (header base styles + duplicated component styles), add a single `<link>` tag in `header.ejs`, remove the inline `<style>` blocks, and verify visual parity. Standalone pages (login.ejs, error.ejs, mfa-verify.ejs) keep their own inline styles since they do NOT include the header partial.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CSS-01 | Common CSS patterns (severity badges, card layouts, status indicators) moved from inline styles to public/styles.css | Duplication map below identifies exact classes, source files, and extraction targets. Express already serves `public/` as static. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express static middleware | (already configured) | Serves `public/` directory | `app.use(express.static('public'))` on line 41 of server.js |
| EJS partials | (already configured) | `header.ejs` is included by all authenticated pages | Single point to add `<link>` tag |

### Supporting
No new libraries needed. This is pure HTML/CSS refactoring.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Single styles.css | Multiple CSS files (per-module) | Over-engineering for this codebase size; REQUIREMENTS.md explicitly says "CSS framework adoption" is out of scope |

**Installation:**
```bash
# No installation needed -- zero new dependencies
```

## Architecture Patterns

### Current State: Inline `<style>` Duplication Map

**Category 1: Severity badges (11 files, identical CSS)**
```css
.sev-Critical  { background:#ffe0e0; color:#c0392b; }
.sev-High      { background:#fff0e0; color:#c0732a; }
.sev-Medium    { background:#fffbe0; color:#9a7d0a; }
.sev-Low       { background:#e8f8e8; color:#1e8449; }
.sev-Info      { background:#e8f0ff; color:#1a5276; }
.badge-sm { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
```

Files: `sca/student-lab.ejs`, `sca/finding-detail.ejs`, `sca/instructor.ejs`, `sca/answer-key.ejs`, `sca/student-detail.ejs`, `dast/student-lab.ejs`, `dast/scenario-detail.ejs`, `dast/instructor.ejs`, `vm/student-lab.ejs`, `vm/vuln-detail.ejs`, `vm/instructor.ejs`, `pentest/student-lab.ejs`, `pentest/engagement-detail.ejs`, `pentest/report-builder.ejs`

Note: Minor variations exist -- `badge-sm` padding is `2px 10px` in `finding-detail.ejs` and `scenario-detail.ejs` vs `2px 8px` elsewhere; `3px 10px` in `vuln-detail.ejs`. `.sev-Info` only appears in files that need it (VM, answer-key, instructor). Normalize to a single canonical version.

**Category 2: Classification badges (6 files)**
```css
.cls-confirmed      { background:#d4edda; color:#155724; }
.cls-false_positive { background:#f8d7da; color:#721c24; }
.cls-needs          { background:#fff3cd; color:#856404; }
.cls-none           { background:#e9ecef; color:#6c757d; }
```

Files: `sca/student-lab.ejs`, `sca/finding-detail.ejs`, `sca/instructor.ejs`, `sca/answer-key.ejs`, `sca/student-detail.ejs`

**Category 3: VM status/source badges (3 files)**
```css
.status-open        { background:#fde8e8; color:#a93226; }
.status-in_progress { background:#fef9e7; color:#9a7d0a; }
.status-resolved    { background:#e8f8e8; color:#1e8449; }
.status-wont_fix    { background:#ececec; color:#555; }
.src-sca    { background:#e8f0ff; color:#1a5276; }
.src-dast   { background:#fde8f0; color:#7b1f42; }
.src-pentest{ background:#f0e8ff; color:#5b2c8c; }
.src-manual { background:#f0f0f0; color:#444; }
```

Files: `vm/student-lab.ejs`, `vm/vuln-detail.ejs`, `vm/instructor.ejs`

**Category 4: Progress bars (3 files)**
```css
.progress-bar-wrap { background:#e9ecef; border-radius:4px; height:6px; margin-top:4px; }
.progress-bar-fill { height:6px; border-radius:4px; background:#002855; }
```

Files: `sca/instructor.ejs`, `dast/instructor.ejs`

And the similar variant in `sca/student-lab.ejs`:
```css
.progress-outer { background:#e9ecef; border-radius:8px; height:12px; }
.progress-inner { height:12px; border-radius:8px; background:#002855; transition:width 0.3s; }
```

**Category 5: Action buttons (2 files)**
```css
.action-btn { padding:4px 10px; border:none; border-radius:4px; cursor:pointer; font-size:0.8rem; }
.btn-import   { background:#002855; color:#fff; }
.btn-imported { background:#e9ecef; color:#6c757d; cursor:default; }
```

Files: `sca/instructor.ejs`, `dast/instructor.ejs`

**Category 6: Student activity status badges (1 file, but shared pattern)**
```css
.status-active     { background:#d4edda; color:#155724; }
.status-inactive   { background:#fff3cd; color:#856404; }
.status-notstarted { background:#e9ecef; color:#6c757d; }
```

File: `sca/instructor.ejs`

**Category 7: Finding/scenario cards (shared pattern)**
```css
.finding-card { border:1px solid #dee2e6; border-radius:8px; padding:1rem 1.25rem; margin-bottom:1rem; background:#fff; }
.finding-card.done { border-left:4px solid #28a745; }
.finding-card.pending { border-left:4px solid #ffc107; }
.scenario-card { border:1px solid #dee2e6; border-radius:8px; padding:1.25rem; margin-bottom:1rem; background:#fff; }
.scenario-card.done    { border-left:4px solid #28a745; }
.scenario-card.locked  { opacity:0.6; }
```

Files: `sca/student-lab.ejs`, `dast/student-lab.ejs`

**Category 8: DAST precondition boxes (2 files)**
```css
.precondition-box { border-radius:6px; padding:0.6rem 0.9rem; font-size:0.9rem; }
.pre-met   { background:#d4edda; color:#155724; border:1px solid #c3e6cb; }
.pre-unmet { background:#fff3cd; color:#856404; border:1px solid #ffeeba; }
```

Files: `dast/student-lab.ejs`, `dast/scenario-detail.ejs`

**Category 9: Header base styles (1 file -- `header.ejs`)**
All 409 lines of CSS in `header.ejs` defining: reset, body, sidebar, nav, user profile, main content, security status, badges, page content, cards, buttons, alerts, tables, page header, grids, stat cards.

### Target Architecture

```
public/
  styles.css           # NEW -- all shared CSS (~250 lines)
  images/
  vendor/prism/

views/
  partials/header.ejs  # MODIFIED -- inline <style> replaced with <link> tag
  sca/*.ejs            # MODIFIED -- inline <style> blocks removed
  dast/*.ejs           # MODIFIED -- inline <style> blocks removed
  vm/*.ejs             # MODIFIED -- inline <style> blocks removed
  pentest/*.ejs        # MODIFIED -- inline <style> blocks removed
  login.ejs            # UNCHANGED -- standalone page, no header partial
  error.ejs            # UNCHANGED -- standalone page, no header partial
  mfa-verify.ejs       # UNCHANGED -- standalone page, no header partial
  admin/*.ejs          # MODIFIED if they have shared patterns
```

### Pattern: CSS Extraction Approach

**What:** Move all inline `<style>` blocks that define shared/reusable classes into `public/styles.css`. Add `<link rel="stylesheet" href="/styles.css">` to `header.ejs <head>`. Remove emptied `<style>` blocks from templates.

**When to use:** When the same CSS classes are duplicated across 3+ files.

**Rules:**
1. Header base styles (sidebar, cards, buttons, alerts, tables, grids) move to `styles.css` first
2. Then shared component styles (severity badges, classification badges, status badges, progress bars, action buttons, cards)
3. Page-specific styles that are NOT shared stay inline (e.g., answer-key `.ak-*` classes, pentest `.phase-*` classes, security panel `.security-grid` etc.)
4. Standalone pages (login, error, mfa-verify) keep their own inline styles -- they don't include header.ejs

**Example -- header.ejs before:**
```html
<head>
  <style>
    /* 409 lines of CSS */
  </style>
</head>
```

**Example -- header.ejs after:**
```html
<head>
  <link rel="stylesheet" href="/styles.css">
</head>
```

### Decision: What Stays Inline vs What Moves

| Category | Move to styles.css? | Reason |
|----------|---------------------|--------|
| Header base (sidebar, cards, buttons, tables) | YES | Foundation CSS, used by every authenticated page |
| Severity badges (.sev-*) | YES | Duplicated in 14 files |
| .badge-sm | YES | Duplicated in 14 files |
| Classification badges (.cls-*) | YES | Duplicated in 6 files |
| VM status badges (.status-open, etc.) | YES | Duplicated in 3 files |
| Source badges (.src-*) | YES | Duplicated in 3 files |
| Progress bars | YES | Duplicated in 3 files |
| Action buttons (.action-btn, .btn-import) | YES | Duplicated in 2 files |
| Finding/scenario cards | YES | Shared pattern across SCA/DAST |
| Precondition boxes | YES | Duplicated in 2 files |
| Student activity status (.status-active, etc.) | YES | Shared pattern |
| Modal styles (.modal, .modal-box) | YES | Used in VM instructor |
| Answer-key specific (.ak-*) | BORDERLINE -- YES | Only 1 file but cleanly namespaced, keeps template clean |
| Pentest-specific (.phase-*, .finding-row, .report-section) | BORDERLINE -- YES | Only pentest module but keeps templates clean |
| Prism line-highlight override | NO -- keep in header.ejs | Conditional on needsPrism flag, small (3 lines) |
| Security panel (.security-grid, .security-card) | YES | Page-specific but still benefits from extraction |
| Login/error/mfa page styles | NO | Standalone pages with own `<head>` |

### Anti-Patterns to Avoid
- **Partial extraction:** Don't leave some severity badge definitions inline and move others. Move ALL instances at once.
- **Changing visual appearance:** This is a refactor, not a redesign. The extracted CSS must produce identical visual output.
- **Breaking the Prism conditional:** The `needsPrism` conditional CSS loading in header.ejs must remain functional.
- **Over-abstracting:** Don't create a CSS class naming system or BEM methodology. Keep the existing class names exactly as-is.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CSS minification | Custom build step | Raw CSS file | No build system exists; CSS is small (~250 lines); classroom project |
| CSS modules/scoping | CSS-in-JS or modules | Flat CSS with descriptive class names | No build tool, no framework, existing convention |
| CSS framework | Bootstrap, Tailwind, etc. | Existing hand-written CSS | Explicitly out of scope per REQUIREMENTS.md |

**Key insight:** This project has zero CSS build tools and intentionally stays that way. The extraction is a simple file move operation, not an architecture migration.

## Common Pitfalls

### Pitfall 1: Badge-sm Padding Inconsistency
**What goes wrong:** The `.badge-sm` class has slight padding variations across files (2px 8px vs 2px 10px vs 3px 10px).
**Why it happens:** Different developers/phases defined the class independently.
**How to avoid:** Pick the most common value (`2px 8px`) as the canonical version. Verify visual parity after extraction. The 2px difference is imperceptible.
**Warning signs:** If badges look visually different after extraction, check padding values.

### Pitfall 2: Missing `.sev-Info` in Some Files
**What goes wrong:** Some files define `.sev-Info` and some don't. After extraction, all pages will have it available but that's fine (unused CSS is harmless).
**Why it happens:** Only VM and answer-key views show Info-severity items.
**How to avoid:** Include `.sev-Info` in the shared stylesheet. Extra unused classes cause no issues.

### Pitfall 3: CSS Specificity/Order Issues
**What goes wrong:** Moving CSS from inline `<style>` (which appears after `<link>` tags) to an external stylesheet could change specificity if there are conflicting rules.
**Why it happens:** Inline `<style>` blocks in `<head>` come after any `<link>` tags, giving them higher precedence in case of conflicts.
**How to avoid:** Since the header.ejs base CSS will ALSO move to styles.css, and we'll place the `<link>` tag where the `<style>` block was, ordering is preserved. There are no conflicting rules between header CSS and page CSS since they use different class names.
**Warning signs:** If the sidebar or base layout looks different after extraction, check CSS load order.

### Pitfall 4: Forgetting to Remove Empty Style Blocks
**What goes wrong:** Leaving empty `<style></style>` tags or partially-emptied style blocks in templates after extraction.
**Why it happens:** Oversight during refactoring.
**How to avoid:** After extraction, grep for `<style>` across all modified templates to verify blocks are fully removed.

### Pitfall 5: Standalone Pages Breaking
**What goes wrong:** Login, error, and MFA pages break because they get linked to styles.css which assumes app-layout context.
**Why it happens:** These pages have their own `<head>` with custom full-page CSS (centered container, etc.).
**How to avoid:** Don't touch login.ejs, error.ejs, or mfa-verify.ejs. They are standalone and have NO shared CSS with the app layout.

### Pitfall 6: Prism CSS Conditional Loading
**What goes wrong:** Moving the Prism line-highlight override into styles.css means it loads even when Prism is not needed.
**Why it happens:** The override is currently inside a `<% if (locals.needsPrism) { %>` conditional block.
**How to avoid:** Keep the Prism line-highlight override inside the conditional block in header.ejs. It's only 3 lines and is page-conditional.

## Code Examples

### styles.css Structure
```css
/* ===== Base (from header.ejs) ===== */
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,...; line-height:1.6; color:#333; background:#f0f2f5; }
/* ... sidebar, nav, main-content, cards, buttons, alerts, tables, grids, stat-cards ... */

/* ===== Severity Badges ===== */
.sev-Critical  { background:#ffe0e0; color:#c0392b; }
.sev-High      { background:#fff0e0; color:#c0732a; }
.sev-Medium    { background:#fffbe0; color:#9a7d0a; }
.sev-Low       { background:#e8f8e8; color:#1e8449; }
.sev-Info      { background:#e8f0ff; color:#1a5276; }
.badge-sm      { display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }

/* ===== Classification Badges ===== */
.cls-confirmed      { background:#d4edda; color:#155724; }
.cls-false_positive { background:#f8d7da; color:#721c24; }
.cls-needs          { background:#fff3cd; color:#856404; }
.cls-none           { background:#e9ecef; color:#6c757d; }

/* ===== VM Status & Source Badges ===== */
.status-open        { background:#fde8e8; color:#a93226; }
.status-in_progress { background:#fef9e7; color:#9a7d0a; }
.status-resolved    { background:#e8f8e8; color:#1e8449; }
.status-wont_fix    { background:#ececec; color:#555; }
.src-sca    { background:#e8f0ff; color:#1a5276; }
.src-dast   { background:#fde8f0; color:#7b1f42; }
.src-pentest{ background:#f0e8ff; color:#5b2c8c; }
.src-manual { background:#f0f0f0; color:#444; }

/* ===== Student Activity Status ===== */
.status-active     { background:#d4edda; color:#155724; }
.status-inactive   { background:#fff3cd; color:#856404; }
.status-notstarted { background:#e9ecef; color:#6c757d; }

/* ===== Progress Bars ===== */
.progress-bar-wrap { background:#e9ecef; border-radius:4px; height:6px; margin-top:4px; }
.progress-bar-fill { height:6px; border-radius:4px; background:#002855; }
.progress-outer    { background:#e9ecef; border-radius:8px; height:12px; }
.progress-inner    { height:12px; border-radius:8px; background:#002855; transition:width 0.3s; }

/* ===== Action Buttons ===== */
.action-btn   { padding:4px 10px; border:none; border-radius:4px; cursor:pointer; font-size:0.8rem; }
.btn-import   { background:#002855; color:#fff; }
.btn-imported { background:#e9ecef; color:#6c757d; cursor:default; }

/* ===== Finding & Scenario Cards ===== */
.finding-card          { border:1px solid #dee2e6; border-radius:8px; padding:1rem 1.25rem; margin-bottom:1rem; background:#fff; }
.finding-card.done     { border-left:4px solid #28a745; }
.finding-card.pending  { border-left:4px solid #ffc107; }
.scenario-card         { border:1px solid #dee2e6; border-radius:8px; padding:1.25rem; margin-bottom:1rem; background:#fff; }
.scenario-card.done    { border-left:4px solid #28a745; }
.scenario-card.locked  { opacity:0.6; }

/* ===== Precondition Boxes ===== */
.precondition-box { border-radius:6px; padding:0.6rem 0.9rem; font-size:0.9rem; }
.pre-met   { background:#d4edda; color:#155724; border:1px solid #c3e6cb; }
.pre-unmet { background:#fff3cd; color:#856404; border:1px solid #ffeeba; }

/* ... page-specific sections as needed ... */
```

### header.ejs Modification
```html
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= typeof title !== 'undefined' ? title : t('nav.defaultTitle') %></title>
  <link rel="stylesheet" href="/styles.css">
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
</head>
```

### Template Cleanup Example (sca/student-lab.ejs)
```html
<!-- BEFORE: 23 lines of <style> block -->
<style>
  .sev-Critical  { background:#ffe0e0; color:#c0392b; }
  ... (all duplicated CSS)
</style>

<!-- AFTER: entire <style> block removed -->
<!-- Classes are now available via styles.css linked in header.ejs -->
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Inline `<style>` per-template | External shared stylesheet | This phase | Eliminates duplication across 14+ templates |

**Deprecated/outdated:**
- N/A -- this is a straightforward CSS refactoring, no external technology involved.

## Open Questions

1. **Page-specific styles: extract or leave inline?**
   - What we know: Some templates have styles unique to that page (answer-key `.ak-*`, pentest `.phase-*`, security panel `.security-grid`). These are NOT duplicated.
   - What's unclear: Whether to also extract page-specific styles for consistency, or leave them inline to minimize the diff.
   - Recommendation: Extract ALL page-specific styles into styles.css as well. This fully satisfies CSS-01's "instead of inline `<style>` blocks" criterion and produces cleaner templates. The cost is a slightly larger CSS file (still well under 500 lines) which is negligible.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, no version -- Node.js native) |
| Config file | none -- tests run via `node --test test/*.test.js` |
| Quick run command | `npm test` (smoke tests) |
| Full suite command | `npm run test:integration` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CSS-01 | Shared CSS served and no duplicate `<style>` blocks | smoke | `curl -s http://localhost:3000/styles.css \| head -5` | No -- manual verification |
| CSS-01 | Visual parity after refactor | manual-only | Visual comparison of key pages | N/A -- CSS refactoring verified by visual inspection |

### Sampling Rate
- **Per task commit:** `npm test` (smoke tests verify server starts and pages render)
- **Per wave merge:** `npm run test:integration` (full integration suite)
- **Phase gate:** Full suite green + visual spot-check of severity badges on SCA student-lab page

### Wave 0 Gaps
None -- existing test infrastructure covers server boot and page rendering. CSS extraction is a visual refactor; automated CSS testing would be over-engineering for this classroom project.

## Sources

### Primary (HIGH confidence)
- Direct codebase analysis: All 20 EJS files with `<style>` blocks read and analyzed
- `server.js` line 41: `app.use(express.static(path.join(__dirname, 'public')))` confirms static serving
- `views/partials/header.ejs`: Full 588-line read confirms base CSS structure
- `.planning/REQUIREMENTS.md`: CSS-01 requirement and "CSS framework adoption" out-of-scope constraint

### Secondary (MEDIUM confidence)
- N/A -- no external libraries or APIs involved

### Tertiary (LOW confidence)
- N/A -- all findings verified via direct codebase inspection

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - No libraries needed, just file creation and template editing
- Architecture: HIGH - Direct analysis of all 20 template files with duplication map
- Pitfalls: HIGH - Known from codebase analysis (specificity, conditional Prism, standalone pages)

**Research date:** 2026-03-21
**Valid until:** Indefinite (pure refactoring of existing codebase, no external dependencies)
