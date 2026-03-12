# Feature Landscape

**Domain:** Inline code snippets, instructor answer key, documentation updates, and code quality optimization for an educational SCA lab platform
**Researched:** 2026-03-12
**Milestone:** v1.1 Polish & Pedagogy

## Context

This analysis covers only the four NEW features for v1.1. Everything from v1.0 is shipped and working: 12 SCA findings with file paths, line numbers, CWEs; student finding detail view with classification workflow; instructor dashboard with review matrix and live stats; full French UI with localize() helper; Codespaces deployment with 12 team instances. The v1.1 milestone adds inline code snippets in the finding detail view, an instructor answer key for the 12 findings, updated README/docs, and AI-driven code quality optimization.

## Table Stakes

Features that users expect given the existing platform. Missing any of these makes the v1.1 milestone feel incomplete.

| Feature | Why Expected | Complexity | Dependencies on Existing |
|---------|--------------|------------|--------------------------|
| Multi-line code snippets (5-10 lines) replacing current single-line snippets | Current `code_snippet` field is a single line of code (e.g., `"secret: 'university-secret-key-change-in-production'"`). Students see one line with no context. Any security code review tool shows surrounding context. Without it, students cannot verify the finding against the actual code flow. | MEDIUM | Requires updating all 12 `code_snippet` values in `utils/seedData.js`. The `finding-detail.ejs` already renders `finding.code_snippet` inside a `<pre>` block with dark theme (`background:#282c34; color:#abb2bf`). No schema change needed -- just longer string values. |
| Vulnerable line visually called out within the snippet | When showing 5-10 lines, the specific vulnerable line must be visually distinct (background highlight, arrow marker, or bold). Otherwise students stare at 10 lines of code with no idea which line matters. Every SAST tool (Semgrep, Snyk Code, SonarQube) highlights the flagged line differently from context lines. | LOW | Can be achieved with CSS-only approach: wrap the vulnerable line in a `<span>` with a distinct background color. No JS needed. The seed data could use a marker convention (e.g., `>>> line <<<` or a separate `vulnerable_line_index` field). |
| Line numbers in the code snippet | When code shows multiple lines, students need line numbers to match what they see in the actual file. The finding already displays `file_path:line_number` at the top -- the snippet line numbers must correspond. | LOW | Rendered via CSS `counter-increment` on each line or pre-computed in the seed data string. No new dependencies. Works within the existing `<pre>` block. |
| Instructor answer key view (role-gated) | SOLUTION-GUIDE.md already exists with expected classifications and reasoning for all 12 findings. But the instructor must leave the app to consult a markdown file. An in-app answer key accessible only to professor/admin roles is the natural next step. The teaching flow (SOLUTION-GUIDE.md lines 643-668) explicitly describes the instructor reviewing student work and leading discussion -- an in-app reference eliminates context-switching. | MEDIUM | Requires a new route (e.g., `GET /sca/answer-key`) gated by `requireRole(['admin', 'professor'])`. A new EJS template. Data can be stored as a JSON object in the route file or as new fields in the seed data. Must be in French to match the rest of the UI. |
| Answer key per-finding: expected classification, reasoning, discussion points | The SOLUTION-GUIDE.md already provides expected classification for each of the 12 findings (lines 628-641). The answer key should include: (1) expected classification (confirmed/FP/needs investigation), (2) reasoning explaining why, (3) discussion prompts for the instructor to use in class review. | MEDIUM | Data structure: could be a `ANSWER_KEY` constant object in `routes/sca.js` keyed by finding ID, or new i18n keys under `sca.answerKey.<findingId>`. The latter is better because it keeps French text in the translation system and avoids hardcoded strings in route code. |
| Updated README reflecting v1.1 state | README must accurately describe the current feature set. Post-v1.0, the README likely describes an earlier state. Students and future instructors reading the README should understand what the platform does today. | LOW | Read current README, update sections for new features. No code dependencies. |

## Differentiators

Features that elevate the platform beyond functional. Not strictly required but would make the v1.1 milestone meaningfully better for teaching.

| Feature | Value Proposition | Complexity | Dependencies on Existing |
|---------|-------------------|------------|--------------------------|
| Syntax coloring in code snippets (keyword/string/comment differentiation) | Dark background with monochrome text (current state) is functional but flat. Even minimal syntax coloring -- strings in green, keywords in blue, comments in gray -- makes code more readable and teaches students to "read" code visually. | LOW-MEDIUM | **Two approaches, recommend server-side HTML:** (1) Pre-render colored `<span>` tags directly in seed data strings -- zero runtime cost, zero dependencies, full control. (2) Use highlight.js server-side in the route to wrap `code_snippet` before passing to template. Approach 1 is preferred because of the "no new dependencies" constraint and only 12 static snippets to color. |
| Answer key inline within finding detail (instructor-only collapsible section) | Instead of a separate answer key page, show a collapsible "Corrige" section at the bottom of each finding-detail view when the user is professor/admin. This keeps the instructor in the same view as student reviews, enabling them to compare student reasoning against the expected answer without navigating away. | LOW | Already role-gated: `finding-detail.ejs` lines 80-101 show student reviews only for non-student roles. A similar `<% if (user.role !== 'student') { %>` block can render the answer key. Data passed from the route via the existing `res.render()` call. |
| Answer key comparison indicators (student vs expected) | On the instructor's per-student review view, show whether each student's classification matches the expected answer. A simple green check / red X next to each classification. Helps the instructor quickly spot students who need help without mentally comparing against the solution guide. | LOW | Requires passing the answer key data alongside student reviews in `GET /sca/student/:studentId`. Render as a badge next to each classification. |
| Code quality pass: consistent EJS template patterns | Current EJS templates have inconsistent patterns: some use inline styles, some duplicate CSS across views, some use `<%= %>` where `<%- %>` might be appropriate. A consistency pass makes the codebase more maintainable for future semesters. | MEDIUM | No functional change. Refactoring within existing files. Risk: any EJS change could break rendering. Must verify with smoke test after each change. |
| Code quality pass: route organization and error handling | `routes/sca.js` is clean (237 lines) but other route files may benefit from consistent error handling patterns, removal of dead code, and consistent response formats. | MEDIUM | No functional change. Must be careful not to change behavior. Smoke test is the safety net. |
| Documentation: architecture decision records for v1.1 changes | Document why specific approaches were chosen (e.g., pre-rendered HTML for syntax highlighting instead of client-side library). Helps future instructors or developers understand the rationale. | LOW | Markdown files in `.planning/`. No code dependencies. |

## Anti-Features

Features to explicitly NOT build for v1.1. These are tempting but would violate constraints or add unnecessary risk.

| Anti-Feature | Why Tempting | Why Avoid | What to Do Instead |
|--------------|-------------|-----------|-------------------|
| Client-side syntax highlighting library (Prism.js, highlight.js CDN) | Would give beautiful, automatic syntax coloring for any language | Violates the "no new dependencies" constraint. CDN dependency means Codespaces instances need internet access at render time. Adds client-side JS weight. Only 12 static code snippets -- overkill. | Pre-render colored `<span>` tags in the seed data. 12 snippets is a small enough set to hand-color the HTML. Zero runtime cost, zero dependencies. |
| Live code editor in finding detail | Students could edit and test code fixes in the browser | Massive scope increase. Requires a code editor library (CodeMirror, Monaco), sandboxed execution, and dramatically changes the pedagogical model. This is a different product. | Keep the current read-only code display. Students analyze and classify; they do not fix code in this exercise. |
| Auto-grading against the answer key | Tempting to show students a score when they submit | Explicitly out of scope per PROJECT.md: "Auto-grading or 'correct answer' comparison -- SCA triage is subjective." The exercise is formative. Showing right/wrong answers changes student behavior toward gaming for marks instead of thoughtful analysis. Finding #11 (outdated dependency) deliberately has "Needs Investigation" as the expected answer -- there is no single correct classification. | Keep the answer key instructor-only. Let the instructor lead discussion on ambiguous findings. |
| Student-visible solution explanations post-submission | Show students the expected answer after they submit | Undermines the class discussion phase. The teaching flow explicitly has the instructor review submissions and then lead a group discussion. Revealing answers before discussion removes the "aha moment." | Instructor references the in-app answer key during live class discussion. Students learn from the discussion, not from a reveal screen. |
| Separate answer key database table | Store answer key data in the JSON database alongside findings | Over-engineering for 12 static records that never change at runtime. Adds schema complexity, migration concerns, and seed data changes. The answer key is reference material, not user-generated data. | Store as a constant in route code or as i18n keys. Both are simpler and sufficient. |
| Comprehensive JSDoc or TypeScript migration | Would improve code quality significantly | Scope explosion. The codebase is ~11,800 LOC of working JavaScript. A type migration or full JSDoc pass is a multi-day effort that does not serve the v1.1 pedagogical goals. | Focus code quality on consistency (naming, error handling, dead code removal) rather than type systems. Add JSDoc only to new functions created for v1.1. |
| README auto-generation from code | Tempting to auto-generate docs from code comments | Over-engineering. The README needs a human-written update that explains the product, not API documentation. | Hand-write a clear, concise README update reflecting the current feature set. |

## Feature Dependencies

```
[Multi-line Code Snippets]
    updates seed data in utils/seedData.js (12 code_snippet values)
    no other feature depends on this -- can be done independently

[Vulnerable Line Highlight]
    requires [Multi-line Code Snippets] (meaningless with single-line snippets)
    updates finding-detail.ejs rendering logic
    may need a `vulnerable_line_index` field or marker convention in seed data

[Line Numbers in Snippet]
    requires [Multi-line Code Snippets] (meaningless with single-line snippets)
    CSS-only change in finding-detail.ejs

[Syntax Coloring] (differentiator)
    requires [Multi-line Code Snippets] (coloring applied to the multi-line content)
    if pre-rendered HTML approach: changes seed data strings to include <span> tags
    if pre-rendered: finding-detail.ejs must use <%- %> (unescaped) instead of <%= %> for code_snippet

[Instructor Answer Key View]
    independent of code snippet work
    requires new route + new EJS template
    requires French i18n keys for answer key content
    requires role gating (already established pattern)

[Answer Key Per-Finding Data]
    requires [Instructor Answer Key View] (no view = no place to render it)
    data source: SOLUTION-GUIDE.md lines 628-641 + teaching flow reasoning

[Answer Key Inline in Finding Detail] (differentiator)
    requires [Answer Key Per-Finding Data]
    modifies finding-detail.ejs (instructor-only section)
    can coexist with standalone answer key page

[Updated README]
    independent of all code changes
    should be done LAST so it reflects final state

[Code Quality Optimization]
    independent of feature work
    should be done AFTER feature work to avoid merge conflicts
    must verify with smoke test (npm test) after each change
```

### Dependency Summary

Two independent work streams:
1. **Code Snippet Stream:** Multi-line snippets -> vulnerable line highlight + line numbers -> (optional) syntax coloring
2. **Answer Key Stream:** Answer key data + route + template -> (optional) inline in finding detail

These streams have zero dependencies on each other and can be built in parallel. README and code quality are independent cleanup tasks done last.

## MVP Recommendation

### Must Build (P0) -- Defines the v1.1 milestone

1. **Multi-line code snippets (5-10 lines) with vulnerable line called out** -- This is the headline feature of v1.1. Current single-line snippets provide inadequate context for code review. Every finding needs surrounding code so students can understand the vulnerability in context. The vulnerable line needs a distinct visual treatment (background highlight).

2. **Line numbers in code snippets** -- Essential companion to multi-line display. Students reference `file_path:line_number` and need the snippet lines to correspond.

3. **Instructor answer key (in-app, role-gated)** -- Replaces the need to consult SOLUTION-GUIDE.md externally. Must include expected classification, reasoning, and discussion prompts for all 12 findings. Must be in French.

4. **Updated README** -- Reflect the v1.1 feature set accurately.

### Should Build (P1) -- High value, low risk

5. **Syntax coloring via pre-rendered HTML spans** -- Makes code snippets significantly more readable. Low complexity with the pre-rendered approach (12 static snippets to prepare). No dependencies added.

6. **Answer key inline in finding detail view** -- Eliminates navigation for the instructor. Collapsible section keeps the UI clean.

7. **Answer key comparison badges on student review** -- Quick visual for instructor to spot classification mismatches.

### Defer (P2) -- Code quality and docs

8. **Code quality optimization** -- Important but does not affect the user experience. Should be done after features to avoid merge conflicts. Scope carefully: focus on consistency patterns, not wholesale refactoring.

9. **Architecture decision records** -- Useful for future semesters but not user-facing.

## Implementation Notes

### Code Snippet Approach: Pre-rendered Multi-line Strings in Seed Data

The current `code_snippet` field in `utils/seedData.js` contains single lines like:
```
"secret: 'university-secret-key-change-in-production'"
```

For v1.1, replace with multi-line strings (5-10 lines of actual surrounding code from each referenced file). Example for finding #1 (server.js:44):
```
// Session configuration
const startupSecuritySettings = getSecuritySettings();
app.use(session({
  secret: 'university-class-management-secret-key-change-in-production',  // <-- vulnerable
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
```

Two approaches for marking the vulnerable line:
- **Option A (recommended):** Add a `vulnerable_line_offset` integer field to each finding (e.g., `3` meaning the 4th line, 0-indexed). The EJS template splits the snippet by newlines and applies a highlight class to that line.
- **Option B:** Use a marker convention in the string (e.g., `>>>` prefix). The EJS template detects and strips the marker while applying styling.

Option A is cleaner because it keeps data and presentation separate.

### Code Snippet Rendering: Template Changes

Current rendering in `finding-detail.ejs` line 53:
```html
<pre style="background:#282c34; color:#abb2bf; ..."><%= finding.code_snippet %></pre>
```

Replace with a line-by-line renderer:
```html
<pre style="background:#282c34; color:#abb2bf; ..."><%
  const lines = finding.code_snippet.split('\n');
  const startLine = finding.line_number - finding.vulnerable_line_offset;
  lines.forEach((line, i) => {
    const lineNum = startLine + i;
    const isVuln = (i === finding.vulnerable_line_offset);
%><span style="<%= isVuln ? 'background:#3e2723; display:inline-block; width:100%;' : '' %>"><span style="color:#636d83; user-select:none;"><%= String(lineNum).padStart(3) %> </span><%= line %></span>
<% }); %></pre>
```

This adds line numbers and highlights the vulnerable line with no dependencies.

### Answer Key Data Structure

Store as i18n keys in `fr.json` and `en.json` under `sca.answerKey.<findingId>`:
```json
{
  "sca": {
    "answerKey": {
      "1": {
        "expectedClassification": "confirmed",
        "reasoning": "Le secret de session est visible en clair dans le code source...",
        "discussionPoints": "Demandez aux etudiants : que se passe-t-il si un attaquant..."
      }
    }
  }
}
```

This keeps French text in the translation system (consistent with the existing `sca.findings.<id>` pattern), makes English fallback automatic, and requires no database schema changes.

### Answer Key Route

```
GET /sca/answer-key -> requireAuth, requireRole(['admin', 'professor'])
```

Renders a new `views/sca/answer-key.ejs` template showing all 12 findings with their expected classifications, reasoning, and discussion points. Uses the existing card/table styling from `instructor.ejs`.

### Code Quality Scope

Focus areas (from codebase observation):
- **Consistent error handling:** Some routes return JSON errors, others render error pages. Standardize per route type (API vs page).
- **Dead code removal:** Check for unused variables, unreachable branches.
- **CSS extraction:** Inline `<style>` blocks in SCA templates share duplicated CSS (severity colors, badge styles). Consider extracting to a shared partial or the public CSS file.
- **Consistent naming:** Verify function/variable naming follows a single convention throughout.

Out of scope for code quality: TypeScript migration, JSDoc for existing code, dependency updates, architectural changes.

## Sources

- [Highlight.js server-side rendering](https://hackernoon.com/server-side-code-highlighting-in-node-4f10h4289) -- confirms highlight.js works server-side in Node but requires npm install (ruled out by constraint)
- [CSS-only syntax highlighting approaches](https://github.com/soulshined/ft-syntax-highlight) -- pure CSS syntax highlighter exists but requires manual span wrapping (validates our pre-rendered approach)
- [Server-side code highlighting performance](https://remysharp.com/2019/04/09/code-highlighting-server-or-client) -- SSR highlighted code has zero client-side impact and smaller total transfer
- [OWASP Security Shepherd](https://owasp.org/www-project-security-shepherd/) -- uses user-specific solution keys to prevent sharing; instructor admin controls for class management
- [OWASP Secure Coding Dojo - Code Review 101](https://owasp.org/SecureCodingDojo/codereview101/) -- structured code review training with inline code display
- [Snyk Code SAST tool UX](https://snyk.io/product/snyk-code/) -- highlights affected code lines with context, provides specific remediation inline
- [SAST tools feature comparison](https://www.guru99.com/code-review-tools.html) -- all major tools show filename, location, line number, and affected code snippet with the problematic line highlighted
- [yeswehack/vulnerable-code-snippets](https://github.com/yeswehack/vulnerable-code-snippets) -- collection of vulnerable code snippets used for security education, showing the pattern of presenting code with highlighted vulnerable sections
- Existing `SOLUTION-GUIDE.md` in the repository (lines 614-678) -- already contains expected classifications, teaching flow, and grading rubric for all 12 SCA findings

---
*Feature research for: HEC Montreal SCA Lab v1.1 Polish & Pedagogy*
*Researched: 2026-03-12*
