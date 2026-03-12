# Pitfalls Research

**Domain:** Adding inline code snippets, instructor answer key, documentation, and code quality optimization to an existing educational SCA lab
**Researched:** 2026-03-12
**Confidence:** HIGH (all findings verified against codebase)

---

## Critical Pitfalls

### Pitfall 1: Inline Code Snippets Rendered Without HTML Escaping Create XSS in a Security Lab

**What goes wrong:**
The current `finding-detail.ejs` renders the existing single-line `code_snippet` field via `<%= finding.code_snippet %>` inside a `<pre>` tag (line 53). EJS `<%=` auto-escapes HTML entities, which is correct. When expanding to multi-line code snippets (5-10 lines), developers naturally switch to `<%-` (unescaped) to preserve formatting, or wrap the snippet in a `<code>` tag with innerHTML for syntax highlighting. The moment you use unescaped output for code that contains `<script>`, `<img onerror=`, or HTML angle brackets, you introduce XSS -- in a security education platform. The irony would be devastating to credibility.

Several of the 12 seed findings contain angle brackets or HTML-significant characters. Finding 7 references "No CSRF middleware configured" which is benign, but any future snippet containing `<script>` tags or template literals with `${}` inside EJS would break rendering or create injection.

**Why it happens:**
Multi-line code with syntax highlighting feels like it needs raw HTML output. Developers reach for `<%-` or build HTML strings with span-based coloring, bypassing EJS escaping.

**How to avoid:**
1. Continue using `<%= %>` (escaped) for all code snippet content inside `<pre><code>` blocks
2. For syntax highlighting without external dependencies: use CSS-only styling on the `<pre>` block (dark theme already exists at line 53 of finding-detail.ejs) and a simple EJS helper that wraps the vulnerable line in a `<mark>` tag using string replacement AFTER escaping
3. Never use `<%-` for any user-facing data, even seed data -- treat seed data as untrusted
4. Test with a snippet containing `<script>alert(1)</script>` to verify escaping works

**Warning signs:**
- Any `<%-` tag in the code snippet rendering area
- Code snippets rendering as blank or broken (HTML entities being interpreted)
- Syntax highlighting that requires building raw HTML strings

**Phase to address:**
Phase 1 (Inline Code Snippets) -- must be the first architectural decision before any template work begins.

---

### Pitfall 2: Adding New Fields to Seed Data Breaks Existing Student Databases on Re-seed

**What goes wrong:**
The v1.1 features require adding new data to the 12 SCA findings: multi-line `code_snippet` content (currently single-line), and potentially new fields for the answer key (e.g., `expected_classification`, `instructor_reasoning`). The `seedDatabase()` function in `utils/seedData.js` starts by running `DELETE FROM` on all tables (lines 7-12), then re-inserts everything. If a Codespaces instance has already been used in class (students have submitted reviews), re-seeding **destroys all student work** stored in `sca_student_reviews`.

The JSON-file database (`config/database.js`) loads data from `database/data.json` at startup. The seed function only runs when `isDatabaseSeeded()` returns false. But if a developer runs `seedDatabase()` manually to pick up new snippet data, or if the seed-check logic changes, all 12 team instances lose their student data.

**Why it happens:**
Seed data updates feel safe because "it's just reference data." But the seed function is destructive -- it wipes all tables, not just the ones being updated. There is no migration path for updating existing findings without losing reviews.

**How to avoid:**
1. Do NOT modify `seedDatabase()` to add new fields -- it is a nuclear option that destroys everything
2. Instead, store multi-line code snippets and answer key data as **static data structures** in the route file or a new data module (e.g., `utils/scaSnippets.js`), keyed by finding ID
3. These static structures get merged at render time in the route handler, never touching the database
4. The existing `DIFFICULTY_MAP` constant in `routes/sca.js` (line 8) is the proven pattern -- finding-level enrichment at route level without DB changes
5. If DB schema changes are truly needed later, write a migration function that updates individual records, not a full reseed

**Warning signs:**
- Any modification to `seedDatabase()` or the `scaFindings` array in `seedData.js`
- Adding columns to the `INSERT INTO sca_findings` statement
- Running seed during development while Codespaces instances are active

**Phase to address:**
Phase 1 (Inline Code Snippets) and Phase 2 (Answer Key) -- the data architecture decision must be made before either feature starts.

---

### Pitfall 3: Answer Key Accidentally Exposed to Students Through Shared Routes

**What goes wrong:**
The current SCA route architecture in `routes/sca.js` uses a single `GET /sca/findings/:id` endpoint (line 139) that serves both students and instructors, with role-based rendering in the EJS template. If the answer key data (expected classification, reasoning, discussion points) is passed to the template as part of the finding object or as a separate variable, it will be present in the page source for ALL users -- students included. Even if the EJS template conditionally renders `<% if (user.role !== 'student') { %>`, the data is still in the HTML source if it was passed via a JavaScript variable or hidden element.

This is explicitly listed as out of scope in PROJECT.md: "Solution guide visible to students -- instructor references SOLUTION-GUIDE.md during discussion."

**Why it happens:**
The simplest implementation adds answer key fields to the finding object and conditionally shows them in EJS. This works visually but the data is still server-rendered into the page. Students who view source or inspect the DOM see everything.

**How to avoid:**
1. **Never pass answer key data to the template when the user is a student.** The role check must happen in the route handler (`routes/sca.js`), not the template
2. In the `GET /sca/findings/:id` route, only merge answer key data when `user.role !== 'student'`:
   ```javascript
   if (user.role !== 'student') {
     localizedFinding.answerKey = ANSWER_KEYS[finding.id];
   }
   ```
3. Alternatively, serve the answer key on a separate instructor-only route (e.g., `GET /sca/findings/:id/answer-key`) with `requireRole(['admin', 'professor'])` middleware
4. The existing SOLUTION-GUIDE.md is a Markdown file in the repo root -- students with Codespaces access can read it. Consider whether the in-app answer key partially replaces this file or supplements it

**Warning signs:**
- Answer key data passed unconditionally in `res.render()` calls
- Answer key fields present in the `finding` object that gets passed to all templates
- Any `<script>` block in EJS that serializes the finding object to JSON (would include answer key)

**Phase to address:**
Phase 2 (Instructor Answer Key) -- the route-level gating pattern must be established before any template work.

---

### Pitfall 4: Code Snippet Expansion Breaks the Student Lab Card Layout

**What goes wrong:**
The current `student-lab.ejs` renders an inline review form for each finding (line 96-128) that includes a single-line code snippet in a `<pre>` block (line 99). When expanding to 5-10 lines of syntax-highlighted code, this `<pre>` block will dominate the card, pushing the classification form below the fold. With 12 findings each showing a multi-line snippet, the page becomes extremely long and students lose orientation. The inline form pattern that works for a 1-line snippet becomes unwieldy at 5-10 lines.

Additionally, the finding-detail page (`finding-detail.ejs`) uses a 2-column grid layout (line 34: `grid-template-columns:2fr 1fr`). A 10-line code block in the left column will be fine on wide screens but will overflow or compress on smaller Codespaces browser panels where the viewport may be narrow.

**Why it happens:**
Expanding a 1-line snippet to 10 lines seems like a simple content change, but it fundamentally changes the visual weight of the code block relative to other elements.

**How to avoid:**
1. In `student-lab.ejs`, show only the **vulnerable line** (1 line, as today) in the card-level inline form. Reserve the full multi-line snippet for the `finding-detail.ejs` page only
2. In `finding-detail.ejs`, use a scrollable `<pre>` with `max-height: 300px; overflow-y: auto` to contain long snippets
3. Highlight the vulnerable line within the multi-line context using a background color highlight (e.g., `background: rgba(255, 0, 0, 0.1)`) rather than only showing the vulnerable line
4. Test the layout at the Codespaces browser panel width (~1200px typical, can be as narrow as 900px with sidebar open)

**Warning signs:**
- Student-lab page requires excessive scrolling to reach all 12 findings
- Code blocks overflowing their containers horizontally
- Finding-detail page right column (review form) pushed below the code block on narrow viewports

**Phase to address:**
Phase 1 (Inline Code Snippets) -- layout decisions must be made alongside the snippet data structure.

---

### Pitfall 5: Missing French Translations for New UI Elements Breaks Consistency

**What goes wrong:**
v1.0 established a complete French UI with ~136 i18n keys in `fr.json`. The v1.1 features will add new UI elements: snippet-related labels (e.g., "Ligne vulnerable," "Contexte du code"), answer key labels (e.g., "Classification attendue," "Points de discussion," "Raisonnement"), and any new section headers. If these new strings are added in English or hardcoded directly in templates, the UI becomes a jarring mix of French and English.

The v1.0 key decision was explicit: "All ~136 keys added upfront in Phase 1. Phases 2-4 only wire templates, never add keys." This pattern should be repeated for v1.1.

**Why it happens:**
Developers add the feature first, verify it works, then plan to "translate later." But with the no-new-dependencies constraint and EJS templates, every hardcoded English string requires a separate pass to extract into `fr.json`. The translation step gets deferred or forgotten.

**How to avoid:**
1. Add ALL new i18n keys to `fr.json` (and `en.json`) BEFORE writing any template code, following the v1.0 pattern
2. New keys needed (estimate):
   - `sca.findingDetail.vulnerableLine` -- "Ligne vulnérable"
   - `sca.findingDetail.codeContext` -- "Contexte du code"
   - `sca.findingDetail.lineNumber` -- "Ligne {n}"
   - `sca.answerKey.title` -- "Clé de réponse"
   - `sca.answerKey.expectedClassification` -- "Classification attendue"
   - `sca.answerKey.reasoning` -- "Raisonnement"
   - `sca.answerKey.discussionPoints` -- "Points de discussion"
   - `sca.answerKey.instructorOnly` -- "Visible uniquement par l'instructeur"
3. Use Quebec French conventions: "ligne vulnerable" not "ligne de code vulnerable," terminology consistent with existing 136 keys
4. Grep all modified EJS files for any raw English string before considering a phase complete

**Warning signs:**
- English strings visible in any student-facing or instructor-facing view
- New `t()` calls in templates that return the key path itself (meaning the key is missing from fr.json)
- i18n fallback warnings in server console: `Translation missing: fr.sca.answerKey.title`

**Phase to address:**
Phase 1 (before template work begins) -- add all keys upfront as the very first task, mirroring v1.0 approach.

---

### Pitfall 6: Code Quality Refactoring Breaks the Smoke Test or Changes Behavior

**What goes wrong:**
The v1.1 milestone includes "AI-driven code quality optimization." The smoke test (`scripts/smoke-test.js`) validates all 13 ports, French content presence, and authenticated student journey. It checks for specific French strings in the HTML responses (e.g., "Connexion"). Refactoring that reorganizes routes, renames files, changes response structure, or alters HTML class names can silently break the smoke test or, worse, change runtime behavior in ways the smoke test does not catch.

The codebase is ~11,800 LOC across 6,870 JS + 4,928 EJS. A broad refactoring pass risks introducing regressions in the custom SQL-to-JSON database adapter (`config/database.js` executeSQL function), which uses string matching on SQL query patterns (e.g., `if (sql.includes('FROM sca_findings'))`). Renaming or restructuring queries can break this brittle adapter.

**Why it happens:**
"Code quality" feels low-risk because you are not changing behavior. But the JSON database adapter is pattern-matched to specific SQL strings, and the smoke test is pattern-matched to specific HTML content. Both are fragile to structural changes.

**How to avoid:**
1. Run `npm test` before and after EVERY refactoring commit -- not just at the end
2. Never refactor the `executeSQL` function in `config/database.js` without understanding that it pattern-matches SQL strings -- any query restructuring needs corresponding adapter updates
3. Refactoring scope should be limited to:
   - Extracting repeated code into functions
   - Consolidating duplicated CSS styles across EJS templates
   - Improving variable naming and code organization
   - NOT restructuring routes, database queries, or response formats
4. Do not refactor and add features in the same commit -- separate concerns make regression tracking possible

**Warning signs:**
- Smoke test failing after a "simple" refactoring change
- Database queries returning `undefined` or empty arrays after query text changes
- EJS template errors after file renames or moves

**Phase to address:**
Phase 4 (Code Quality) -- must be the LAST phase, after all features are complete and tested. Never refactor in parallel with feature work.

---

## Technical Debt Patterns

Shortcuts that seem reasonable but create long-term problems.

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Hardcoding multi-line snippets directly in `seedData.js` | Single source of truth | Destroys student data on reseed; bloats seed file | Never -- use a separate static data module |
| Storing answer key in the finding database record | Simple query, one object | Exposes answer to students if role check is missed; requires DB migration | Never -- use route-level data injection |
| Adding a syntax highlighting library (Prism.js, highlight.js) | Professional code rendering | Violates no-new-dependencies constraint; adds CDN dependency or bundle | Never for v1.1 -- use CSS-only `<pre>` styling |
| Inlining 10-line snippets in student-lab card view | Students see code without navigation | Cards become unusably tall, 12 x 10 lines = 120 lines of code on one page | Never -- show full snippet only on finding-detail page |
| Skipping `en.json` updates when adding `fr.json` keys | Faster -- French is the only active language | English fallback breaks if FR key is missing; future EN toggle becomes impossible | Acceptable for v1.1 IF en.json gets matching keys added simultaneously |

## Integration Gotchas

Common mistakes when connecting new features to the existing system.

| Integration Point | Common Mistake | Correct Approach |
|-------------------|----------------|------------------|
| `localize()` function in `utils/i18n.js` | Trying to localize new fields (snippet context, answer key) through the same overlay mechanism | `localize()` only overlays `title`, `description`, `remediation` (line 95). New fields need either new localize support or should be stored pre-translated in the static data module |
| `DIFFICULTY_MAP` pattern in `routes/sca.js` | Not realizing this is the established pattern for finding-level enrichment | Follow this exact pattern for snippets and answer keys: constant object keyed by finding ID, merged at route handler time |
| Finding detail route rendering | Passing the entire enriched finding object to `res.render()` including instructor-only fields | Conditionally build the template data object based on `user.role` before passing to `res.render()` |
| EJS `<script>` blocks with French strings | Adding new client-side JS that uses English strings instead of EJS-baked constants | Follow the established pattern: `const MSG_FOO = '<%= t("key") %>';` at top of script block (see instructor.ejs line 143) |
| Smoke test French content checks | Adding new French UI elements that the smoke test does not verify | Update smoke test assertions to include new French strings, especially any new section headers visible on the finding-detail page |
| `student-lab.ejs` inline form code snippet | Replacing the 1-line snippet with the full multi-line snippet | Keep 1-line vulnerable-line preview in student-lab cards; full snippet only on finding-detail page |

## Performance Traps

Patterns that work at small scale but fail as usage grows.

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Loading all 12 multi-line snippets into the student-lab page | Page becomes slow on Codespaces where bandwidth is limited | Only load snippets on finding-detail page, not the list view | With 12 x 10-line snippets (1-2KB each), unlikely to be a real problem, but it hurts layout more than performance |
| N+1 lookups if snippet data is stored in DB and queried per-finding | Route handler makes 12 individual queries instead of one | Use static data module (zero DB queries for snippets) | Not applicable if using the recommended static approach |
| Large answer key objects serialized into every instructor page load | Instructor dashboard becomes slow with 12 findings x full reasoning text | Only load answer key data on finding-detail page for instructors, not the overview matrix | At 12 findings this is negligible, but good practice |

## Security Mistakes

Domain-specific security issues beyond general web security.

| Mistake | Risk | Prevention |
|---------|------|------------|
| Answer key data in page source for students | Students see expected answers, defeating the exercise's pedagogical purpose | Route-level role gating: never pass answer key to template for student role |
| SOLUTION-GUIDE.md readable via Codespaces file explorer | Students can open the repo file tree and read the full solution guide | This is a known accepted risk (it is in the repo). The in-app answer key should add value beyond what SOLUTION-GUIDE.md provides (e.g., per-finding inline reasoning, discussion prompts) |
| Code snippets showing real file paths and line numbers | Students could try to navigate to the actual vulnerable file in Codespaces | This is intentional -- the SCA lab is designed to map findings to the real codebase. Not a bug. |
| Refactoring that accidentally fixes a vulnerability used as a teaching example | A code quality pass might "fix" the hardcoded secrets or add input validation, removing the teaching material | Never modify files that contain intentional vulnerabilities during code quality work: `server.js` session secret, `utils/encryption.js` AES key, `routes/auth.js` plaintext comparison, `routes/admin.js` path traversal |

## UX Pitfalls

Common user experience mistakes in this domain.

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Multi-line code snippet without line numbers | Students cannot reference "line 44" when discussing findings with the instructor | Add line numbers as a CSS counter or inline prefix (e.g., `44 | const secret = ...`) in the `<pre>` block |
| Vulnerable line not visually distinct in multi-line context | Students spend time finding the relevant line in a 10-line block | Highlight the vulnerable line with a distinct background color and/or a left-border marker |
| Answer key visible immediately without collapsible toggle | Instructor sees answer before forming their own assessment; clutters the page | Use a `<details><summary>` collapsible element for the answer key, collapsed by default |
| Mixing English security terms with French UI | Students confused by inconsistent language (e.g., "True Positive" button but French description) | Keep security terms that are industry-standard in English (CWE, CVSS, severity levels) but translate pedagogical terms to French (classification labels, instructions, hints) -- this is the v1.0 established pattern |
| Code snippets with no file context | Students see 10 lines of code but do not know what the file does or where these lines sit in the broader file | Add a brief 1-line file description above the snippet (e.g., "server.js -- Configuration principale du serveur Express") |

## "Looks Done But Isn't" Checklist

Things that appear complete but are missing critical pieces.

- [ ] **Inline snippets:** Code renders correctly -- verify it also renders correctly when the snippet contains HTML angle brackets (`<`, `>`), template literals, and single/double quotes
- [ ] **Inline snippets:** Vulnerable line is highlighted -- verify the highlight works when the vulnerable line is the FIRST or LAST line of the snippet (edge cases)
- [ ] **Inline snippets:** Line numbers display -- verify line numbers match the actual file line numbers (not 1-based from snippet start). Finding 1 references line 44 of server.js; the snippet should show lines ~40-48, not lines 1-9
- [ ] **Answer key:** Data is hidden from students -- verify by logging in as `alice_student` and viewing page source on a finding-detail page to confirm no answer key data is present
- [ ] **Answer key:** French translations exist for ALL 12 findings' answer key text -- verify no English leaks through
- [ ] **Answer key:** Each finding has expected classification, reasoning, AND discussion points -- verify none are placeholder or empty
- [ ] **Code quality:** `npm test` passes after refactoring -- run the full smoke test, not just a single page check
- [ ] **Code quality:** Intentional vulnerabilities are preserved -- verify all 12 SCA findings still map to real code (hardcoded secret still hardcoded, plaintext comparison still plaintext, etc.)
- [ ] **Documentation:** README reflects v1.1 features -- verify it mentions inline snippets and answer key, not just the v1.0 feature set
- [ ] **Documentation:** SOLUTION-GUIDE.md is updated if the answer key changes the instructor workflow -- verify the guide references the in-app answer key feature
- [ ] **i18n:** Every new string in every modified EJS file uses `t()` -- grep for raw English strings in modified files
- [ ] **i18n:** `en.json` has matching keys for every new `fr.json` key -- the fallback system needs English equivalents

## Recovery Strategies

When pitfalls occur despite prevention, how to recover.

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Student data lost from accidental reseed | HIGH | No built-in recovery. Must restore from Codespaces backup or git stash of `database/data.json`. Prevention is the only strategy. |
| Answer key exposed to students | MEDIUM | Redeploy with fixed role-gating. Students who already saw the answers may need to be told -- pedagogical impact is moderate since SCA triage is formative, not graded. |
| Broken smoke test after refactoring | LOW | Revert the refactoring commit. Run `npm test` to confirm clean state. Refactor again in smaller increments. |
| XSS in code snippet rendering | MEDIUM | Fix the escaping immediately. Audit all `<%-` usage in SCA templates. The irony of XSS in a security lab will be a teaching moment if handled transparently. |
| English strings leaked into French UI | LOW | Add missing keys to `fr.json`, redeploy. Use `grep -r "TODO\|FIXME\|English" views/sca/` to find remaining issues. |
| Intentional vulnerability accidentally fixed | HIGH | Identify which finding was affected. Revert the specific fix. Verify the seed data still maps to real vulnerable code. Re-run smoke test. |

## Pitfall-to-Phase Mapping

How roadmap phases should address these pitfalls.

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| XSS in snippet rendering | Phase 1 (Snippets) | Test snippet containing `<script>` tags renders as text, not executable HTML |
| Seed data destruction | Phase 1 (Snippets) | Verify `seedData.js` is NOT modified; snippets stored in static module |
| Answer key student exposure | Phase 2 (Answer Key) | Log in as student, view-source on finding-detail page, confirm no answer key data |
| Broken card layout | Phase 1 (Snippets) | Visual check at 1200px and 900px viewport width on student-lab and finding-detail |
| Missing French translations | Phase 1 (before templates) | All new i18n keys added to both fr.json and en.json before any EJS work |
| Smoke test regression | Phase 4 (Code Quality) | `npm test` passes before AND after every refactoring commit |
| Intentional vulns removed | Phase 4 (Code Quality) | Checklist: verify all 12 SCA findings still map to real vulnerable code in the actual codebase files |
| `localize()` not covering new fields | Phase 1 (Snippets) | Verify snippet context labels use `t()` calls, not `localize()` overlay |

## Sources

- Direct codebase analysis: `routes/sca.js`, `views/sca/finding-detail.ejs`, `views/sca/student-lab.ejs`, `views/sca/instructor.ejs`
- Database architecture: `config/database.js` (JSON-file DB with SQL pattern matching)
- Seed data structure: `utils/seedData.js` (12 SCA findings with destructive reseed)
- i18n system: `utils/i18n.js`, `config/translations/fr.json` (~136 keys, `localize()` overlays 3 fields only)
- Existing patterns: `DIFFICULTY_MAP` in `routes/sca.js` (route-level constant enrichment), `SOLUTION-GUIDE.md` (existing instructor reference)
- v1.0 key decisions from `PROJECT.md`: no new dependencies, all i18n keys upfront, localize() overlays title/description/remediation only

---
*Pitfalls research for: v1.1 milestone -- inline snippets, answer key, docs, code quality*
*Researched: 2026-03-12*
