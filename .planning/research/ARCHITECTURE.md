# Architecture Patterns

**Domain:** Integration of inline code snippets, instructor answer key, and code quality improvements into existing SCA lab
**Researched:** 2026-03-12
**Milestone:** v1.1 Polish & Pedagogy
**Confidence:** HIGH (based on direct codebase analysis, no external dependencies)

---

## Executive Summary

The v1.1 features integrate cleanly into the existing Express/EJS architecture with minimal structural changes. The codebase follows a clear pattern: seed data in `utils/seedData.js` feeds a JSON-file DB, routes in `routes/sca.js` query and shape data, EJS templates in `views/sca/` render it, and i18n in `config/translations/fr.json` provides French text via the `t()` helper. All three new features (inline code snippets, instructor answer key, documentation) follow this same flow with zero new dependencies required.

The key architectural insight: the code snippet data already exists in seed data (`code_snippet` field), but it is a single line. Expanding it to 5-10 lines with line-number context and vulnerable-line highlighting is a **data enrichment + template styling** task, not a structural change. The instructor answer key is a **new data layer + new route + new view**, gated behind professor/admin role checks already in place. Code quality is a **refactoring** pass with no user-facing architecture changes.

---

## Current Architecture (As-Is)

### Component Map

```
server.js
  |-- languageMiddleware (utils/i18n.js)    -- sets res.locals.t() and res.locals.currentLang
  |-- routes/sca.js                          -- all SCA endpoints, exports { router, importToVM }
  |     |-- GET /sca                         -- student-lab or instructor dashboard (role-switched)
  |     |-- GET /sca/stats                   -- live polling JSON (instructor only)
  |     |-- GET /sca/findings/:id            -- finding detail (shared, role-aware)
  |     |-- POST /sca/findings/:id/review    -- student submit/save review
  |     |-- GET /sca/student/:studentId      -- instructor: view one student's reviews
  |     |-- POST /sca/import-to-vm/:id       -- instructor: push finding to VM
  |
  |-- views/sca/
  |     |-- student-lab.ejs                  -- card list of 12 findings with inline review forms
  |     |-- finding-detail.ejs               -- full detail page (code, description, form/reviews)
  |     |-- instructor.ejs                   -- findings table, student matrix, stats polling
  |     |-- student-detail.ejs               -- instructor view of one student's reviews
  |
  |-- utils/seedData.js                      -- 12 SCA findings seeded on first boot
  |-- config/database.js                     -- JSON file DB with SQL-like prepare/run/get/all API
  |-- config/translations/fr.json            -- ~136 keys, sca.findings.{id}.{field} for localization
  |-- utils/i18n.js                          -- t(), localize(), languageMiddleware
```

### Data Flow: Finding Detail

```
1. Browser requests GET /sca/findings/1
2. routes/sca.js:139 queries db.sca_findings for id=1
3. localize(finding, lang) overlays French title/description/remediation from fr.json
4. DIFFICULTY_MAP adds difficulty level
5. Template receives: { finding, myReview, allReviews, vmEntry }
6. finding-detail.ejs renders: badges, location, code_snippet, description, hints, form
```

### Existing Code Snippet Handling

The `code_snippet` field in seed data is currently a **single line** of code:
```
"secret: 'university-secret-key-change-in-production'"
```

It renders in `finding-detail.ejs` line 53 as:
```html
<pre style="background:#282c34; color:#abb2bf; padding:1rem; ..."><%= finding.code_snippet %></pre>
```

And in `student-lab.ejs` line 99 as a compact preview:
```html
<pre style="margin:0.5rem 0 0; ..."><%= f.code_snippet %></pre>
```

**No syntax highlighting, no line numbers, no vulnerable-line callout.** This is the primary gap.

---

## Recommended Architecture (To-Be)

### Feature 1: Inline Code Snippets (Enhanced)

**Strategy:** Enrich the seed data `code_snippet` field with multi-line context, add `code_snippet_start_line` and `code_snippet_vuln_line` fields, and use pure CSS for rendering (no new dependencies like highlight.js -- constraint: no new dependencies).

#### Data Layer Changes

**File:** `utils/seedData.js` -- MODIFY the 12 `scaFindings` entries

Add two new fields per finding:
- `code_snippet_start_line` (integer): the starting line number of the snippet
- `code_snippet_vuln_line` (integer): the line within the snippet that contains the vulnerability (1-indexed relative to snippet)

Expand `code_snippet` from one line to 5-10 lines of surrounding context.

**Example for Finding 1 (Hardcoded Session Secret, server.js:44):**
```javascript
[1, 'Hardcoded Session Secret', 'server.js', 44,
  `const startupSecuritySettings = getSecuritySettings();
app.use(session({
  secret: 'university-class-management-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    secure: !!startupSecuritySettings.https_enabled
  }
}));`,
  // code_snippet_start_line: 43, code_snippet_vuln_line: 3
  ...
]
```

**File:** `config/database.js` -- MODIFY the INSERT handler for `sca_findings`

Add storage for the two new fields. The existing handler at line ~577 creates an object from params -- add `code_snippet_start_line` and `code_snippet_vuln_line` as params[12] and params[13] (after `false_positive_reason`).

#### Template Layer Changes

**File:** `views/sca/finding-detail.ejs` -- MODIFY the code snippet section (line 52-53)

Replace the plain `<pre>` with a numbered, highlighted-line code block:

```html
<h3 style="margin-bottom:0.5rem;"><%= t('sca.findingDetail.codeSnippet') %></h3>
<div class="code-block">
  <% const lines = finding.code_snippet.split('\n');
     const startLine = finding.code_snippet_start_line || finding.line_number;
     const vulnLine = finding.code_snippet_vuln_line || 1;
  %>
  <% lines.forEach((line, i) => {
    const lineNum = startLine + i;
    const isVuln = (i + 1) === vulnLine;
  %>
  <div class="code-line <%= isVuln ? 'code-line-vuln' : '' %>">
    <span class="code-line-num"><%= lineNum %></span>
    <span class="code-line-text"><%= line %></span>
  </div>
  <% }) %>
</div>
```

**CSS (add to finding-detail.ejs `<style>` block):**
```css
.code-block {
  background: #282c34;
  border-radius: 6px;
  overflow-x: auto;
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.85rem;
  margin-bottom: 1rem;
}
.code-line {
  display: flex;
  padding: 0 1rem;
  line-height: 1.6;
}
.code-line-num {
  color: #636d83;
  min-width: 3ch;
  text-align: right;
  padding-right: 1rem;
  user-select: none;
  flex-shrink: 0;
}
.code-line-text {
  color: #abb2bf;
  white-space: pre;
}
.code-line-vuln {
  background: rgba(224, 108, 117, 0.15);
  border-left: 3px solid #e06c75;
}
.code-line-vuln .code-line-text {
  color: #e06c75;
  font-weight: 600;
}
```

**File:** `views/sca/student-lab.ejs` -- MODIFY the compact preview (line 97-100)

Keep the existing compact view but show just the vulnerable line (not the full multi-line snippet) for the card preview:

```html
<div style="background:#282c34; border-radius:6px; padding:0.5rem 0.75rem; margin-bottom:0.75rem; overflow-x:auto;">
  <code style="color:#e06c75; font-size:0.8rem; white-space:pre;">
    L<%= f.line_number %>: <%= f.code_snippet.split('\n')[(f.code_snippet_vuln_line || 1) - 1] || f.code_snippet.split('\n')[0] %>
  </code>
</div>
```

#### i18n Impact

**None.** The `sca.findingDetail.codeSnippet` key already exists ("Extrait de code"). No new translation keys needed for this feature.

#### No-New-Dependencies Approach

Pure CSS provides adequate "syntax highlighting" for the pedagogical use case:
- Dark background (#282c34 -- One Dark theme)
- Monospace font
- Red highlight on vulnerable line
- Line numbers

This is sufficient for 5-10 lines of JavaScript. Full syntax highlighting (keyword coloring) would require a library like highlight.js or Prism. That is explicitly out of scope per the "no new dependencies" constraint. If desired later, highlight.js is 100% client-side and could be loaded from a CDN without an npm dependency.

---

### Feature 2: Instructor Answer Key

**Strategy:** Add a new data file `data/sca-answer-key.json` with the 12 expected answers, a new route `GET /sca/answer-key`, and a new view `views/sca/answer-key.ejs`. Gate behind professor/admin role. The data already exists in SOLUTION-GUIDE.md -- this makes it accessible in the UI during live class discussion.

#### Data Layer

**New file:** `data/sca-answer-key.json`

Keep the JSON file minimal -- just classification enums:
```json
{
  "1": { "expectedClassification": "confirmed" },
  "2": { "expectedClassification": "confirmed" },
  "3": { "expectedClassification": "confirmed" },
  "4": { "expectedClassification": "confirmed" },
  "5": { "expectedClassification": "confirmed" },
  "6": { "expectedClassification": "confirmed" },
  "7": { "expectedClassification": "confirmed" },
  "8": { "expectedClassification": "confirmed" },
  "9": { "expectedClassification": "confirmed" },
  "10": { "expectedClassification": "confirmed" },
  "11": { "expectedClassification": "needs_investigation" },
  "12": { "expectedClassification": "confirmed" }
}
```

**Rationale for separate JSON file (not in DB or seed data):**
- The answer key is **instructor-only reference data**, never modified at runtime
- It does not need DB queries, counters, or update handlers
- Keeping it as a static JSON file loaded at startup is consistent with how `config/translations/` files work
- It avoids modifying the database.js handler (which is already complex at ~1100 lines)

**i18n:** All rich text (reasoning, discussion points, common mistakes) lives in the translation files under `sca.answerKey.{id}.*`. This keeps the JSON file small while enabling bilingual content.

Translation keys to add to `fr.json` under `sca.answerKey`:
```json
"answerKey": {
  "title": "Corrige de l'instructeur",
  "subtitle": "Reference pour la discussion en classe -- visible uniquement par l'instructeur",
  "expectedClassification": "Classification attendue",
  "reasoning": "Raisonnement",
  "discussionPoints": "Points de discussion",
  "commonMistakes": "Erreurs frequentes des etudiants",
  "1": {
    "reasoning": "Le secret de session est code en dur dans le code source...",
    "discussionPoints": "Que faudrait-il a un attaquant pour exploiter cela ?|En quoi cela differe entre developpement et production ?",
    "commonMistakes": "Certains etudiants classent comme faux positif pensant que c'est un environnement de developpement."
  },
  ...12 findings...
}
```

This adds ~40 new translation keys (4 structural + 3 per finding).

#### Route Layer

**File:** `routes/sca.js` -- ADD new route

```javascript
// --- GET /sca/answer-key --- Instructor answer key for class discussion
router.get('/answer-key', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const lang = req.session.language || 'fr';
  const findings = db.prepare('SELECT * FROM sca_findings').all();
  const answerKey = require('../data/sca-answer-key.json');

  const enriched = findings.map(f => ({
    ...localize(f, lang),
    difficulty: DIFFICULTY_MAP[f.id] || 'medium',
    expected: answerKey[String(f.id)] || {}
  }));

  res.render('sca/answer-key', {
    title: t(lang, 'sca.answerKey.title'),
    findings: enriched
  });
});
```

**Route conflict analysis:** The new `GET /answer-key` does NOT conflict with `GET /findings/:id` because they have different path prefixes (`/answer-key` vs `/findings/:id`). Safe to add anywhere in the file.

#### View Layer

**New file:** `views/sca/answer-key.ejs`

Layout: A single-page reference showing all 12 findings with:
- Finding title, severity, CWE badge
- Expected classification (color-coded badge)
- Reasoning text from t()
- Discussion points as a bullet list (split on `|` delimiter)
- Common student mistakes callout
- Code snippet (reuse the enhanced multi-line display from Feature 1)

This view is instructor-only. It reuses existing CSS patterns (`.card`, `.badge-sm`, `.sev-*` classes).

#### Navigation

**File:** `views/sca/instructor.ejs` -- ADD a link to the answer key

Add a button/link near the page header:
```html
<a href="/sca/answer-key" style="..." class="btn btn-primary">
  <%= t('sca.answerKey.title') %>
</a>
```

This is visible only on the instructor dashboard (which is already gated to professor/admin roles).

---

### Feature 3: Code Quality Optimization

**Strategy:** Refactoring pass across the codebase with no architecture changes. Focus areas based on code review:

#### Identified Patterns to Improve

1. **Duplicated CSS across EJS views**: The `.sev-Critical`, `.sev-High`, etc. badge styles are copy-pasted in `student-lab.ejs`, `finding-detail.ejs`, `instructor.ejs`, and `student-detail.ejs`. Extract to a `public/css/sca.css` file or into `header.ejs`.

2. **Duplicated difficulty map logic**: `diffColors`/`diffLabel` appear in EJS inline code in both `student-lab.ejs` and `finding-detail.ejs`. The route already computes `difficulty` -- pass the label and color from the route instead.

3. **Inline styles**: Most EJS templates use extensive `style="..."` attributes. While functional, extracting common patterns to CSS classes improves readability. Low-priority polish.

4. **Magic strings**: Classification values (`'confirmed'`, `'false_positive'`, `'needs_investigation'`) appear as string literals in multiple files. Extract to a shared constant.

5. **Route file organization**: `routes/sca.js` is 237 lines and well-organized. Adding the answer-key route keeps it under 280 lines -- still manageable. No need to split.

#### What NOT to Change

- Do not restructure the database layer (config/database.js is 1100+ lines but stable)
- Do not add a build step or CSS preprocessor
- Do not restructure the EJS template hierarchy
- Do not modify the i18n architecture (localize() pattern is clean)

---

## Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `utils/seedData.js` | Seeds 12 SCA findings with enhanced code snippets | `config/database.js` |
| `data/sca-answer-key.json` | Static instructor answer data (classifications) | `routes/sca.js` (require) |
| `config/translations/fr.json` | Answer key reasoning, discussion points (French) | `utils/i18n.js` via t() |
| `config/translations/en.json` | Answer key reasoning, discussion points (English) | `utils/i18n.js` via t() |
| `routes/sca.js` | New `/answer-key` route, enhanced finding data | `views/sca/answer-key.ejs` |
| `views/sca/finding-detail.ejs` | Enhanced code block with line numbers and vuln highlight | receives `finding` from route |
| `views/sca/student-lab.ejs` | Compact vulnerable-line preview in cards | receives `findings` from route |
| `views/sca/answer-key.ejs` | New instructor answer key page | receives `findings` + answer key |
| `views/sca/instructor.ejs` | Link to answer key page | navigates to `/sca/answer-key` |

---

## New vs Modified Files

### New Files (2-3)

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `data/sca-answer-key.json` | 12 expected classifications | ~15 |
| `views/sca/answer-key.ejs` | Instructor answer key view | ~120 |
| `public/css/sca.css` (optional) | Shared SCA styles extracted from EJS | ~60 |

### Modified Files (7)

| File | What Changes | Scope |
|------|-------------|-------|
| `utils/seedData.js` | Expand code_snippet to 5-10 lines, add 2 new fields per finding | Lines 179-251 (data only) |
| `config/database.js` | Handle 2 new fields in sca_findings INSERT | ~3 lines in handler |
| `routes/sca.js` | Add GET /answer-key route | ~20 new lines |
| `views/sca/finding-detail.ejs` | Replace `<pre>` with line-numbered code block | Lines 52-53 become ~20 lines |
| `views/sca/student-lab.ejs` | Update compact snippet to show vuln line | Lines 97-100 become ~8 lines |
| `views/sca/instructor.ejs` | Add answer key link in header | ~3 lines |
| `config/translations/fr.json` | Add ~40 keys for answer key content | Under sca.answerKey.* |

### Unchanged Files

| File | Why Unchanged |
|------|--------------|
| `server.js` | No new routes mounted (answer-key is under /sca router) |
| `utils/i18n.js` | localize() and t() need no changes |
| `middleware/auth.js` | requireAuth unchanged |
| `middleware/rbac.js` | requireRole unchanged |
| `views/partials/header.ejs` | Sidebar already links to /sca |

---

## Data Flow: Enhanced Code Snippet

```
1. Boot: seedData.js inserts finding with multi-line code_snippet,
   code_snippet_start_line=43, code_snippet_vuln_line=3

2. Request: GET /sca/findings/1
   - routes/sca.js fetches finding from DB
   - localize() overlays French title/description/remediation
     (code_snippet stays English -- it is actual source code)
   - Template receives finding with all fields

3. Render: finding-detail.ejs
   - Splits code_snippet by \n
   - Iterates lines with computed line numbers (start_line + index)
   - Applies .code-line-vuln class to the vulnerable line
   - Result: numbered code block with red-highlighted vulnerable line
```

## Data Flow: Answer Key

```
1. Boot: data/sca-answer-key.json loaded once via require()

2. Request: GET /sca/answer-key (professor/admin only)
   - Route loads all 12 findings from DB
   - Merges answer-key data per finding
   - localize() provides French finding text
   - t('sca.answerKey.{id}.reasoning') provides French reasoning
   - Template receives enriched array

3. Render: answer-key.ejs
   - Shows all 12 findings in order
   - Expected classification badge (confirmed/FP/needs investigation)
   - Reasoning, discussion points, common mistakes
   - Code snippet (reuses enhanced rendering)
```

---

## Patterns to Follow

### Pattern 1: Data Enrichment via Seed Data

**What:** Add new fields to existing seed data rather than creating new tables/collections.
**When:** The data is static, pre-determined, and directly associated with existing entities.
**Why:** Avoids adding complexity to the JSON-file DB layer (already 1100+ lines).

```javascript
// In seedData.js -- add fields to existing array entries
[1, 'Hardcoded Session Secret', 'server.js', 44,
  `multi-line\ncode\nsnippet`,     // expanded code_snippet
  'Hardcoded Credentials', 'CWE-798', 'Critical',
  'Description...', 'Semgrep', 'Remediation...', null,
  43,                               // code_snippet_start_line (NEW)
  3                                 // code_snippet_vuln_line (NEW)
]
```

### Pattern 2: Static Reference Data as JSON File

**What:** Instructor-only reference data lives in a standalone JSON file loaded via `require()`.
**When:** Data is read-only, never modified at runtime, small enough to fit in memory.
**Why:** Avoids adding DB handlers, counters, and update logic for data that never changes.

```javascript
// In routes/sca.js
const answerKey = require('../data/sca-answer-key.json');
// Used directly in route handler -- no DB query needed
```

### Pattern 3: Rich Text in Translation Files

**What:** Longer instructional text (reasoning, discussion points) goes into `fr.json` / `en.json`, not into the data file.
**When:** Content needs to be bilingual and is text-heavy.
**Why:** Consistent with existing `sca.findings.{id}.description` pattern. Keeps the data file minimal.

```javascript
// In the EJS template
<%= t('sca.answerKey.' + finding.id + '.reasoning') %>
```

### Pattern 4: CSS-Only Code Rendering

**What:** Line-numbered code blocks with vulnerability highlighting using pure CSS.
**When:** Displaying 5-10 lines of code with a specific line called out.
**Why:** Zero dependencies. Adequate for the pedagogical use case. The dark theme with red highlight provides clear visual contrast.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Adding highlight.js or Prism as a Dependency

**What:** Adding a JS syntax highlighting library for code snippets.
**Why bad:** Violates the "no new dependencies" constraint. Adds complexity for coloring keywords when the pedagogical value is in identifying the vulnerable line, not reading syntax-highlighted code.
**Instead:** Use CSS-only dark theme with vulnerable-line red highlight.

### Anti-Pattern 2: Storing Answer Key in the Database

**What:** Creating a new `sca_answer_key` collection in the JSON DB.
**Why bad:** The answer key is static reference data. Adding it to the DB means adding INSERT/UPDATE/SELECT handlers in `config/database.js` (already 1100+ lines). It would never be modified at runtime.
**Instead:** Use a static JSON file loaded via `require()`.

### Anti-Pattern 3: Making Answer Key Visible to Students

**What:** Showing expected classifications anywhere students can see.
**Why bad:** PROJECT.md explicitly states this is out of scope: "Solution guide visible to students -- instructor references SOLUTION-GUIDE.md during discussion."
**Instead:** Gate behind `requireRole(['admin', 'professor'])` and do not link from student-visible views.

### Anti-Pattern 4: Modifying the localize() Function

**What:** Changing `localize()` to overlay new fields like `code_snippet`.
**Why bad:** `code_snippet` contains actual source code -- it must NOT be translated. The existing `localize()` overlays only `title`, `description`, and `remediation`. Code stays in the original language because it is code.
**Instead:** Leave `localize()` unchanged.

### Anti-Pattern 5: Creating a Separate CSS Build Pipeline

**What:** Adding PostCSS, SCSS, or a bundler to manage duplicated styles.
**Why bad:** Adds build complexity to a project with zero build steps.
**Instead:** If extracting CSS, use a static `public/css/sca.css` file loaded via `<link>` tag.

---

## Suggested Build Order

This ordering is based on dependency analysis:

### Phase 1: Seed Data Enrichment (code snippets)
**Depends on:** Nothing
**Blocks:** Template changes that render multi-line snippets

1. Expand all 12 `code_snippet` values in `utils/seedData.js` to 5-10 lines
2. Add `code_snippet_start_line` and `code_snippet_vuln_line` fields
3. Update `config/database.js` INSERT handler for the 2 new fields
4. Test: restart server, verify findings load correctly via `/sca`

### Phase 2: Enhanced Code Block Templates
**Depends on:** Phase 1 (multi-line data must exist)

1. Add CSS for `.code-block`, `.code-line`, `.code-line-vuln` to `finding-detail.ejs`
2. Replace the `<pre>` tag with the line-numbered code block
3. Update compact preview in `student-lab.ejs`
4. Test: verify all 12 findings render correctly, vuln line is highlighted

### Phase 3: Instructor Answer Key
**Depends on:** Phase 1 (uses enriched finding data), Phase 2 (reuses code block rendering)

1. Create `data/sca-answer-key.json` with 12 classifications
2. Add ~40 translation keys to `fr.json` and `en.json`
3. Add `GET /sca/answer-key` route in `routes/sca.js`
4. Create `views/sca/answer-key.ejs`
5. Add link button on `views/sca/instructor.ejs`
6. Test: access as professor, verify all 12 answers render, verify students cannot access

### Phase 4: Code Quality & Documentation
**Depends on:** Phases 1-3 complete (refactor after features are in)

1. Extract duplicated SCA CSS into shared location
2. Extract classification constants to shared module
3. Update README.md
4. Run smoke test (`npm test`) to verify nothing breaks

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Multi-line code_snippet breaks existing compact preview | Medium | Low | Test student-lab.ejs card rendering after data change |
| Answer key route conflicts with :id param | None | N/A | Routes have distinct prefixes (/answer-key vs /findings/:id) |
| New DB fields break existing queries | Low | Medium | Existing queries use SELECT * so new fields included automatically |
| Code quality refactoring introduces regressions | Low | Medium | Run smoke test after each change; refactor last |
| Translation keys missing for some findings | Low | Low | t() returns the key string as fallback; visually obvious |
| Deleting existing DB required for new seed fields | Low | Medium | Only affects dev -- Codespaces instances rebuild from scratch |

---

## Sources

- Direct codebase analysis of all files listed in the Component Map
- Existing SOLUTION-GUIDE.md section 15 (SCA findings table with expected classifications)
- PROJECT.md v1.1 milestone requirements and constraints
- Confidence: HIGH -- all analysis based on reading the actual codebase, no external research needed
