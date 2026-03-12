# Phase 3: SCA Student Experience - Research

**Researched:** 2026-03-12
**Domain:** EJS template translation, SCA content enrichment, pedagogical scaffolding (intro banner, difficulty badges, contextual hints)
**Confidence:** HIGH

## Summary

Phase 3 transforms the student-facing SCA lab from hardcoded English into a fully French experience with pedagogical enhancements. The work spans four domains: (1) wiring `t()` calls into student-lab.ejs and finding-detail.ejs templates, (2) enriching finding descriptions with business-impact context, (3) adding difficulty indicators with sorted display, and (4) building guided scaffolding (intro banner + per-finding hints).

The codebase is well-prepared. All 136+ SCA translation keys already exist in fr.json (added in Phase 1). The `localize()` function in `utils/i18n.js` overlays French title/description/remediation onto seed data objects. The `toggleForm()` vanilla JS pattern in student-lab.ejs provides a proven expand/collapse mechanism to reuse for hints. The `badge-sm` CSS class with severity color pairs is established.

**Primary recommendation:** Execute in two waves -- first wire translations and localize() into the route handler (the plumbing), then add the three content features (banner, difficulty, hints) which all depend on the translated foundation being in place.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Guided intro banner: Full-width blue info card (#e8f0ff with HEC navy text) at top of student-lab page, between page header and progress card. Dismiss via localStorage. Content uses existing fr.json keys: `sca.guided.introBannerTitle` and `sca.guided.introBannerText`. Dismiss button uses `sca.guided.dismiss` ("Compris").
- Difficulty indicators assigned by vulnerability type: Facile (hardcoded secrets, plaintext comparisons -- findings 1, 2, 3, 4), Moyen (access control, CSRF, IDOR -- findings 6, 7, 8), Avance (config/dependency/session issues -- findings 5, 9, 10, 11, 12). Color-coded badges: green (#e8f8e8/#1e8449) Facile, orange (#fff0e0/#c0732a) Moyen, red (#ffe0e0/#c0392b) Avance. Badge on both student-lab cards AND finding-detail page. List sorted by difficulty: Facile first, then Moyen, then Avance.
- Contextual hints: Collapsible "Besoin d'aide ?" section on finding-detail page only. Placed below description, before remediation. 2-3 guiding analysis questions per finding. Expand/collapse via vanilla JS toggle (consistent with toggleForm pattern).
- Description enrichment: Append 1-2 business impact sentences to existing `sca.findings.X.description` values in fr.json. Frame in THIS university app's context. No separate field -- enrich existing description text directly. English en.json updated in sync.
- Translation wiring: Replace all hardcoded English strings with `t()` calls. Classification dropdown uses `sca.common.truePositive/falsePositive/needsInvestigation`. AJAX feedback uses `sca.common.savedDraft/submittedSuccess/errorSaving/networkError`. Call `localize()` on findings in routes/sca.js before passing to views.

### Claude's Discretion
- Exact difficulty assignment for each of the 12 findings (within the category guidelines above)
- Exact French wording for each finding's 2-3 analysis hint questions
- Exact business impact sentences appended to each description
- Whether to use numbered keys (`sca.findings.X.hint1`) or an array pattern for hints
- Sorting implementation approach (route-level sort vs template-level)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TRAN-02 | SCA student-lab view fully translated to French (progress text, button labels, form fields, AJAX feedback) | All keys exist in fr.json under `sca.studentLab.*` and `sca.common.*`. Replace 20+ hardcoded English strings with `t()` calls. AJAX feedback messages wired via JS-embedded `t()` output. |
| TRAN-03 | SCA finding-detail view fully translated to French (code snippet labels, classification options, notes placeholders) | All keys exist under `sca.findingDetail.*`. Replace ~15 hardcoded strings. Classification dropdown options use `sca.common.truePositive/falsePositive/needsInvestigation`. |
| TRAN-09 | Classification dropdown labels in French | Keys already in fr.json: `sca.common.truePositive` = "Vrai positif", `sca.common.falsePositive` = "Faux positif", `sca.common.needsInvestigation` = "Necessite une investigation". Wire into both student-lab.ejs inline form and finding-detail.ejs form. |
| TRAN-10 | AJAX save/submit feedback messages in French | Keys already in fr.json: `sca.common.savedDraft`, `sca.common.submittedSuccess`, `sca.common.errorSaving`, `sca.common.networkError`. Inject via EJS-rendered JS variables in template script block. |
| SCAC-01 | All 12 finding descriptions enriched with business impact | Append 1-2 sentences to existing `sca.findings.X.description` in both fr.json and en.json. Frame impact in university app context (grades, enrollment, sessions). |
| SCAC-02 | Guided workflow intro banner on student-lab view | New HTML block between page-header and progress card. Uses existing keys `sca.guided.introBannerTitle/introBannerText/dismiss`. localStorage for dismissal persistence. |
| SCAC-03 | Finding difficulty indicators | Difficulty lookup map in route handler. Badge rendering with traffic-light colors. Findings sorted by difficulty before passing to view. |
| SCAC-04 | Contextual hints per finding | New fr.json keys for per-finding hints. Collapsible section in finding-detail.ejs using toggleForm-style JS. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| EJS | existing | Server-side templates | Already used throughout; all views are .ejs |
| Express | existing | HTTP routing | Already wired; routes/sca.js handles all SCA endpoints |
| Vanilla JS | N/A | Client-side interactions | Project constraint: no new dependencies |
| localStorage API | N/A | Banner dismissal persistence | Browser-native; no server round-trip needed |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| utils/i18n.js (custom) | N/A | t() translation + localize() overlay | Every template string replacement and finding localization |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| localStorage for dismiss | Cookie/session | localStorage is simpler, no server involvement, persists across sessions |
| Route-level sort | Template-level sort | Route-level is cleaner -- template just renders in order received |
| Numbered hint keys | Array in JSON | Numbered keys (`hint1`, `hint2`, `hint3`) are simpler with the existing t() function which navigates dot-separated paths; arrays would require t() to return non-string values |

**Installation:**
```bash
# No installation needed -- zero new dependencies (project constraint)
```

## Architecture Patterns

### Files Modified (complete list)

```
config/translations/fr.json     # Enrich descriptions, add per-finding hint keys
config/translations/en.json     # Enrich descriptions in sync, add per-finding hint keys
routes/sca.js                   # localize() calls, difficulty map, sorting
views/sca/student-lab.ejs       # Full t() wiring, intro banner, difficulty badges, sort-aware rendering
views/sca/finding-detail.ejs    # Full t() wiring, difficulty badge, collapsible hints section
```

### Pattern 1: Translation Wiring in EJS
**What:** Replace every hardcoded English string with `<%= t('sca.namespace.key') %>`
**When to use:** Every static text element in templates
**Example:**
```ejs
<!-- BEFORE (hardcoded English) -->
<h1 class="page-title">Static Code Analysis Lab</h1>
<div style="color:#666; font-size:0.9rem;">findings submitted</div>

<!-- AFTER (t() wired) -->
<h1 class="page-title"><%= t('sca.studentLab.title') %></h1>
<div style="color:#666; font-size:0.9rem;"><%= t('sca.studentLab.findingsSubmitted') %></div>
```

### Pattern 2: localize() in Route Handler
**What:** Call `localize()` on each finding before passing to template so `finding.title`, `finding.description`, `finding.remediation` are already French
**When to use:** In the student GET handler (`routes/sca.js:42-60`) before `res.render()`
**Example:**
```javascript
// In routes/sca.js, student branch
const { localize } = require('../utils/i18n');
const lang = req.session.language || 'fr';

// Localize each finding
const localizedFindings = findings.map(f => localize(f, lang));
```

### Pattern 3: Difficulty Lookup Map
**What:** A static object mapping finding IDs to difficulty levels, used in the route handler to attach difficulty to each finding before sorting
**When to use:** In routes/sca.js, before passing findings to views
**Example:**
```javascript
const DIFFICULTY_MAP = {
  1: 'easy', 2: 'easy', 3: 'easy', 4: 'easy',       // Facile
  6: 'medium', 7: 'medium', 8: 'medium',              // Moyen
  5: 'advanced', 9: 'advanced', 10: 'advanced',       // Avance
  11: 'advanced', 12: 'advanced'                        // Avance
};
const DIFFICULTY_ORDER = { easy: 0, medium: 1, advanced: 2 };

// Attach difficulty and sort
const enriched = localizedFindings.map(f => ({
  ...f,
  difficulty: DIFFICULTY_MAP[f.id] || 'medium'
}));
enriched.sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty]);
```

### Pattern 4: localStorage Banner Dismissal
**What:** Check localStorage on page load; if dismissed, hide banner. On dismiss click, set localStorage key.
**When to use:** Intro banner on student-lab page
**Example:**
```html
<% if (user.role === 'student') { %>
<div id="sca-intro-banner" style="background:#e8f0ff; ...">
  <strong><%= t('sca.guided.introBannerTitle') %></strong>
  <p><%= t('sca.guided.introBannerText') %></p>
  <button onclick="dismissBanner()"><%= t('sca.guided.dismiss') %></button>
</div>
<script>
  if (localStorage.getItem('sca-intro-dismissed')) {
    document.getElementById('sca-intro-banner').style.display = 'none';
  }
  function dismissBanner() {
    localStorage.setItem('sca-intro-dismissed', '1');
    document.getElementById('sca-intro-banner').style.display = 'none';
  }
</script>
<% } %>
```

### Pattern 5: AJAX Feedback with Translated Messages
**What:** Embed translated strings as JS variables via EJS, then reference in the saveReview function
**When to use:** student-lab.ejs script block for AJAX feedback
**Example:**
```ejs
<script>
const MSG_SAVING = '<%= t("sca.common.saving") %>';
const MSG_SAVED = '<%= t("sca.common.savedDraft") %>';
const MSG_SUBMITTED = '<%= t("sca.common.submittedSuccess") %>';
const MSG_ERROR = '<%= t("sca.common.errorSaving") %>';
const MSG_NETWORK = '<%= t("sca.common.networkError") %>';

async function saveReview(event, findingId) {
  // ... existing logic ...
  msg.textContent = MSG_SAVING;
  // on success:
  msg.textContent = action === 'submit' ? MSG_SUBMITTED : MSG_SAVED;
  // on error:
  msg.textContent = MSG_ERROR;
  // on catch:
  msg.textContent = MSG_NETWORK;
}
</script>
```

### Pattern 6: Collapsible Hints Section (toggleForm-style)
**What:** A "Besoin d'aide ?" heading that reveals 2-3 guiding questions when clicked
**When to use:** finding-detail.ejs, below description, before remediation
**Example:**
```ejs
<div style="margin-bottom:1rem;">
  <button onclick="toggleHints()" type="button" style="background:none; border:1px solid #dee2e6; ...">
    Besoin d'aide ?
  </button>
  <div id="hints-section" style="display:none; margin-top:0.5rem; ...">
    <ul>
      <li><%= t('sca.findings.' + finding.id + '.hint1') %></li>
      <li><%= t('sca.findings.' + finding.id + '.hint2') %></li>
    </ul>
  </div>
</div>
<script>
function toggleHints() {
  const el = document.getElementById('hints-section');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
</script>
```

### Anti-Patterns to Avoid
- **Do NOT add difficulty to the database schema:** Difficulty is a pedagogical overlay, not persistent data. Use a route-level lookup map. Adding a column would require schema migration and seed data changes for a display-only property.
- **Do NOT use `t()` inside JavaScript string literals without EJS delimiters:** `t()` is server-side only. In `<script>` blocks, embed translations via `<%= t('key') %>` into JS variables, then reference those variables.
- **Do NOT pass raw finding objects without localize():** Templates must receive already-localized findings. Otherwise, French descriptions only appear if the template calls `t()` for every field, duplicating logic.
- **Do NOT create separate hint files:** All hint text belongs in fr.json/en.json alongside existing finding translations. Keep the single-source-of-truth pattern.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation lookups | Custom string mapping | `t('key')` via res.locals.t | Already wired via languageMiddleware; handles fallback to English |
| Finding text overlay | Per-field conditionals in template | `localize(finding, lang)` | Handles title/description/remediation in one call with fallback |
| Expand/collapse UI | Custom animation/transition library | `toggleForm()`-style display toggle | Proven pattern already in student-lab.ejs; zero dependencies |
| Persistent dismissal | Server-side cookie tracking | `localStorage.setItem/getItem` | Browser-native; survives page reloads; no server state needed |

**Key insight:** Every mechanism needed for this phase already exists in the codebase. The work is wiring, content authoring, and minor HTML additions -- not building new infrastructure.

## Common Pitfalls

### Pitfall 1: t() Key Typos Silently Return the Key String
**What goes wrong:** A misspelled key like `sca.studentLab.titl` returns the literal string "sca.studentLab.titl" instead of the translation, without crashing.
**Why it happens:** The i18n.js `t()` function returns the key itself when not found, logging only a `console.warn`.
**How to avoid:** After wiring, visually inspect every page in the browser. Every visible `sca.` prefix in the rendered page indicates a broken key.
**Warning signs:** Dot-separated text visible in the rendered HTML.

### Pitfall 2: Forgetting to localize() Findings Before Passing to Template
**What goes wrong:** The student-lab.ejs loops over `findings` and displays `f.title` and `f.description` -- if findings are not localized, they show English seed data text.
**Why it happens:** localize() must be explicitly called in the route handler; the middleware does not auto-localize.
**How to avoid:** Call `localize()` on every finding in the student GET handler (`/sca` route) AND the finding-detail GET handler (`/sca/findings/:id`). Verify both paths.
**Warning signs:** Titles/descriptions still in English even though other strings (labels, buttons) are in French.

### Pitfall 3: AJAX Feedback Messages Still in English
**What goes wrong:** The inline `saveReview()` function in student-lab.ejs has hardcoded English strings like `'Draft saved.'` and `'Network error'`.
**Why it happens:** JavaScript runs client-side, so `t()` is not directly available. Developers wire the HTML but forget the JS.
**How to avoid:** Embed translations as JS constants at the top of the `<script>` block using EJS delimiters: `const MSG = '<%= t("key") %>'`.
**Warning signs:** Form labels are French but save/submit feedback flashes English.

### Pitfall 4: finding-detail.ejs Title Uses `finding.title` Directly
**What goes wrong:** The page header at `<h1><%= finding.title %></h1>` shows the English seed data title.
**Why it happens:** The `title` variable passed to `res.render()` in routes/sca.js is also set from the raw English `finding.title`.
**How to avoid:** In routes/sca.js finding-detail handler, localize the finding BEFORE constructing the render title: `const localized = localize(finding, lang); res.render('...', { finding: localized, title: localized.title })`.
**Warning signs:** Page title and `<h1>` show English while other labels are French.

### Pitfall 5: Difficulty Sort Breaks reviewMap Lookup
**What goes wrong:** After sorting findings by difficulty, the findings display in new order but reviewMap lookups still work (they're keyed by ID), so this is actually safe. BUT if sorting mutates the original array from the database query, it could affect subsequent requests in edge cases.
**Why it happens:** JavaScript array.sort() mutates in place.
**How to avoid:** Create a new array (`[...findings]` or `.map()`) before sorting. Do not sort the original DB result array.
**Warning signs:** Inconsistent finding order across page loads (unlikely with in-memory DB but defensive coding matters).

### Pitfall 6: en.json and fr.json Out of Sync After Enrichment
**What goes wrong:** Descriptions are enriched in fr.json but en.json keeps the old short text. If a student switches to English (future feature) or the fallback triggers, they see incomplete descriptions.
**Why it happens:** The CONTEXT.md explicitly says to update en.json in sync, but it's easy to forget.
**How to avoid:** Treat fr.json and en.json as a pair. Every description edit in fr.json gets a corresponding en.json edit.
**Warning signs:** `console.warn` messages from localize() about missing translations.

## Code Examples

### Complete Difficulty Badge Rendering (student-lab.ejs)
```ejs
<%
  const diffColors = {
    easy: { bg: '#e8f8e8', color: '#1e8449' },
    medium: { bg: '#fff0e0', color: '#c0732a' },
    advanced: { bg: '#ffe0e0', color: '#c0392b' }
  };
  const diffLabel = {
    easy: t('sca.difficulty.easy'),
    medium: t('sca.difficulty.medium'),
    advanced: t('sca.difficulty.advanced')
  };
%>
<span class="badge-sm" style="background:<%= diffColors[f.difficulty].bg %>; color:<%= diffColors[f.difficulty].color %>;">
  <%= diffLabel[f.difficulty] %>
</span>
```

### Complete Route Handler Modification (routes/sca.js student branch)
```javascript
const { localize } = require('../utils/i18n');

const DIFFICULTY_MAP = {
  1: 'easy', 2: 'easy', 3: 'easy', 4: 'easy',
  6: 'medium', 7: 'medium', 8: 'medium',
  5: 'advanced', 9: 'advanced', 10: 'advanced',
  11: 'advanced', 12: 'advanced'
};
const DIFFICULTY_ORDER = { easy: 0, medium: 1, advanced: 2 };

// Inside student branch of GET /sca:
const lang = req.session.language || 'fr';
const enriched = findings.map(f => ({
  ...localize(f, lang),
  difficulty: DIFFICULTY_MAP[f.id] || 'medium'
}));
enriched.sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty]);

return res.render('sca/student-lab', {
  title: t(lang, 'sca.studentLab.title'),
  findings: enriched,
  reviewMap,
  submitted,
  total: findings.length
});
```

### Hint Key Structure in fr.json
```json
{
  "sca": {
    "findings": {
      "1": {
        "title": "Secret de session code en dur",
        "description": "Le secret de session Express est code en dur... Dans cette application, cela pourrait...",
        "remediation": "Deplacez le secret...",
        "hint1": "Que se passe-t-il si un attaquant accede au code source ?",
        "hint2": "Cette valeur devrait-elle etre dans le code ou dans l'environnement ?",
        "hint3": "Quel type de donnees un attaquant pourrait-il falsifier avec ce secret ?"
      }
    }
  }
}
```

### Student-Lab Button Label Translation
```ejs
<!-- Three states: not started, draft, submitted -->
<button onclick="toggleForm(<%= f.id %>)" style="...">
  <%= isDone ? t('sca.studentLab.viewEdit') : review ? t('sca.studentLab.continueReview') : t('sca.studentLab.startReview') %>
</button>
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in templates | t() calls with fr.json/en.json | Phase 1 (2026-03-12) | All keys pre-created; Phase 3 wires them |
| Raw seed data in views | localize() overlay | Phase 1 (2026-03-12) | Route handlers must call localize() before render |
| No difficulty metadata | Route-level difficulty map | Phase 3 (this phase) | Findings get difficulty badge + sorted display |
| No pedagogical scaffolding | Banner + hints | Phase 3 (this phase) | Students get guided analysis support |

## Open Questions

1. **Exact hint content for all 12 findings**
   - What we know: 2-3 guiding questions per finding, in French, that steer thinking without giving the answer
   - What's unclear: The exact wording -- this is a content authoring task
   - Recommendation: Author during implementation; use Claude's discretion per CONTEXT.md

2. **Exact business impact sentences for all 12 descriptions**
   - What we know: 1-2 sentences per finding framed as "Dans cette application..."
   - What's unclear: Exact wording
   - Recommendation: Author during implementation; update both fr.json and en.json

3. **Numbered keys vs array for hints**
   - What we know: t() navigates dot-separated paths and returns strings; it can also return objects
   - What's unclear: Whether t() returning an object (array) causes issues in EJS
   - Recommendation: Use numbered keys (`hint1`, `hint2`, `hint3`) -- simpler, proven with existing t() function, avoids edge cases with non-string returns. The template iterates over known key suffixes.

## Sources

### Primary (HIGH confidence)
- `config/translations/fr.json` -- verified all SCA keys exist (sca.studentLab.*, sca.findingDetail.*, sca.common.*, sca.guided.*, sca.difficulty.*, sca.findings.1-12.*)
- `config/translations/en.json` -- verified matching English key structure
- `utils/i18n.js` -- verified t() function signature, localize() fields (title, description, remediation), languageMiddleware
- `routes/sca.js` -- verified student GET handler (lines 42-60), finding-detail handler (lines 90-117), review POST handler (lines 120-154)
- `views/sca/student-lab.ejs` -- verified all 20+ hardcoded English strings, toggleForm() pattern, AJAX saveReview() function
- `views/sca/finding-detail.ejs` -- verified all ~15 hardcoded English strings, form structure, VM import section
- `utils/seedData.js` -- verified all 12 finding structures with severity levels for difficulty mapping
- `config/database.js` -- verified sca_findings schema (no difficulty column -- confirms lookup map approach)
- `views/partials/header.ejs` -- verified t() usage pattern, lang="fr" attribute

### Secondary (MEDIUM confidence)
- None needed -- all findings from direct codebase inspection

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - zero new dependencies; all tools already in codebase
- Architecture: HIGH - patterns verified from existing Phase 1/2 implementations and direct code inspection
- Pitfalls: HIGH - derived from actual code inspection of the exact files being modified
- Content authoring: MEDIUM - exact French wording for 12 x hints + 12 x business impact sentences is a creative task, not a technical one

**Research date:** 2026-03-12
**Valid until:** 2026-04-12 (stable -- internal project, no external dependency changes)
