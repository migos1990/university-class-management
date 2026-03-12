# Phase 4: SCA Instructor Experience - Research

**Researched:** 2026-03-12
**Domain:** EJS template translation wiring, JSON polling endpoint, inline JS i18n
**Confidence:** HIGH

## Summary

Phase 4 translates two EJS templates (instructor.ejs, student-detail.ejs) from hardcoded English to French via `t()` calls, adds `localize()` calls on finding objects in two route handlers, and builds a new `/sca/stats` JSON endpoint with 30-second client-side polling for live class progress stats. All 27+ translation keys already exist in fr.json under `sca.instructor.*` and `sca.studentDetail.*`. No new npm dependencies are needed.

The work is entirely additive -- replacing English string literals with `t('key')` calls in EJS, adding `localize(finding, lang)` calls in the route layer so finding titles render in French, and inserting a stat-card bar with vanilla JS `setInterval` + `fetch()` polling. The patterns are identical to what was done in Phase 3 for student-lab.ejs and finding-detail.ejs, making this phase highly predictable.

**Primary recommendation:** Follow the exact same translation wiring pattern used in Phase 3 (EJS `t()` calls, EJS-embedded JS constants for client-side strings, `localize()` in route handler), and add the stats endpoint as a lightweight Express route returning JSON from existing database queries.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Progress stats design: Horizontal row of 3 stat cards above the Findings Overview table (top of page, first thing instructor sees). Big bold number with small label below each card. White card background with HEC navy (#002855) text. No icons or emoji -- minimal, scannable. Three stats: students started, average completion %, submissions per 5 minutes (pace).
- Auto-refresh behavior: 30-second polling interval via setInterval. Stats bar only refreshes -- findings table and student matrix stay static until page reload. Dedicated JSON endpoint: GET /sca/stats returning {studentsStarted, totalStudents, avgCompletion, pace}. Small "Mis a jour : HH:MM:SS" timestamp below the stats bar. Vanilla JS fetch() for the AJAX call -- no new dependencies.
- Class pace definition: "Rythme global" = count of submissions in the last 5 minutes. Displayed as "X soumissions / 5 min". No directional trend indicator. "Students started" = students with at least 1 review record (any status). "Average completion" = mean of (submitted reviews / total findings) across all students, as percentage.
- Instructor finding localization: Call localize() on findings in the instructor route handler before passing to instructor.ejs. Call localize() on findings in the student-detail route handler before passing to student-detail.ejs. Severity badges stay English.
- VM action translations: Translate confirm() dialog, button states, and error alert messages. All keys already exist in fr.json under sca.instructor.*.
- Translation wiring: Replace all hardcoded English strings in instructor.ejs and student-detail.ejs with t() calls. Use existing fr.json keys. Classification badges use sca.common.* keys.

### Claude's Discretion
- Exact stat card spacing, padding, and font sizes
- Whether the stats endpoint shares query logic with the main instructor route or has its own optimized queries
- Exact French wording for the confirm() dialog and alert messages if keys need adjustment
- How to pass t() translations to client-side JS for the confirm/alert/button text (inline script variables or data attributes)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TRAN-04 | SCA instructor dashboard fully translated to French (table headers, matrix labels, import buttons) | 17 keys at `sca.instructor.*` already exist in fr.json; wire with `<%= t('sca.instructor.keyName') %>` in instructor.ejs; localize() findings for French titles |
| TRAN-05 | SCA student-detail view fully translated to French | 10 keys at `sca.studentDetail.*` already exist in fr.json; wire with `<%= t('sca.studentDetail.keyName') %>` in student-detail.ejs; localize() findings for French titles |
| INST-01 | Live class progress stats on SCA instructor view (students started, average completion %, pace) | New GET /sca/stats endpoint returning JSON; 3 stat cards with polling; keys at sca.instructor.studentsStarted/avgCompletion/overallPace exist |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express.js | existing | Route handler for /sca/stats | Already in project |
| EJS | existing | Template rendering with t() calls | Already in project |
| better-sqlite3 | existing | Database queries for stats | Already in project |
| Vanilla JS fetch() | native | Client-side polling | No new dependencies per project constraint |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| utils/i18n.js (t) | project util | Translation key lookup | Every hardcoded English string in templates |
| utils/i18n.js (localize) | project util | French title/description/remediation overlay on finding objects | Instructor route + student-detail route |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| setInterval polling | WebSocket / SSE | WebSocket explicitly out of scope per REQUIREMENTS.md; polling at 30s is sufficient |
| Vanilla fetch() | htmx / axios | No new dependencies constraint; vanilla fetch is already used in student-lab.ejs |

**Installation:**
```bash
# No installation needed -- all tools already in the project
```

## Architecture Patterns

### Recommended Project Structure
```
routes/sca.js               # Add localize() calls + new /sca/stats route
views/sca/instructor.ejs     # Replace English strings with t() calls, add stats bar + polling JS
views/sca/student-detail.ejs # Replace English strings with t() calls
```

### Pattern 1: EJS Translation Wiring (t() calls)
**What:** Replace every hardcoded English string in an EJS template with `<%= t('sca.section.key') %>`
**When to use:** Every static text element -- headings, labels, table headers, button text, tooltips
**Example (from student-lab.ejs, established in Phase 3):**
```ejs
<!-- BEFORE (hardcoded English) -->
<h1 class="page-title">Static Code Analysis - Instructor Dashboard</h1>
<th>Title</th>
<th>Severity</th>

<!-- AFTER (translated) -->
<h1 class="page-title"><%= t('sca.instructor.title') %></h1>
<th><%= t('sca.instructor.finding') %></th>
<th><%= t('sca.instructor.severity') %></th>
```

### Pattern 2: Client-Side Translation Constants (EJS-embedded JS)
**What:** Declare JS constants in an inline `<script>` block using EJS `<%= t() %>` to bake translated strings into client JS
**When to use:** When client-side JS needs translated strings (confirm dialogs, button state changes, error alerts)
**Example (from student-lab.ejs, established in Phase 3):**
```ejs
<script>
const MSG_CONFIRM_IMPORT = '<%= t("sca.instructor.confirmImport") %>';
const MSG_IMPORTING = '<%= t("sca.instructor.importing") %>';
const MSG_IN_VM = '<%= t("sca.instructor.inVM") %>';
const MSG_PUSH_VM = '<%= t("sca.instructor.pushToVM") %>';
const MSG_NETWORK_ERROR = '<%= t("sca.common.networkError") %>';
const MSG_IMPORT_FAILED = '<%= t("sca.common.errorSaving") %>';

async function importToVM(findingId, btn) {
  if (!confirm(MSG_CONFIRM_IMPORT)) return;
  btn.disabled = true;
  btn.textContent = MSG_IMPORTING;
  // ...
}
</script>
```

### Pattern 3: Route-Level localize() for Finding Objects
**What:** Call `localize(finding, lang)` on each finding before passing to EJS template
**When to use:** When template displays finding titles, descriptions, or remediation that need French overlay
**Example (from the student GET handler in routes/sca.js, established in Phase 3):**
```javascript
// In instructor GET handler (routes/sca.js ~line 77-101)
const lang = req.session.language || 'fr';
const localizedFindings = findings.map(f => localize(f, lang));
// Pass localizedFindings to template instead of raw findings

// In student-detail GET handler (routes/sca.js ~line 176-192)
const lang = req.session.language || 'fr';
const localizedFindings = findings.map(f => localize(f, lang));
// Pass localizedFindings to template instead of raw findings
```

### Pattern 4: JSON Stats Endpoint with Polling
**What:** New GET /sca/stats route returning JSON for client-side polling
**When to use:** INST-01 live class progress stats
**Example:**
```javascript
// Route: GET /sca/stats
router.get('/stats', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const findings = db.prepare('SELECT COUNT(*) as count FROM sca_findings').get();
  const totalFindings = findings.count;
  const students = db.prepare("SELECT * FROM users WHERE role = 'student'").all();
  const totalStudents = students.length;

  // Students started: those with at least 1 review record (any status)
  const studentsStarted = db.prepare(
    "SELECT COUNT(DISTINCT student_id) as count FROM sca_student_reviews"
  ).get().count;

  // Average completion: mean of (submitted / totalFindings) per student
  const submittedPerStudent = db.prepare(`
    SELECT student_id, COUNT(*) as cnt
    FROM sca_student_reviews WHERE status = 'submitted'
    GROUP BY student_id
  `).all();
  let avgCompletion = 0;
  if (totalStudents > 0 && totalFindings > 0) {
    const totalPct = submittedPerStudent.reduce((sum, s) => sum + (s.cnt / totalFindings), 0);
    // Mean across ALL students (not just those who started)
    avgCompletion = Math.round((totalPct / totalStudents) * 100);
  }

  // Pace: submissions in last 5 minutes
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  const pace = db.prepare(
    "SELECT COUNT(*) as count FROM sca_student_reviews WHERE submitted_at >= ?"
  ).get(fiveMinAgo).count;

  res.json({ studentsStarted, totalStudents, avgCompletion, pace });
});
```

### Pattern 5: setInterval Polling with Timestamp
**What:** Client-side JS that polls the stats endpoint every 30s and updates the DOM
**When to use:** Stats bar auto-refresh
**Example:**
```javascript
async function refreshStats() {
  try {
    const res = await fetch('/sca/stats');
    const data = await res.json();
    document.getElementById('stat-started').textContent = data.studentsStarted + '/' + data.totalStudents;
    document.getElementById('stat-completion').textContent = data.avgCompletion + '%';
    document.getElementById('stat-pace').textContent = data.pace;
    document.getElementById('stats-timestamp').textContent =
      'Mis \u00e0 jour : ' + new Date().toLocaleTimeString('fr-CA', { hour12: false });
  } catch (e) {
    // Silently fail -- stats will refresh on next interval
  }
}
refreshStats(); // Initial load
setInterval(refreshStats, 30000);
```

### Anti-Patterns to Avoid
- **Forgetting to pass `lang` to localize():** Always get lang from `req.session.language || 'fr'` in the route handler, never hardcode 'fr'
- **Translating severity badges:** Severity stays English per Phase 1 decision -- do NOT translate "Critical", "High", etc.
- **Using t() in client JS directly:** The t() function is server-side only. Use EJS-embedded JS constants (Pattern 2) to bridge the gap
- **Mutating original findings array:** Use `.map()` to create new localized copies, never modify the DB result objects directly
- **Adding new fr.json keys:** All keys were pre-loaded in Phase 1. If a key appears missing, check sca.instructor.* and sca.studentDetail.* -- it is almost certainly already there

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation lookup | Custom string replacement | `t('sca.instructor.key')` | Already works, tested in 3 phases |
| Finding localization | Manual field-by-field overlay | `localize(finding, lang)` | Handles title/description/remediation with fallback |
| Client-side French strings | Runtime i18n library | EJS-embedded JS constants | Pattern established in Phase 3, zero dependencies |

**Key insight:** Everything needed for this phase already exists in the codebase. The task is purely wiring -- connecting existing infrastructure (t(), localize(), fr.json keys) to two templates that still have hardcoded English, plus a straightforward new JSON endpoint.

## Common Pitfalls

### Pitfall 1: Missing t() Calls in Dynamic Content
**What goes wrong:** Static labels get translated but dynamically computed strings (like "18/30 submitted") remain English
**Why it happens:** Easy to overlook strings assembled in EJS scriptlets rather than appearing as plain HTML text
**How to avoid:** Audit every `<%=` expression in instructor.ejs and student-detail.ejs; if it outputs text a human reads, it needs translation
**Warning signs:** Mixed French/English on the page; English words "submitted", "confirmed", "FP", "Not started", "View" still visible

### Pitfall 2: Stats Endpoint Returning Wrong Pace Count
**What goes wrong:** Pace always shows 0 because submitted_at is NULL for draft saves
**Why it happens:** Only reviews with `action === 'submit'` get a `submitted_at` timestamp; drafts have NULL
**How to avoid:** The SQL for pace must filter on `submitted_at IS NOT NULL AND submitted_at >= ?` (the 5-minute window)
**Warning signs:** Pace reads 0 even after students are actively submitting

### Pitfall 3: confirm() Dialog Shows Key Instead of French Text
**What goes wrong:** Client-side `confirm()` shows a raw key string like "sca.instructor.confirmImport" instead of French text
**Why it happens:** Using `t()` directly in the `<script>` block instead of through EJS interpolation, or the key doesn't exist
**How to avoid:** Use the EJS-embedded JS constants pattern (Pattern 2); verify key exists in fr.json first
**Warning signs:** Alert/confirm boxes show dot-separated key paths

### Pitfall 4: localize() Called After Template Render
**What goes wrong:** Template receives raw English finding titles despite localize() existing
**Why it happens:** localize() was called but the original (unlocalized) findings array was passed to `res.render()`
**How to avoid:** Assign localized result to a new variable and pass THAT to render; double-check the variable name in the `res.render()` call
**Warning signs:** Finding titles still in English while all other labels are in French

### Pitfall 5: Stats Polling Continues After Navigating Away
**What goes wrong:** Console errors from fetch() calls after instructor navigates to student-detail page
**Why it happens:** setInterval is never cleared
**How to avoid:** This is minor and acceptable for this use case. The interval will be garbage-collected on page navigation in a traditional (non-SPA) app. No action needed.

### Pitfall 6: Classification Badge Translation Inconsistency
**What goes wrong:** Classification labels like "confirmed", "false_positive", "needs_investigation" displayed raw from DB
**Why it happens:** The raw database values are used directly in badges without mapping through t()
**How to avoid:** Map classification values through sca.common.* keys: confirmed -> sca.common.truePositive, false_positive -> sca.common.falsePositive, needs_investigation -> sca.common.needsInvestigation
**Warning signs:** Student-detail table shows "confirmed" or "false_positive" instead of "Vrai positif" or "Faux positif"

## Code Examples

### Example 1: instructor.ejs Stats Bar HTML
```ejs
<!-- Stats bar: 3 cards above Findings Overview -->
<div style="display:flex; gap:1.5rem; margin-bottom:1.5rem; flex-wrap:wrap;">
  <div class="card" style="flex:1; min-width:180px; text-align:center; padding:1.25rem;">
    <div id="stat-started" style="font-size:2.2rem; font-weight:700; color:#002855;">0/0</div>
    <div style="color:#666; font-size:0.85rem; margin-top:0.25rem;"><%= t('sca.instructor.studentsStarted') %></div>
  </div>
  <div class="card" style="flex:1; min-width:180px; text-align:center; padding:1.25rem;">
    <div id="stat-completion" style="font-size:2.2rem; font-weight:700; color:#002855;">0%</div>
    <div style="color:#666; font-size:0.85rem; margin-top:0.25rem;"><%= t('sca.instructor.avgCompletion') %></div>
  </div>
  <div class="card" style="flex:1; min-width:180px; text-align:center; padding:1.25rem;">
    <div id="stat-pace" style="font-size:2.2rem; font-weight:700; color:#002855;">0</div>
    <div style="color:#666; font-size:0.85rem; margin-top:0.25rem;"><%= t('sca.instructor.overallPace') %></div>
  </div>
</div>
<div id="stats-timestamp" style="text-align:right; font-size:0.75rem; color:#999; margin-top:-1rem; margin-bottom:1rem;"></div>
```

### Example 2: instructor.ejs Translated Table Headers
```ejs
<thead>
  <tr>
    <th>#</th>
    <th><%= t('sca.instructor.finding') %></th>
    <th><%= t('sca.instructor.file') %></th>
    <th><%= t('sca.instructor.severity') %></th>
    <th>CWE</th>
    <th><%= t('sca.instructor.reviews') %></th>
    <th><%= t('sca.instructor.vm') %></th>
  </tr>
</thead>
```

### Example 3: student-detail.ejs Translation Wiring
```ejs
<div class="page-header">
  <div style="display:flex; align-items:center; gap:1rem; flex-wrap:wrap;">
    <a href="/sca" style="color:#666; text-decoration:none; font-size:0.9rem;">&larr; <%= t('sca.studentDetail.backToDashboard') %></a>
    <h1 class="page-title" style="margin:0;"><%= t('sca.studentDetail.reviewsTitle', { username: student.username }) %></h1>
  </div>
</div>
```

### Example 4: Classification Badge Mapping in student-detail.ejs
```ejs
<% if (r) { %>
  <%
    const clsLabel = r.classification === 'confirmed' ? t('sca.common.truePositive')
      : r.classification === 'false_positive' ? t('sca.common.falsePositive')
      : t('sca.common.needsInvestigation');
    const clsClass = r.classification === 'needs_investigation' ? 'needs' : r.classification;
  %>
  <span class="badge-sm cls-<%= clsClass %>"><%= clsLabel %></span>
<% } else { %>
  <span class="badge-sm cls-none"><%= t('sca.studentDetail.notStarted') %></span>
<% } %>
```

### Example 5: Route Handler with localize() (instructor)
```javascript
// In the instructor branch of GET /sca (routes/sca.js ~line 77-101)
const lang = req.session.language || 'fr';
const localizedFindings = findings.map(f => localize(f, lang));

res.render('sca/instructor', {
  title: t(lang, 'sca.instructor.title'),
  findings: localizedFindings,  // <-- localized, not raw
  students,
  matrix,
  importedIds,
  allReviews
});
```

## Translation Key Inventory

All keys verified present in fr.json:

### sca.instructor.* (17 keys)
| Key | French Value | Used In |
|-----|-------------|---------|
| title | "Analyse de code statique -- Tableau de bord instructeur" | Page title |
| findingsOverview | "Apercu des constats" | Section heading |
| studentProgressMatrix | "Matrice de progression des etudiants" | Section heading |
| finding | "Constat" | Table header |
| file | "Fichier" | Table header |
| severity | "Severite" | Table header |
| reviews | "Analyses" | Table header |
| vm | "GV" | Table header |
| submitted | "soumis" | Review count label |
| confirmed | "confirme" | Badge text |
| fp | "FP" | Badge text |
| inVM | "Dans GV" | Button state |
| pushToVM | "Envoyer au GV" | Button label |
| importing | "Importation..." | Button loading state |
| student | "Etudiant" | Matrix header |
| classProgress | "Progression de la classe" | Stats section |
| studentsStarted | "Etudiants ayant commence" | Stat card label |
| avgCompletion | "Completion moyenne" | Stat card label |
| overallPace | "Rythme global" | Stat card label |

### sca.studentDetail.* (10 keys)
| Key | French Value | Used In |
|-----|-------------|---------|
| backToDashboard | "Tableau de bord ACS" | Back link |
| reviewsTitle | "Analyses ACS : {username}" | Page title (interpolated) |
| student | "Etudiant" | Label |
| reviewsSubmitted | "Analyses soumises" | Label |
| finding | "Constat" | Table header |
| severity | "Severite" | Table header |
| classification | "Classification" | Table header |
| status | "Statut" | Table header |
| notes | "Notes" | Table header |
| notStarted | "Non commence" | Badge text |
| view | "Voir" | Details expand label |

### sca.common.* (used for classification labels)
| Key | French Value | Used In |
|-----|-------------|---------|
| truePositive | "Vrai positif" | Classification badge |
| falsePositive | "Faux positif" | Classification badge |
| needsInvestigation | "Necessite une investigation" | Classification badge |
| networkError | "Erreur reseau -- veuillez reessayer." | Import error alert |

### Keys That May Need Addition
The confirm dialog key (`sca.instructor.confirmImport` or similar, e.g., "Envoyer ce constat au gestionnaire de vulnerabilites ?") and the import failure message are not explicitly listed in the current fr.json. The CONTEXT.md says "All keys already exist in fr.json under sca.instructor.*" but the current JSON shows no `confirmImport` or `importFailed` key. Two options:

1. Use existing keys creatively: `sca.common.networkError` for network errors, construct confirm text from existing keys
2. Add 2-3 small keys if needed: `sca.instructor.confirmImport`, `sca.instructor.importFailed`

**Recommendation:** Check the exact keys at implementation time. If missing, add them to fr.json -- this is a trivial addition and consistent with the additive-only principle.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in EJS | t() calls with fr.json keys | Phase 1-3 | Consistent French UI |
| Raw finding objects | localize() overlay | Phase 3 | French titles/descriptions |
| Full page reload for data | setInterval + fetch JSON | New in Phase 4 | Live stats without reload |

**No deprecated approaches in play** -- this phase uses the exact same patterns established in Phases 1-3.

## Open Questions

1. **Confirm dialog exact key name**
   - What we know: CONTEXT.md says the key exists under sca.instructor.*, but no `confirmImport` key is visible in current fr.json
   - What's unclear: Whether the key was added but not included in the file I read, or needs to be added
   - Recommendation: At implementation time, if key is missing, add `sca.instructor.confirmImport: "Envoyer ce constat au gestionnaire de vulnerabilites ?"` and `sca.instructor.importFailed: "Echec de l'importation"` to fr.json

2. **Average completion denominator**
   - What we know: CONTEXT.md says "mean of (submitted reviews / total findings) across all students"
   - What's unclear: "All students" means all enrolled students (from users table WHERE role='student') or only those who started
   - Recommendation: Use ALL students (including those who haven't started), matching the denominator interpretation that gives the instructor the truest picture of class progress. A student who hasn't started has 0% completion.

## Sources

### Primary (HIGH confidence)
- `config/translations/fr.json` - Direct inspection of all 27+ keys under sca.instructor.* and sca.studentDetail.*
- `routes/sca.js` - Direct inspection of instructor GET handler (lines 77-101) and student-detail GET handler (lines 176-192)
- `views/sca/instructor.ejs` - Direct inspection of all 148 lines, identified every hardcoded English string
- `views/sca/student-detail.ejs` - Direct inspection of all 79 lines, identified every hardcoded English string
- `utils/i18n.js` - Direct inspection of t(), localize(), and languageMiddleware functions
- `views/sca/student-lab.ejs` - Reference pattern for EJS-embedded JS constants and AJAX fetch

### Secondary (MEDIUM confidence)
- CONTEXT.md Phase 4 decisions - User-confirmed design choices

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - No new libraries, all tools already in project and verified by inspection
- Architecture: HIGH - Patterns identical to Phase 3 (student-lab.ejs, finding-detail.ejs), verified by code inspection
- Pitfalls: HIGH - Based on direct code analysis of the exact files being modified
- Translation keys: HIGH - All keys verified present in fr.json except 2-3 possible additions for confirm/error dialogs

**Research date:** 2026-03-12
**Valid until:** 2026-04-12 (stable -- no external dependencies or fast-moving APIs)
