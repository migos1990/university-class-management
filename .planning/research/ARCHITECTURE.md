# Architecture Patterns

**Domain:** SCA Lab Production Readiness -- i18n, UX, and Dashboard Integration
**Researched:** 2026-03-12
**Confidence:** HIGH (based on direct codebase analysis, no external dependencies)

## Current Architecture Summary

The app is a server-rendered Express/EJS monolith with a classroom-manager orchestrator. Key facts for integration planning:

| Component | Location | Role |
|-----------|----------|------|
| i18n middleware | `utils/i18n.js` | Loads `config/translations/{en,fr}.json`, exposes `t()` helper to all EJS views via `res.locals.t` |
| Language middleware | `server.js:59` | Sets language from `req.session.language`, defaults to `'en'` |
| SCA routes | `routes/sca.js` | Student lab + instructor dashboard, all strings hardcoded in English in EJS |
| SCA views | `views/sca/*.ejs` | 4 templates: `student-lab`, `instructor`, `finding-detail`, `student-detail` |
| Shared views | `views/partials/header.ejs`, `views/login.ejs`, `views/error.ejs` | All strings hardcoded in English |
| Classroom manager | `scripts/classroom-manager.js` | Spawns team instances, serves instructor dashboard on port 3000, polls `/api/summary` every 60s |
| Summary API | `server.js:126-224` | `/api/summary` returns SCA progress per-student (submitted_count) |
| Seed data | `utils/seedData.js` | 12 SCA findings with English titles/descriptions/remediation |
| Translation files | `config/translations/{en,fr}.json` | Extensive French translations for admin/auth/nav/dashboard but ZERO SCA-specific keys |

## Recommended Architecture

### Integration Strategy: Additive-Only Modifications

Every change must be additive -- never restructure existing working code. The app works; it just speaks English where it needs to speak French, and the instructor needs better class-wide visibility.

Three integration layers, each independent:

```
Layer 1: Translation Data (JSON files + seed data)
   |
   v
Layer 2: View Integration (EJS templates use t() calls)
   |
   v
Layer 3: Dashboard Enhancement (new API fields + polling JS)
```

### Component Boundaries

| Component | Responsibility | Communicates With | Modified Files |
|-----------|---------------|-------------------|----------------|
| Translation JSON | Store all French strings for SCA domain | Read by `utils/i18n.js` at startup | `config/translations/fr.json`, `config/translations/en.json` |
| Language default | Set session language to `'fr'` for all users | `utils/i18n.js` middleware | `utils/i18n.js` (1-line change) |
| SCA view templates | Replace hardcoded English with `t()` calls | Translation JSON via `res.locals.t` | `views/sca/*.ejs` (4 files) |
| Shared UI templates | Replace hardcoded English in header/login/error | Translation JSON via `res.locals.t` | `views/partials/header.ejs`, `views/login.ejs`, `views/error.ejs` |
| Dashboard templates | Replace hardcoded English in student/professor dashboards | Translation JSON via `res.locals.t` | `views/student/dashboard.ejs`, `views/professor/dashboard.ejs` |
| SCA seed data | Add French fields to finding objects | Read by `views/sca/*.ejs` | `utils/seedData.js` |
| Summary API | Add richer SCA progress data | Consumed by classroom-manager | `server.js` `/api/summary` endpoint |
| Classroom dashboard | Display SCA-specific live stats | Polls `/api/class-overview` | `scripts/classroom-manager.js` |

## Data Flow

### Flow 1: French Translation Resolution (Existing Mechanism)

```
1. Server starts -> utils/i18n.js loads config/translations/fr.json into memory
2. Request arrives -> languageMiddleware reads req.session.language
3. res.locals.t = (key, params) => t(lang, key, params)  // bound to 'fr'
4. EJS template calls: <%= t('sca.lab.title') %>
5. i18n.js navigates fr.json: sca -> lab -> title -> "Analyse de code statique"
6. If key missing in fr.json, falls back to en.json, then returns raw key
```

**Critical detail:** The `t()` function is already available in ALL views via `res.locals.t`. No middleware changes needed to use it. The only work is (a) adding keys to the JSON files and (b) replacing hardcoded strings in EJS with `<%= t('key') %>` calls.

### Flow 2: Default Language Change

```
Current:  utils/i18n.js line 75: const lang = req.session.language || 'en'
Needed:   utils/i18n.js line 75: const lang = req.session.language || 'fr'
```

One-line change. Session language is never explicitly set anywhere in the codebase (there is no language toggle UI), so every user gets the default. Changing `'en'` to `'fr'` makes the entire app French by default.

### Flow 3: SCA Seed Data Enrichment

Two approaches for translating finding-level content (titles, descriptions, remediation):

**Approach A -- Dual-language fields in seed data (RECOMMENDED):**
```
Add fr_title, fr_description, fr_remediation to each SCA finding in seedData.js
EJS templates check: finding.fr_title || finding.title
```

**Why this, not the translation JSON:** SCA finding content is dynamic, DB-stored data -- not UI chrome. Putting 12 multi-paragraph French descriptions into the translation JSON would bloat it and couple DB content to UI translation infrastructure. The seed data already owns this content.

**Why not Approach B (translation JSON):** The `t()` function resolves static UI labels. Finding descriptions are educational content that belongs with the finding data itself, not the UI translation layer. Mixing them would make the translation file unwieldy (12 findings x 3 fields = 36 long-form entries).

### Flow 4: Student Progress Tracking (Existing)

```
Student browser                    Student instance (port 300x)
     |                                     |
     | POST /sca/findings/:id/review       |
     |------------------------------------>|
     |                                     | db.prepare('INSERT/UPDATE sca_student_reviews')
     |                                     | saveDatabase() -> data.json
     |                                     |

Classroom manager (port 3000)      Student instance (port 300x)
     |                                     |
     | GET /api/summary (every 60s)        |
     |------------------------------------>|
     |                                     | Query sca_findings + sca_student_reviews
     |                                     | Calculate per-student submitted_count
     |    <-- JSON: sca.per_student[] -----|
     |                                     |
     | Render in dashboard HTML            |
```

**Current data returned by /api/summary for SCA:**
```javascript
sca: {
  total_findings: 12,
  avg_completion_pct: 0,    // % of all students x all findings that are submitted
  per_student: [
    { username: 'alice_student', submitted_count: 0 },
    { username: 'bob_student', submitted_count: 0 },
    // ...
  ]
}
```

### Flow 5: Enhanced Instructor Dashboard (Proposed Addition)

To give the instructor class-wide SCA visibility without WebSockets (explicitly out of scope), extend the existing polling architecture:

```
Enhanced /api/summary response for SCA:
sca: {
  total_findings: 12,
  avg_completion_pct: 25,
  per_student: [
    {
      username: 'alice_student',
      submitted_count: 3,
      draft_count: 2,           // NEW: findings with saved drafts
      last_activity: '...'      // NEW: timestamp of last review action
    },
    // ...
  ],
  consensus: {                  // NEW: class-wide agreement indicators
    1: { confirmed: 4, false_positive: 1, needs_investigation: 0 },
    2: { confirmed: 3, false_positive: 0, needs_investigation: 2 },
    // ... per finding_id
  },
  class_stats: {                // NEW: aggregate stats
    total_submitted: 15,
    total_drafts: 8,
    students_started: 5,
    students_completed: 1       // all 12 submitted
  }
}
```

**No new endpoints needed.** The existing `/api/summary` response is already consumed by the classroom-manager's `fetchSummary()` and cached in `summaryCache[]`. Adding fields to the response object is backward-compatible.

The classroom-manager dashboard (`dashboardHTML()` in `scripts/classroom-manager.js`) can then render an SCA-specific section using the existing `renderLabProgress()` pattern, with per-team SCA detail.

## Patterns to Follow

### Pattern 1: Translation Key Namespacing

**What:** Organize SCA translation keys under `sca.*` namespace in the JSON files, mirroring the existing `dashboard.*`, `auth.*`, `security.*` pattern.

**When:** Every UI string replacement in SCA views.

**Structure:**
```json
{
  "sca": {
    "lab": {
      "title": "Laboratoire d'analyse de code statique",
      "subtitle": "Examinez chaque constatation, classez-la et documentez votre raisonnement -- puis soumettez.",
      "findingsSubmitted": "constatations soumises",
      "complete": "termine"
    },
    "review": {
      "classification": "Classification",
      "selectPlaceholder": "-- selectionner --",
      "confirmed": "Vrai positif (vulnerabilite confirmee)",
      "falsePositive": "Faux positif",
      "needsInvestigation": "Necessite une enquete approfondie",
      "yourNotes": "Vos notes d'analyse",
      "notesPlaceholder": "Expliquez pourquoi vous avez classifie de cette facon...",
      "proposedRemediation": "Remediation proposee",
      "remediationPlaceholder": "Comment corrigeriez-vous cela?",
      "saveDraft": "Enregistrer le brouillon",
      "submit": "Soumettre",
      "submitted": "Soumis",
      "draftSaved": "Brouillon enregistre"
    },
    "instructor": {
      "title": "Analyse de code statique -- Tableau de bord instructeur",
      "findingsOverview": "Apercu des constatations",
      "studentProgress": "Matrice de progression des etudiants",
      "pushToVM": "Envoyer au VM",
      "inVM": "Dans le VM",
      "reviews": "evaluations",
      "confirmed": "confirme",
      "fp": "FP"
    },
    "finding": {
      "location": "Emplacement",
      "codeSnippet": "Extrait de code",
      "description": "Description",
      "remediationGuidance": "Guide de remediation",
      "references": "References",
      "studentReviews": "Evaluations des etudiants",
      "yourReview": "Votre evaluation",
      "vulnerabilityManager": "Gestionnaire de vulnerabilites"
    },
    "severity": {
      "Critical": "Critique",
      "High": "Eleve",
      "Medium": "Moyen",
      "Low": "Faible"
    },
    "status": {
      "submitted": "soumis",
      "notStarted": "Non commence",
      "startReview": "Commencer l'evaluation",
      "continue": "Continuer",
      "viewEdit": "Voir / Modifier"
    }
  }
}
```

### Pattern 2: Bilingual Seed Data Fields

**What:** Add `fr_*` fields alongside existing English fields in seed data, letting views pick the right language.

**When:** SCA finding titles, descriptions, and remediation guidance.

**Example in seedData.js:**
```javascript
[1, 'Hardcoded Session Secret',
  // ... existing fields ...
  'Semgrep', 'Move the secret to an environment variable...', null,
  // NEW French fields appended:
  'Secret de session code en dur',
  'Le secret de session Express est code en dur dans le code source. Toute personne ayant acces au code peut forger des cookies de session, menant a un contournement d\'authentification.',
  'Deplacez le secret vers une variable d\'environnement (SESSION_SECRET). Generez une valeur aleatoire cryptographiquement securisee de 64 octets pour la production.'
],
```

**View access pattern:**
```ejs
<%= currentLang === 'fr' && finding.fr_title ? finding.fr_title : finding.title %>
```

Or cleaner with a helper added to `res.locals`:
```javascript
// In server.js middleware, after languageMiddleware
res.locals.localize = (obj, field) => {
  const frField = 'fr_' + field;
  return (res.locals.currentLang === 'fr' && obj[frField]) ? obj[frField] : obj[field];
};
```
```ejs
<%= localize(finding, 'title') %>
```

### Pattern 3: Polling-Based Dashboard Refresh (Existing Pattern)

**What:** The classroom-manager already polls `/api/summary` every 60s and `/health` every 30s. The client-side JS (`fetchOverview()`) re-renders all dashboard sections from the JSON response.

**When:** Adding any new dashboard section for SCA.

**Follow the existing pattern exactly:**
1. Add data to the `/api/summary` response in `server.js`
2. Add a `renderSCAProgress()` function in `classroom-manager.js` (server-side HTML)
3. Add a `renderSCAProgressDOM()` function in the `<script>` block (client-side DOM update)
4. The 60s polling interval is sufficient for a classroom setting

**Do NOT introduce WebSockets.** The project explicitly lists this as out of scope, and the polling architecture works well for 12 teams with 30-second and 60-second intervals.

## Anti-Patterns to Avoid

### Anti-Pattern 1: Restructuring the i18n System

**What:** Replacing the simple `t()` function with a full i18n library (i18next, etc.) or changing the JSON structure.

**Why bad:** Adds a dependency (violates constraint), risks breaking the existing translations that already work for admin/auth/dashboard, and introduces unnecessary complexity for a one-night deployment.

**Instead:** Use the existing `t()` system as-is. It supports nested keys, parameter interpolation via `{paramName}`, and English fallback. That is everything needed.

### Anti-Pattern 2: Putting Finding Content in Translation JSON

**What:** Adding SCA finding descriptions (12 findings x ~100 words each) to `config/translations/fr.json`.

**Why bad:** Translation JSON is for UI chrome (labels, buttons, headings). Finding content is educational material that is stored in the database and seeded at startup. Mixing these concerns makes both files harder to maintain, and requires translating content that should live with its data.

**Instead:** Add `fr_title`, `fr_description`, `fr_remediation` fields to the seed data objects. Views use the `localize()` helper to pick the right field based on `currentLang`.

### Anti-Pattern 3: Adding Real-Time WebSocket Infrastructure

**What:** Installing socket.io or ws for live dashboard updates.

**Why bad:** Explicitly out of scope. The classroom-manager already has a working polling architecture (30s health, 60s summary). Adding WebSockets introduces a new dependency, new failure modes, and complexity for marginal benefit in a classroom of 12 teams.

**Instead:** Reduce the summary polling interval from 60s to 30s if faster updates are desired. The overhead of 12 HTTP requests every 30 seconds is negligible.

### Anti-Pattern 4: Modifying the Database Schema

**What:** Altering `config/database.js` to add new tables or change the SQL-like query interface.

**Why bad:** The database module is a 1128-line monolith with string-matching SQL parsing. Any structural change risks breaking existing queries. The SCA tables (`sca_findings`, `sca_student_reviews`) already have all the fields needed.

**Instead:** Add `fr_*` fields to the seed data INSERT statements. The JSON database stores whatever fields you put in -- there is no schema enforcement. New fields on existing collections are automatically persisted.

### Anti-Pattern 5: Creating a Language Toggle UI

**What:** Building a dropdown or flag-based language switcher.

**Why bad:** Explicitly out of scope ("Defaulting to French is simpler and sufficient"). Adds UI complexity, session management concerns, and testing surface for zero benefit when all students speak French.

**Instead:** Change the default language from `'en'` to `'fr'` in `utils/i18n.js` line 75. Done.

## Integration Points (Detailed)

### Integration Point 1: Default Language Switch

**File:** `utils/i18n.js`
**Line:** 75
**Change:** `'en'` to `'fr'`
**Risk:** LOW -- English fallback still works if any French key is missing
**Dependencies:** None
**Test:** Login page should show French labels after change

### Integration Point 2: Translation JSON Extension

**Files:** `config/translations/fr.json`, `config/translations/en.json`
**Change:** Add `sca` section with ~60 keys, add `nav` section updates for French sidebar labels
**Risk:** LOW -- missing keys fall back to English; new keys are purely additive
**Dependencies:** None (loaded at startup, no restart needed in dev)
**Test:** Spot-check a few `t('sca.lab.title')` calls render correctly

### Integration Point 3: SCA View Template Modifications

**Files:** `views/sca/student-lab.ejs`, `views/sca/instructor.ejs`, `views/sca/finding-detail.ejs`, `views/sca/student-detail.ejs`
**Change:** Replace ~80 hardcoded English strings with `<%= t('sca.xxx') %>` calls
**Risk:** MEDIUM -- a typo in a key name shows the raw key instead of French text; functional but ugly
**Dependencies:** Integration Point 2 (translation keys must exist)
**Test:** Load each page, verify no raw key strings visible

### Integration Point 4: Shared UI Template Modifications

**Files:** `views/partials/header.ejs`, `views/login.ejs`, `views/error.ejs`, `views/student/dashboard.ejs`, `views/professor/dashboard.ejs`
**Change:** Replace hardcoded English strings in navigation, login form, error messages, dashboards
**Risk:** MEDIUM -- header.ejs is included by every authenticated page; a syntax error breaks everything
**Dependencies:** Integration Point 2
**Test:** Login, navigate through sidebar, trigger a 404 -- all should show French

### Integration Point 5: Seed Data French Fields

**File:** `utils/seedData.js`
**Change:** Add `fr_title`, `fr_description`, `fr_remediation` to each of the 12 SCA finding INSERT calls
**Risk:** MEDIUM -- requires careful SQL parameter alignment with `config/database.js` INSERT handler
**Dependencies:** Must also update the INSERT handler in `config/database.js` to store the new fields (or rely on the JSON storage being schema-free -- which it is)
**Test:** After re-seeding, verify `finding.fr_title` exists in the finding objects

### Integration Point 6: Localize Helper

**File:** `server.js` (in the middleware block around line 62)
**Change:** Add `res.locals.localize` helper function
**Risk:** LOW -- purely additive
**Dependencies:** None
**Test:** Use `localize(finding, 'title')` in a view and verify it returns French when `currentLang === 'fr'`

### Integration Point 7: Enhanced /api/summary

**File:** `server.js` (lines 165-175 in the `/api/summary` handler)
**Change:** Add `draft_count`, `last_activity`, `consensus`, and `class_stats` fields to the SCA section
**Risk:** LOW -- additive fields on existing JSON response; classroom-manager ignores unknown fields
**Dependencies:** None
**Test:** `curl localhost:300x/api/summary | jq '.sca'` should show new fields

### Integration Point 8: Classroom Dashboard SCA Section

**File:** `scripts/classroom-manager.js`
**Change:** Add `renderSCADetail()` and `renderSCADetailDOM()` functions following the existing pattern
**Risk:** LOW-MEDIUM -- the dashboard is a self-contained HTML document; adding a section follows the established pattern
**Dependencies:** Integration Point 7 (needs enhanced summary data)
**Test:** Start classroom manager, verify SCA section appears with team progress

## Suggested Build Order

The following order respects dependencies and minimizes risk:

### Phase 1: Foundation (no visual changes yet)

1. **Change default language** (`utils/i18n.js` line 75: `'en'` -> `'fr'`)
2. **Add SCA keys to `fr.json` and `en.json`** (additive, no views touch this yet)
3. **Add `localize()` helper to `server.js`** (additive middleware)

*Rationale:* These three changes are invisible to users. Nothing breaks. They create the infrastructure all subsequent work depends on.

### Phase 2: Shared UI Translation (login + navigation)

4. **Translate `login.ejs`** (first thing students see; French login = immediate confidence)
5. **Translate `header.ejs` sidebar** (navigation labels, section titles)
6. **Translate `error.ejs`** (safety net for 404/500 in French)
7. **Translate `student/dashboard.ejs` and `professor/dashboard.ejs`**

*Rationale:* The login page and sidebar are the first and most persistent UI elements. Getting these right immediately makes the app feel French. Do this before SCA-specific views because students hit these first.

### Phase 3: SCA Student Experience

8. **Add French fields to seed data** (`seedData.js` -- `fr_title`, `fr_description`, `fr_remediation`)
9. **Translate `student-lab.ejs`** (the main student working page)
10. **Translate `finding-detail.ejs`** (where students do the actual review work)
11. **Add guided workflow hints** (contextual French tips in the review form)

*Rationale:* This is the core student experience. After login and navigation are French, this is where students spend 90% of their time.

### Phase 4: SCA Instructor Experience

12. **Translate `instructor.ejs`** (SCA dashboard with review matrix)
13. **Translate `student-detail.ejs`** (individual student review view)
14. **Enhance `/api/summary`** (add consensus, drafts, class_stats)
15. **Add SCA detail section to classroom-manager dashboard**

*Rationale:* The instructor dashboard is less urgent than student-facing pages but needed for class monitoring. The enhanced summary data feeds the classroom-level view.

### Phase 5: Polish and Verification

16. **End-to-end walkthrough** (login as student, complete one finding review, verify all French)
17. **Error path testing** (invalid login, 404, network errors -- all French)
18. **Codespaces boot verification** (clean instance, auto-seed, French by default)

*Rationale:* Final verification pass. This is the "does it actually work in the real classroom?" phase.

### Dependency Graph

```
Phase 1 (Foundation)
  |
  +-- Phase 2 (Shared UI) -- depends on translation keys existing
  |
  +-- Phase 3 (SCA Student) -- depends on translation keys + seed data
  |     |
  |     +-- Phase 4 (SCA Instructor) -- depends on student views working
  |           |
  |           +-- Phase 5 (Polish) -- depends on everything else
```

Phases 2 and 3 can be done in parallel since they modify different files. Phase 4 depends on Phase 3 (same translation keys, same seed data changes). Phase 5 is sequential after everything else.

## Scalability Considerations

| Concern | 1 team (dev) | 12 teams (class) | 50+ teams (future) |
|---------|-------------|------------------|---------------------|
| Translation loading | Negligible (2 JSON files in memory) | Same -- loaded once per process | Same |
| Summary polling | 1 request/60s | 12 requests/60s (staggered) | May need batching or longer interval |
| Seed data size | 12 findings + fr fields | Same per instance | Same |
| Dashboard rendering | Instant | ~12 cards, fast | Grid may need pagination |

For tonight's 12-team class, there are zero scalability concerns. The polling architecture handles this load trivially.

## Sources

- Direct codebase analysis (HIGH confidence -- all claims verified against source code)
- `utils/i18n.js` -- translation loading and `t()` function implementation
- `server.js` -- middleware registration, `/api/summary` endpoint
- `scripts/classroom-manager.js` -- polling intervals, dashboard HTML generation
- `config/translations/fr.json` -- existing translation structure and coverage
- `views/sca/*.ejs` -- current hardcoded English strings requiring translation
- `.planning/codebase/ARCHITECTURE.md` -- existing architectural documentation
- `.planning/PROJECT.md` -- project constraints and scope decisions

---

*Architecture research: 2026-03-12*
