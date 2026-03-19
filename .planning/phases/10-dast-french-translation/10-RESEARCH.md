# Phase 10: DAST French Translation - Research

**Researched:** 2026-03-19
**Domain:** EJS i18n view translation, Node.js localization overlays, Quebec French content authoring
**Confidence:** HIGH

## Summary

Phase 10 translates the DAST lab to full Quebec French, replicating the same i18n pattern established in Phase 1 for SCA views. The work is purely additive: new keys in fr.json/en.json, a new `dastLocalize()` function in `utils/i18n.js`, t() calls replacing hardcoded English in 3 EJS views, and server-side translation of precondition messages.

The codebase already has a mature, proven i18n infrastructure. The `localize()` function for SCA findings (utils/i18n.js:92-109) provides the exact template for `dastLocalize()`. The SCA views (sca/student-lab.ejs, sca/finding-detail.ejs, sca/instructor.ejs) serve as reference implementations showing every pattern needed: `t()` for view chrome, EJS-embedded JS constants for client-side messages, and `localize()` for overlaying translations onto seed data objects.

There are 6 DAST scenarios with 4 translatable fields each (title, description, steps, expected_finding) = 24 scenario-level translations. The 3 DAST views contain approximately 40-50 hardcoded English strings for UI chrome (headings, labels, buttons, status badges, form labels, feedback messages). Precondition messages (5 strings) need server-side t() translation. Client-side JS strings (~10-12) need EJS-embedded constant translation.

**Primary recommendation:** Follow the SCA localize() pattern exactly. Create dastLocalize() with 4 overlay fields, add all i18n keys upfront in both fr.json and en.json, then sweep each view replacing hardcoded strings with t() calls.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Extend localize() with a new `dastLocalize()` function in utils/i18n.js for DAST scenarios
- Overlay 4 fields per scenario: title, description, steps (as JSON array), expected_finding
- Call dastLocalize() in route handlers (routes/dast.js) before passing data to res.render() -- matches SCA pattern
- fr.json key structure: `dast.scenarios.{id}.{field}` -- mirrors `sca.findings.{id}.{field}` pattern
- Steps stored as JSON array under `dast.scenarios.{id}.steps` -- dastLocalize() replaces the full array
- Severity badges (Critical, High, Medium, Low) stay in English -- unchanged, same as SCA decision
- OWASP categories (A01:2021, etc.) stay in English -- industry standard
- Vulnerability type names stay in English -- students should learn English CVE/security terminology
- Full French prose for step translations, keeping technical terms inline as-is (URLs, usernames, passwords, tool names, file paths)
- All 3 DAST views get full t() i18n key replacement: headings, form labels, buttons, status badges, table headers
- ~40-50 new i18n keys in fr.json under `dast.` namespace
- All keys added upfront in fr.json (and en.json for fallback) -- matches Phase 1 pattern
- Replace hardcoded English messages in routes/dast.js precondition endpoint with t() calls
- Server-side translation using t(req.session.language, 'dast.precondition.{key}') -- returns translated string directly in JSON
- EJS-embedded constants pattern from Phase 7: `const MESSAGES = { saving: '<%= t("dast.js.saving") %>' }`
- All AJAX feedback messages translated: saving, submitted, draft saved, network error, error saving
- All confirm() and alert() dialogs translated

### Claude's Discretion
- Exact French translation wording for all ~50 i18n keys and 6 scenarios
- How to structure dastLocalize() internally (separate function vs. parameterized localize())
- Whether to add en.json keys for DAST (for fallback completeness) or rely on existing English seed data
- Order of implementation (keys first vs. views first)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DAST-01 | All 6 DAST scenario descriptions, instructions, and results display in Quebec French | dastLocalize() overlays title, description, steps, expected_finding from fr.json keys `dast.scenarios.{1-6}.{field}` -- identical to SCA localize() pattern |
| DAST-02 | All DAST views (scenario list, scenario detail, results) display in Quebec French | ~50 t() key replacements across student-lab.ejs, scenario-detail.ejs, instructor.ejs + EJS-embedded JS constants for client-side strings + precondition server-side translation |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| utils/i18n.js | project built-in | t() and localize() functions | Already powers all French i18n across the app |
| config/translations/fr.json | project built-in | French translation dictionary | Single source of truth for all French strings |
| config/translations/en.json | project built-in | English fallback dictionary | t() falls back to en.json when fr key missing |
| EJS templates | already installed | Server-side template rendering | All views use EJS with `<%= t('key') %>` pattern |

### Supporting
No new libraries or dependencies required. This phase uses exclusively existing project infrastructure.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Separate dastLocalize() | Parameterized localize(obj, lang, prefix, fields) | Cleaner abstraction but changes existing SCA function signature; keep separate for safety |
| en.json fallback keys | Rely on seed data English | Adding en.json keys costs minimal effort, provides consistent t() fallback behavior, and matches Phase 1 pattern |

## Architecture Patterns

### Recommended Project Structure
No new files or directories. All changes go into existing files:
```
utils/i18n.js              # Add dastLocalize() function + export
routes/dast.js             # Import dastLocalize + t, use in route handlers
config/translations/fr.json  # Add ~70 keys under dast.* namespace
config/translations/en.json  # Add parallel English fallback keys
views/dast/student-lab.ejs   # Replace hardcoded English with t() calls
views/dast/scenario-detail.ejs # Replace hardcoded English with t() calls
views/dast/instructor.ejs     # Replace hardcoded English with t() calls
```

### Pattern 1: dastLocalize() -- Seed Data Overlay
**What:** A function that takes a DAST scenario object and overlays translated fields from fr.json, identical in structure to the SCA localize() function.
**When to use:** In route handlers, before passing scenario data to res.render().
**Example:**
```javascript
// Source: utils/i18n.js (existing localize pattern at lines 92-109)
function dastLocalize(scenario, lang) {
  if (lang === 'en') return scenario;

  const fields = ['title', 'description', 'steps', 'expected_finding'];
  const localized = { ...scenario };

  for (const field of fields) {
    const key = `dast.scenarios.${scenario.id}.${field}`;
    const translated = t(lang, key);
    if (translated !== key) {
      localized[field] = (field === 'steps')
        ? JSON.stringify(translated)  // steps comes back as array from JSON
        : translated;
    }
  }

  return localized;
}
```

**Key detail about steps:** In fr.json, `dast.scenarios.{id}.steps` is stored as a JSON array. The t() function navigates to the array and returns it. dastLocalize() must handle this: when the translated value is an array, assign it directly (the view already JSON.parses the steps field, so the overlay must store the stringified version -- OR the route handler can pass the parsed array alongside). The simplest approach: store the French steps as an array in fr.json, let t() return the array, and in dastLocalize() stringify it back so it matches the schema. Alternatively, dastLocalize() can set a separate `localizedSteps` property as a parsed array.

**Recommended approach for steps:** Since `routes/dast.js` line 79 already does `steps = JSON.parse(scenario.steps)`, and the student-lab view also parses at line 26, the cleanest pattern is:
1. Store steps as a JSON array in fr.json: `"steps": ["Connectez-vous en tant que...", "Naviguez vers..."]`
2. In dastLocalize(), when field is 'steps' and the translated value is an array, JSON.stringify it before assigning (so it matches the DB schema expectation)
3. The existing JSON.parse in the route/view then unpacks it as before

### Pattern 2: t() View Chrome Replacement
**What:** Replace every hardcoded English string in EJS views with `<%= t('dast.namespace.key') %>`.
**When to use:** All static text in views -- headings, labels, buttons, status badges, table headers.
**Example (from SCA reference):**
```ejs
<!-- Before -->
<h1 class="page-title">Dynamic Analysis Lab</h1>

<!-- After -->
<h1 class="page-title"><%= t('dast.studentLab.title') %></h1>
```

### Pattern 3: EJS-Embedded JS Constants for Client-Side Strings
**What:** Inline translated strings into `<script>` blocks using EJS interpolation so client-side JS has access to translated messages.
**When to use:** Any JavaScript string displayed to the user (AJAX feedback, confirm dialogs, alert messages).
**Example (from SCA student-lab.ejs lines 148-152):**
```ejs
<script>
const MSG_SAVING = '<%= t("dast.js.saving") %>';
const MSG_SAVED = '<%= t("dast.js.savedDraft") %>';
const MSG_SUBMITTED = '<%= t("dast.js.submitted") %>';
const MSG_ERROR = '<%= t("dast.js.errorSaving") %>';
const MSG_NETWORK = '<%= t("dast.js.networkError") %>';
const MSG_CONFIRM_IMPORT = '<%= t("dast.js.confirmImport") %>';
const MSG_IMPORTED = '<%= t("dast.js.imported") %>';
const MSG_CHECKING = '<%= t("dast.js.checkingPrecondition") %>';
</script>
```

### Pattern 4: Server-Side Precondition Translation
**What:** In routes/dast.js precondition endpoint, replace hardcoded English messages with t() calls.
**When to use:** Any JSON response that includes user-facing strings.
**Example:**
```javascript
// Before (routes/dast.js line 116-117)
return res.json({ met: true, message: 'No precondition required — scenario is always available.' });

// After
const lang = req.session.language || 'fr';
return res.json({ met: true, message: t(lang, 'dast.precondition.none') });
```

### Anti-Patterns to Avoid
- **Translating severity badges:** Per locked decision, Critical/High/Medium/Low stay in English. Do NOT add t() calls around severity values.
- **Translating OWASP categories or vulnerability types:** These are industry-standard English terms. Leave as-is.
- **Client-side i18n lookup for preconditions:** The server returns the pre-translated string. No client-side translation logic needed.
- **Modifying the existing localize() function:** Keep it untouched. dastLocalize() is a separate function.
- **Hardcoding French strings directly in views:** ALL strings go through t() with keys in fr.json, even if the app defaults to French. This maintains the established pattern.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation lookup | Custom string replacement | Existing t() function | Already handles nested key lookup, fallback to English, parameter interpolation |
| Seed data overlay | Manual field-by-field replacement in routes | dastLocalize() modeled on localize() | Centralizes translation logic, consistent with SCA pattern |
| Client-side i18n | fetch-based translation loading | EJS-embedded constants | Already proven in SCA views, zero runtime overhead, works offline |

**Key insight:** The entire i18n infrastructure already exists. This phase is purely about adding content (keys) and replacing strings (views). Zero new architecture needed.

## Common Pitfalls

### Pitfall 1: Steps Field Type Mismatch
**What goes wrong:** The `steps` field in the database is a JSON string. If dastLocalize() assigns a raw array (from fr.json) instead of a JSON string, JSON.parse in routes/views will fail or double-parse.
**Why it happens:** t() returns the actual JSON type from the translations file. For an array value, it returns a JavaScript array, not a string.
**How to avoid:** In dastLocalize(), when handling the 'steps' field, check if the translated value is an array and JSON.stringify() it before assigning to the localized object. This preserves the contract that `scenario.steps` is always a JSON string.
**Warning signs:** Steps showing as `[object Object]` or empty arrays in the view.

### Pitfall 2: Missing JSON Escaping in EJS-Embedded Constants
**What goes wrong:** French strings with apostrophes (e.g., "l'enregistrement") break JavaScript string literals in `<script>` blocks.
**Why it happens:** EJS `<%= %>` outputs raw content. A French apostrophe inside a single-quoted JS string produces a syntax error.
**How to avoid:** Use the `<%- JSON.stringify(t('key')) %>` pattern for strings that may contain quotes, or ensure all EJS-embedded constants use backtick template literals. Alternatively, use `<%= t('key').replace(/'/g, "\\'") %>` -- but the simplest proven approach in this codebase is that the SCA views use single-quoted constants and the French strings avoid raw apostrophes by using proper Unicode characters.
**Warning signs:** JavaScript console errors on page load, broken UI interactivity.

### Pitfall 3: Forgetting to Import dastLocalize in routes/dast.js
**What goes wrong:** Scenarios display in English because dastLocalize() is never called.
**Why it happens:** routes/dast.js currently does not import from utils/i18n.js at all.
**How to avoid:** Add `const { dastLocalize, t } = require('../utils/i18n');` at the top of routes/dast.js. Call dastLocalize on every scenario before rendering.

### Pitfall 4: Not Translating Both Student-Lab Inline Form AND Scenario-Detail Form
**What goes wrong:** The student-lab view has an inline expandable form per scenario (lines 64-106) AND the scenario-detail view has a separate full form (lines 92-127). Both need translation.
**Why it happens:** Easy to miss that there are two separate forms with overlapping but not identical labels.
**How to avoid:** Use the same i18n keys for identical labels (e.g., dast.form.evidence, dast.form.impact) across both views.

### Pitfall 5: Precondition "Requires: rbac OFF" Badge Text
**What goes wrong:** The student-lab view line 35 has `Requires: <%= s.precondition.replace('_disabled',' OFF') %>` which generates English text dynamically.
**Why it happens:** This is a computed string, not a simple hardcoded string, so it's easy to overlook.
**How to avoid:** Replace with a t() call: `t('dast.precondition.requires', { feature: s.precondition.replace('_disabled','') })` or use a lookup map.

## Code Examples

### Complete Inventory of Hardcoded English Strings to Translate

#### student-lab.ejs (~20 strings)
```
Line 4:  "Dynamic Analysis Lab" -> t('dast.studentLab.title')
Line 5:  "Follow each scenario step-by-step..." -> t('dast.studentLab.subtitle')
Line 35: "Requires: {precondition} OFF" -> t('dast.studentLab.requires', ...)
Line 38: "Submitted" -> t('dast.studentLab.submitted')
Line 40: "Draft saved" -> t('dast.studentLab.draftSaved')
Line 47: "View / Edit" / "Continue" / "Start" -> t('dast.studentLab.viewEdit') etc.
Line 54: "Checking precondition..." -> t('dast.js.checkingPrecondition')
Line 58: "Steps" -> t('dast.form.stepsHeading')
Line 63: "Document Your Finding" -> t('dast.form.documentHeading')
Line 67: "Did you successfully trigger the vulnerability?" -> t('dast.form.triggeredQuestion')
Line 70: "Yes" -> t('common.yes')  [already exists]
Line 73: "No" -> t('common.no')  [already exists]
Line 77: "Evidence / Proof (URL, response, screenshot description)" -> t('dast.form.evidence')
Line 81: "Impact Assessment" -> t('dast.form.impact')
Line 85: "Reproduction Steps" -> t('dast.form.reproduction')
Line 89: "Your Recommendation" -> t('dast.form.recommendation')
Line 93: "Your Severity Rating" -> t('dast.form.severityRating')
Line 95: "-- select --" -> t('dast.form.selectOption')
Line 102: "Save Draft" -> t('dast.form.saveDraft')
Line 103: "Submit" -> t('dast.form.submit')
JS line 136: "Saving..." -> MSG_SAVING
JS line 147: "Submitted!" / "Draft saved." -> MSG_SUBMITTED / MSG_SAVED
JS line 151: "Error saving." -> MSG_ERROR
JS line 155: "Network error." -> MSG_NETWORK
```

#### scenario-detail.ejs (~25 strings)
```
Line 5:  "DAST Lab" (back link) -> t('dast.common.backToLab')
Line 37: "Checking precondition..." -> t('dast.js.checkingPrecondition')
Line 40: "Step-by-Step Instructions" -> t('dast.detail.stepsTitle')
Line 49: "Affected file:" -> t('dast.detail.affectedFile')
Line 50: "lines" -> t('dast.detail.lines')
Line 57: "Student Submissions ({count})" -> t('dast.detail.studentSubmissions', {count})
Line 60: "Student" / "Triggered?" / "Severity" / "Status" / "Grade" -> table headers
Line 68: "Yes" / "No" -> reuse common.yes/common.no
Line 72: "Submitted" / "Draft" -> t('dast.common.submitted') / t('dast.common.draft')
Line 86: "Your Finding" -> t('dast.detail.yourFinding')
Line 89: "Submitted on" -> t('dast.detail.submittedOn')
Line 94: "Triggered?" -> t('dast.form.triggered')
Line 99: "Evidence" -> t('dast.form.evidence')
Line 103: "Impact Assessment" / "Reproduction Steps" / "Recommendation" -> reuse form keys
Line 115: "Your Severity Rating" -> reuse dast.form.severityRating
Line 124-125: "Save Draft" / "Submit" -> reuse dast.form.saveDraft/submit
Line 133: "Vulnerability Manager" -> t('dast.detail.vulnManager')
Line 136: "Imported as" -> t('dast.detail.importedAs')
Line 139: "Push to VM" -> t('dast.detail.pushToVM')
Line 145: "Expected Finding" -> t('dast.detail.expectedFinding')
JS line 164: "Push this scenario to the Vulnerability Manager?" -> MSG_CONFIRM_IMPORT
JS line 168: "Imported! Reloading..." -> MSG_IMPORTED
JS line 169/170: alert messages -> MSG constants
```

#### instructor.ejs (~20 strings)
```
Line 4:  "Dynamic Analysis -- Instructor Dashboard" -> t('dast.instructor.title')
Line 5:  "{n} scenarios | {n} students" -> t('dast.instructor.subtitle', ...)
Line 23: "Scenarios" -> t('dast.instructor.scenariosHeading')
Line 27-33: Table headers: "#", "Scenario", "Type", "Sev.", "Precondition", "Submissions", "VM"
Line 55: "Always on" -> t('dast.instructor.alwaysOn')
Line 66: "In VM" -> t('dast.instructor.inVM')
Line 68: "Push to VM" -> t('dast.instructor.pushToVM')
Line 83: "Student Submissions ({count})" -> t('dast.instructor.studentSubmissions', {count})
Line 88-93: Table headers: "Student ID", "Triggered?", "Severity", "Submitted", "Grade", "Actions"
Line 102: "Triggered" -> t('dast.instructor.triggered')
Line 104: "Not triggered" -> t('dast.instructor.notTriggered')
Line 108: "Draft" -> t('dast.common.draft')
Line 113: "Grade" button -> t('dast.instructor.gradeBtn')
Line 126: "Grade / Feedback" modal title -> t('dast.instructor.gradeFeedbackTitle')
Line 129-133: "Grade" label, "Instructor Feedback" label
Line 137: "Cancel" -> reuse common.cancel
Line 138: "Save" -> reuse common.save
JS line 170: "Push this scenario to the Vulnerability Manager?" -> MSG_CONFIRM_IMPORT
JS line 171: "Importing..." -> MSG_IMPORTING
```

### dastLocalize() Implementation
```javascript
// Source: modeled on utils/i18n.js localize() at lines 92-109
function dastLocalize(scenario, lang) {
  if (lang === 'en') return scenario;

  const fields = ['title', 'description', 'steps', 'expected_finding'];
  const localized = { ...scenario };

  for (const field of fields) {
    const key = `dast.scenarios.${scenario.id}.${field}`;
    const translated = t(lang, key);
    if (translated !== key) {
      // steps is stored as JSON string in DB; t() returns an array from fr.json
      localized[field] = (field === 'steps' && Array.isArray(translated))
        ? JSON.stringify(translated)
        : translated;
    } else {
      console.warn(`dastLocalize: missing ${lang} translation for ${key}`);
    }
  }

  return localized;
}
```

### Route Handler Integration (routes/dast.js)
```javascript
// Add at top of routes/dast.js
const { dastLocalize, t } = require('../utils/i18n');

// In GET / handler, before res.render:
const lang = req.session.language || 'fr';
const localizedScenarios = scenarios.map(s => dastLocalize(s, lang));
// Pass localizedScenarios instead of scenarios to res.render

// In GET /scenarios/:id handler:
const lang = req.session.language || 'fr';
const localizedScenario = dastLocalize(scenario, lang);
// Pass localizedScenario instead of scenario

// In precondition endpoint:
const lang = req.session.language || 'fr';
if (pre === 'none') {
  return res.json({ met: true, message: t(lang, 'dast.precondition.none') });
}
```

### fr.json Key Structure (Scenario Example)
```json
{
  "dast": {
    "scenarios": {
      "1": {
        "title": "IDOR : Acceder aux notes d'un autre etudiant",
        "description": "Lorsque le RBAC est desactive, le serveur ne verifie pas la propriete des ressources. Un etudiant peut consulter les notes de n'importe quel autre etudiant en modifiant l'identifiant dans l'URL.",
        "steps": [
          "Connectez-vous en tant que alice_student (mot de passe : student123)",
          "Naviguez vers Mes cours et notez votre identifiant etudiant dans l'URL",
          "..."
        ],
        "expected_finding": "Un etudiant peut lire les dossiers d'inscription et les notes d'autres utilisateurs sans autorisation"
      }
    },
    "studentLab": { "title": "Laboratoire d'analyse dynamique", "..." : "..." },
    "form": { "triggeredQuestion": "Avez-vous reussi a declencher la vulnerabilite ?", "..." : "..." },
    "precondition": { "none": "Aucune precondition requise -- le scenario est toujours disponible.", "..." : "..." },
    "js": { "saving": "Enregistrement...", "..." : "..." }
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in DAST views | All text through t() and dastLocalize() | This phase | Full French experience for DAST lab |
| No i18n in routes/dast.js | dastLocalize() + t() in route handlers | This phase | Scenario data rendered in French |
| English precondition messages | Server-side t() translation | This phase | Precondition feedback in French |
| English JS feedback messages | EJS-embedded translated constants | This phase | Client-side AJAX feedback in French |

## Open Questions

1. **Apostrophe handling in EJS-embedded JS constants**
   - What we know: SCA views use single-quoted constants (lines 148-152 of sca/student-lab.ejs) and the French strings work because they either avoid apostrophes or use proper escaping.
   - What's unclear: Whether any of the new DAST French strings contain apostrophes that could break single-quoted JS literals.
   - Recommendation: Use the same single-quote pattern as SCA. If any French string contains an apostrophe (e.g., "l'enregistrement"), ensure the translation key uses a Unicode right single quotation mark or escape it. Test by loading each view after adding translations. Alternatively, use template literals (backticks) for all EJS-embedded constants.

2. **dastLocalize() as separate function vs. parameterized localize()**
   - What we know: Context says "Claude's discretion" on this choice.
   - Recommendation: **Use a separate dastLocalize() function.** Rationale: (a) keeps the existing localize() untouched (zero regression risk), (b) the DAST fields differ from SCA fields (4 fields including steps-as-array vs. 3 simple string fields), (c) the steps field requires special array handling that would complicate a generic version.

3. **en.json keys for DAST**
   - What we know: Context says "Claude's discretion" on whether to add en.json keys.
   - Recommendation: **Yes, add en.json keys.** Rationale: (a) matches the Phase 1 pattern where both fr.json and en.json have parallel SCA keys, (b) provides consistent fallback behavior, (c) minimal effort (~70 keys copied from seed data), (d) if a student somehow got lang='en', the app would still work.

4. **Implementation order**
   - What we know: Context says "Claude's discretion" on order.
   - Recommendation: **Keys first, then views.** Add all fr.json + en.json keys in one task, then sweep all 3 views + routes in a second task. This way, when modifying views, all t() keys are already available and testable.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, no dependencies) |
| Config file | none (uses node --test glob) |
| Quick run command | `node --test test/*.test.js` |
| Full suite command | `node --test test/*.test.js` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DAST-01 | 6 DAST scenarios display in French | manual-only | Visual inspection of /dast and /dast/scenarios/{1-6} while logged in | N/A -- translation content correctness requires human review |
| DAST-02 | All DAST views display in French | manual-only | Visual inspection of all 3 views | N/A -- UI text correctness requires human review |

**Manual-only justification:** Translation quality and completeness are best verified by visual inspection. Automated tests could verify that t() keys exist in fr.json, but the real validation is that the rendered pages display correct French text. The existing test infrastructure tests HTTP endpoints and auth gating, not i18n content rendering.

### Sampling Rate
- **Per task commit:** `node --test test/*.test.js` (ensures no regressions to existing functionality)
- **Per wave merge:** `node --test test/*.test.js` + manual visual check of /dast views
- **Phase gate:** All existing tests green + visual confirmation all 3 DAST views render in French

### Wave 0 Gaps
None -- existing test infrastructure covers regression testing. Translation content is validated manually.

## Sources

### Primary (HIGH confidence)
- **utils/i18n.js** (lines 29-68, 73-84, 92-109) -- t() function implementation, languageMiddleware, localize() pattern
- **routes/sca.js** (lines 6, 62-74, 95-99, 160-177) -- Reference implementation for localize() usage in route handlers
- **views/sca/student-lab.ejs** (lines 4-5, 27-31, 148-152) -- Reference implementation for t() usage and EJS-embedded JS constants
- **config/translations/fr.json** -- Existing French translation structure, SCA key patterns
- **views/dast/student-lab.ejs** -- Full source: 160 lines, ~20 hardcoded English strings identified
- **views/dast/scenario-detail.ejs** -- Full source: 175 lines, ~25 hardcoded English strings identified
- **views/dast/instructor.ejs** -- Full source: 181 lines, ~20 hardcoded English strings identified
- **routes/dast.js** -- Full source: 235 lines, precondition endpoint at lines 108-138
- **utils/seedData.js** (lines 407-497) -- All 6 DAST scenario seed data with English text

### Secondary (MEDIUM confidence)
None needed -- all findings are from direct codebase inspection.

### Tertiary (LOW confidence)
None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- using exclusively existing project infrastructure, no new libraries
- Architecture: HIGH -- all patterns are direct replicas of proven SCA i18n implementation
- Pitfalls: HIGH -- identified from direct code inspection and understanding of EJS/JSON interaction
- Translation content: MEDIUM -- French translations are Claude's discretion; quality depends on execution

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- no external dependencies or version concerns)
