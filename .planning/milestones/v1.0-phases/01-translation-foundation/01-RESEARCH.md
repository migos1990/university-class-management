# Phase 1: Translation Foundation - Research

**Researched:** 2026-03-12
**Domain:** i18n infrastructure, JSON translation files, seed data localization helper
**Confidence:** HIGH

## Summary

Phase 1 is entirely infrastructure work -- no template changes, no UI wiring. Three deliverables: (1) flip the default language from English to French in `utils/i18n.js` line 75, (2) add all SCA and shared UI translation keys to both `fr.json` and `en.json`, and (3) create a `localize()` helper in `utils/i18n.js` that overlays French translations from `fr.json` onto seed data finding objects.

The existing i18n system is well-built: `t()` supports dot-separated nested key lookup, parameter interpolation, and English fallback with `console.warn()` on missing keys. The `languageMiddleware` already exposes `t()` and `currentLang` to all EJS views via `res.locals`. The only gap is that the default language is `'en'` and there are zero SCA-specific translation keys. This phase fills those gaps without touching any EJS template.

**Primary recommendation:** Treat this as three independent tasks -- (1) one-line default language change, (2) bulk JSON key authoring, (3) localize() helper function -- that can be implemented and verified in sequence with minimal risk.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Use fr.json lookup pattern: keys like `sca.findings.1.title`, `sca.findings.1.description`, `sca.findings.1.remediation`
- localize() helper takes a finding object and language, returns the finding with translated text fields from fr.json via existing t() function
- Falls back to English (original seed data values) when French key is missing
- Log console.warn() on missing French translations (matches existing i18n.js warning pattern)
- Code snippets stay in English -- they're actual source code, not prose
- localize() lives in utils/i18n.js alongside existing t() function
- Severity levels stay English: Critical, High, Medium, Low
- Category labels stay English: Hardcoded Credentials, Broken Access Control, Path Traversal, etc.
- Finding titles translated to French
- Finding descriptions and remediation translated to French: full prose in Quebec French
- Classification dropdowns in French: "Vrai positif", "Faux positif", "Necessite une investigation"
- CWE identifiers and tool names stay English
- Phase 1 adds ALL translation keys needed by Phases 2-4 in one bulk pass
- Both en.json and fr.json updated in sync
- Existing fr.json keys trusted as-is -- no re-audit
- French role labels with English usernames for demo accounts: "Administrateur: admin / admin123", "Professeur: prof_jones / prof123", "Etudiant(e): alice_student / student123"
- Section header: "Comptes de demonstration"

### Claude's Discretion
- Which text fields localize() covers beyond title/description/remediation (e.g., category if beneficial)
- Exact namespace structure within fr.json SCA keys
- Whether to add DAST/VM translation keys while doing the bulk pass (not required but low cost)
- Exact French wording for all 12 finding translations (within Quebec French conventions decided above)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TRAN-01 | App defaults to French for all new sessions | One-line change in `utils/i18n.js` line 75: change `'en'` to `'fr'` in the default fallback. Verified by reading source -- session.language is never set automatically, so the default controls all new sessions. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express.js | 4.18 | Web framework | Already in use; no changes needed |
| EJS | 3.1 | Template engine | Already in use; t() already available via res.locals |
| utils/i18n.js | Custom | Translation function, middleware | Already in use; localize() extends this module |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| config/translations/fr.json | N/A | French translation strings | All new SCA keys added here |
| config/translations/en.json | N/A | English translation strings | Must stay in sync with fr.json |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| fr.json lookup for seed data | Dual-language fields in seedData.js (fr_title, etc.) | User decision locked: use fr.json pattern. The fr.json approach keeps translation content centralized and avoids modifying the database schema or seed data structure. |

**Installation:**
No new dependencies required. This is a constraint from the project decisions.

## Architecture Patterns

### Recommended Project Structure
```
config/translations/
  en.json              # Add SCA keys in sync with fr.json
  fr.json              # Add all SCA keys (bulk pass for Phases 1-4)
utils/
  i18n.js              # Add localize() function; change default lang to 'fr'
```

### Pattern 1: Default Language Change
**What:** Change the fallback language from `'en'` to `'fr'` in the languageMiddleware
**When to use:** Immediately -- this is the TRAN-01 requirement
**Example:**
```javascript
// Source: utils/i18n.js line 75 (current code)
// BEFORE:
const lang = req.session && req.session.language ? req.session.language : 'en';
// AFTER:
const lang = req.session && req.session.language ? req.session.language : 'fr';
```

### Pattern 2: Translation Key Namespacing
**What:** SCA translation keys follow the project's established dot-separated namespace pattern
**When to use:** When authoring all SCA keys for fr.json and en.json
**Example:**
```json
{
  "sca": {
    "studentLab": {
      "title": "Laboratoire d'analyse de code statique",
      "subtitle": "Examinez chaque constat, classifiez-le et documentez votre raisonnement -- puis soumettez quand vous etes pret.",
      "findingsSubmitted": "constats soumis",
      "complete": "termine",
      "startReview": "Commencer l'analyse",
      "continueReview": "Continuer",
      "viewEdit": "Voir / Modifier",
      "draftSaved": "Brouillon enregistre",
      "submitted": "Soumis"
    },
    "findingDetail": {
      "backToLab": "Laboratoire ACS",
      "location": "Emplacement",
      "codeSnippet": "Extrait de code",
      "description": "Description",
      "remediationGuidance": "Conseils de remediation",
      "yourReview": "Votre analyse",
      "submittedOn": "Soumis le",
      "classification": "Classification",
      "selectOption": "-- choisir --",
      "yourNotes": "Vos notes",
      "proposedRemediation": "Remediation proposee",
      "saveDraft": "Enregistrer le brouillon",
      "submit": "Soumettre",
      "studentReviews": "Analyses des etudiants",
      "vulnerabilityManager": "Gestionnaire de vulnerabilites",
      "importedToVM": "Importe dans le GV comme",
      "notImported": "Ce constat n'a pas encore ete importe dans le gestionnaire de vulnerabilites.",
      "pushToVM": "Envoyer au GV",
      "references": "References",
      "tool": "Outil"
    },
    "instructor": {
      "title": "Analyse de code statique -- Tableau de bord instructeur",
      "findingsOverview": "Apercu des constats",
      "studentProgressMatrix": "Matrice de progression des etudiants",
      "finding": "Constat",
      "file": "Fichier",
      "severity": "Severite",
      "reviews": "Analyses",
      "vm": "GV",
      "submitted": "soumis",
      "confirmed": "confirme",
      "fp": "FP",
      "inVM": "Dans GV",
      "pushToVM": "Envoyer au GV",
      "importing": "Importation..."
    },
    "studentDetail": {
      "backToDashboard": "Tableau de bord ACS",
      "reviewsTitle": "Analyses ACS : {username}",
      "student": "Etudiant",
      "reviewsSubmitted": "Analyses soumises",
      "finding": "Constat",
      "severity": "Severite",
      "classification": "Classification",
      "status": "Statut",
      "notes": "Notes",
      "notStarted": "Non commence",
      "view": "Voir"
    },
    "common": {
      "truePositive": "Vrai positif",
      "truePositiveDesc": "Vrai positif (vulnerabilite confirmee)",
      "falsePositive": "Faux positif",
      "needsInvestigation": "Necessite une investigation",
      "saving": "Enregistrement...",
      "savedDraft": "Brouillon enregistre.",
      "submittedSuccess": "Soumis !",
      "errorSaving": "Erreur lors de l'enregistrement.",
      "networkError": "Erreur reseau -- veuillez reessayer.",
      "findings": "constats",
      "students": "etudiants",
      "reviewsSubmitted": "analyses soumises"
    },
    "guided": {
      "introBannerTitle": "Comment aborder cet exercice",
      "introBannerText": "Pour chaque constat, lisez le code, identifiez si la vulnerabilite est reelle, et documentez votre raisonnement. Il n'y a pas de mauvaise reponse -- l'important est la qualite de votre analyse.",
      "dismiss": "Compris"
    },
    "difficulty": {
      "easy": "Facile",
      "medium": "Moyen",
      "advanced": "Avance"
    },
    "findings": {
      "1": {
        "title": "Secret de session code en dur",
        "description": "...",
        "remediation": "..."
      }
    }
  }
}
```

**Key structural decisions:**
- `sca.studentLab.*` -- student lab view labels
- `sca.findingDetail.*` -- finding detail view labels
- `sca.instructor.*` -- instructor dashboard labels
- `sca.studentDetail.*` -- student detail view labels
- `sca.common.*` -- shared classification labels, AJAX feedback messages
- `sca.guided.*` -- guided workflow banner text
- `sca.difficulty.*` -- difficulty indicator labels
- `sca.findings.{id}.{field}` -- per-finding translated content (title, description, remediation)

### Pattern 3: localize() Helper Function
**What:** A function that takes a finding object and language, returns a copy with translated text fields
**When to use:** In routes/sca.js (Phase 3) before passing findings to views
**Example:**
```javascript
// Source: to be added to utils/i18n.js
/**
 * Localize a seed data object by overlaying French translations from fr.json.
 * @param {object} finding - SCA finding object from database
 * @param {string} lang - Language code ('fr' or 'en')
 * @returns {object} Copy of finding with translated text fields
 */
function localize(finding, lang) {
  if (lang === 'en') return finding;

  const fields = ['title', 'description', 'remediation'];
  const localized = { ...finding };

  for (const field of fields) {
    const key = `sca.findings.${finding.id}.${field}`;
    const translated = t(lang, key);
    // t() returns the raw key string when translation is missing
    if (translated !== key) {
      localized[field] = translated;
    } else {
      console.warn(`localize: missing ${lang} translation for ${key}`);
    }
  }

  return localized;
}
```

**Key design decisions:**
- Returns a shallow copy (`{ ...finding }`) -- does not mutate the original object
- Uses the existing `t()` function internally for consistency
- Detects missing translations by checking if `t()` returned the raw key (established pattern in the codebase)
- Logs `console.warn()` for missing translations (matches existing i18n.js pattern at line 49)
- Only overlays `title`, `description`, `remediation` -- category and severity stay English per user decision
- Falls back to English (original seed data values) when French key is missing

### Pattern 4: Bulk Key Authoring for JSON Files
**What:** Add all SCA keys to both en.json and fr.json in a single pass
**When to use:** Phase 1 adds all keys upfront so Phases 2-4 can focus on template wiring
**Key scope identified from EJS template analysis:**

From `student-lab.ejs`:
- Page title, subtitle, progress labels, button labels (Start Review, Continue, View/Edit)
- Classification dropdown options, form labels, feedback messages
- Status badges (Submitted, Draft saved)

From `finding-detail.ejs`:
- Section headers (Location, Code Snippet, Description, Remediation Guidance, Your Review, References, Vulnerability Manager)
- Form labels and buttons (Classification, Your Notes, Proposed Remediation, Save Draft, Submit)
- VM import labels (Push to VM, Imported to VM)
- Student reviews section header and labels

From `instructor.ejs`:
- Dashboard title and subtitle format
- Table headers (Title, File, Severity, CWE, Reviews, VM)
- Progress labels (submitted, confirmed, FP)
- Matrix section title, student column headers
- VM import buttons (Push to VM, In VM, Importing...)

From `student-detail.ejs`:
- Page title format, back link
- Summary labels (Student, Reviews submitted)
- Table headers (Finding, Severity, Classification, Status, Notes)
- Status labels (Not started, View)

From `login.ejs` (Phase 2 will wire, but keys added now):
- Demo account labels, subtitle, form labels, button

From `header.ejs` (Phase 2 will wire, but keys added now):
- Navigation section titles (Main, Administration, Teaching, Learning, Security Labs)
- Nav link labels (Dashboard, Classes, Security Panel, Audit Logs, MFA Setup, Backups, etc.)
- User role display labels
- Logout button

### Anti-Patterns to Avoid
- **Modifying seedData.js to add fr_ fields:** User decision locked -- use fr.json lookup pattern instead. Seed data stays English-only; French comes from translation files via localize().
- **Changing database schema:** No schema changes. The localize() function operates on objects after they're read from the database, before they're passed to views.
- **Touching any EJS template in Phase 1:** This phase is infrastructure only. Template wiring is Phases 2-4.
- **Splitting key authoring across phases:** All keys go in now. Phases 2-4 should never need to add new translation keys (only wire existing ones to templates).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Nested key lookup | Custom dot-path resolver | Existing `t()` function | Already handles nested lookup, fallback, interpolation, and warning logging |
| Language detection | Browser Accept-Language parsing | Session-based default (`'fr'`) | Simpler, more reliable, and matches the "no toggle" decision |
| Translation file format | Custom format or YAML | Existing JSON structure | Both files already exist with 250+ keys; extend the pattern |

**Key insight:** The entire i18n infrastructure is already built and working. Phase 1 is about filling it with data and adding one small helper function, not building anything new.

## Common Pitfalls

### Pitfall 1: Forgetting to Update en.json in Sync
**What goes wrong:** Adding SCA keys to fr.json but not en.json. The English fallback chain works (`t()` falls back from fr to en), but if someone explicitly sets language to English, or if localize() is called with 'en', there should be clean English keys too.
**Why it happens:** Natural focus on French translation makes it easy to forget the English side.
**How to avoid:** Add every key to both files simultaneously. The en.json values are the same English strings currently hardcoded in the EJS templates.
**Warning signs:** `console.warn()` messages about missing English translations in the server console.

### Pitfall 2: t() Returns the Raw Key on Missing Translation
**What goes wrong:** The `t()` function returns the key string (e.g., `"sca.findings.1.title"`) when a translation is missing, not `undefined` or `null`. localize() must check for this by comparing the return value to the key itself.
**Why it happens:** This is the established behavior in `utils/i18n.js` lines 49-50 -- it returns the key as a fallback.
**How to avoid:** In localize(), compare `t()` result to the key: `if (translated !== key)`.
**Warning signs:** Users see dot-separated key paths instead of translated text.

### Pitfall 3: JSON Syntax Errors in Large Translation Files
**What goes wrong:** Adding 100+ keys to a JSON file makes it easy to introduce syntax errors (trailing commas, missing quotes, unescaped characters). A single syntax error prevents the entire file from loading, crashing the i18n system.
**Why it happens:** JSON is unforgiving about syntax. Quebec French uses many accented characters and apostrophes that need proper encoding.
**How to avoid:** Validate both JSON files after editing (e.g., `node -e "JSON.parse(require('fs').readFileSync('config/translations/fr.json'))"`). Use proper escaping for apostrophes in French text (JSON strings handle single quotes natively, but double quotes need `\"`).
**Warning signs:** Server crashes on startup with "Error loading translation files" message.

### Pitfall 4: Finding IDs Must Match Seed Data Exactly
**What goes wrong:** The localize() function builds keys like `sca.findings.${finding.id}.title`. If the JSON keys use different IDs than what's in the database, translations silently fail and English text is shown.
**Why it happens:** Seed data IDs are hardcoded integers 1-12 in `utils/seedData.js`. The JSON keys must use these exact same integer strings.
**How to avoid:** Cross-reference the 12 finding IDs from seedData.js (lines 179-251) when building the JSON keys. They are: 1 through 12, sequential.
**Warning signs:** localize() logs `console.warn()` for every finding despite keys being present in fr.json.

### Pitfall 5: Apostrophes in French Text
**What goes wrong:** Quebec French heavily uses apostrophes (l'analyse, d'audit, n'a, etc.). In JSON strings, single apostrophes are safe, but they can cause issues in EJS templates if the value is inserted into JavaScript string literals or HTML attributes with single quotes.
**Why it happens:** French grammar requires contractions (de + le = du, de + la = de la, but de + l' = de l').
**How to avoid:** Use standard JSON encoding (apostrophes are valid in JSON strings without escaping). When these values are later used in EJS templates (Phases 2-4), use `<%= t('key') %>` which safely outputs into HTML context, or `<%- JSON.stringify(t('key')) %>` for JavaScript contexts.
**Warning signs:** Broken HTML or JavaScript syntax errors in the browser console.

### Pitfall 6: localize() Must Export from i18n.js Module
**What goes wrong:** The localize() function is added to i18n.js but not exported in `module.exports`. Routes in Phase 3 that try to `require('./utils/i18n').localize` get `undefined`.
**Why it happens:** The module.exports on line 86-90 only exports `t`, `languageMiddleware`, and `translations`. Adding localize() to the file but forgetting to add it to exports.
**How to avoid:** Add `localize` to the existing module.exports object.
**Warning signs:** `TypeError: localize is not a function` errors when Phase 3 wires routes.

## Code Examples

Verified patterns from direct codebase analysis:

### Existing t() Function Usage (how it works)
```javascript
// Source: utils/i18n.js lines 29-68
// t() navigates nested JSON structure via dot-separated keys
// Example: t('fr', 'sca.common.truePositive')
//   -> navigates fr.json: sca -> common -> truePositive
//   -> returns "Vrai positif"
// Falls back to en.json if fr key missing, then returns raw key
```

### Existing languageMiddleware (the one-line change)
```javascript
// Source: utils/i18n.js lines 73-84
function languageMiddleware(req, res, next) {
  // CHANGE THIS LINE (line 75):
  // FROM: const lang = req.session && req.session.language ? req.session.language : 'en';
  // TO:   const lang = req.session && req.session.language ? req.session.language : 'fr';
  const lang = req.session && req.session.language ? req.session.language : 'fr';
  res.locals.t = (key, params) => t(lang, key, params);
  res.locals.currentLang = lang;
  next();
}
```

### localize() Function (to be created)
```javascript
// Source: to be added to utils/i18n.js
function localize(finding, lang) {
  if (lang === 'en') return finding;

  const fields = ['title', 'description', 'remediation'];
  const localized = { ...finding };

  for (const field of fields) {
    const key = `sca.findings.${finding.id}.${field}`;
    const translated = t(lang, key);
    if (translated !== key) {
      localized[field] = translated;
    } else {
      console.warn(`localize: missing ${lang} translation for ${key}`);
    }
  }

  return localized;
}

// Updated module.exports:
module.exports = {
  t,
  localize,
  languageMiddleware,
  translations
};
```

### Translation Key Structure (en.json addition example)
```json
{
  "sca": {
    "common": {
      "truePositive": "True Positive",
      "truePositiveDesc": "True Positive (confirmed vulnerability)",
      "falsePositive": "False Positive",
      "needsInvestigation": "Needs Further Investigation"
    },
    "findings": {
      "1": {
        "title": "Hardcoded Session Secret",
        "description": "The Express session secret is hardcoded in source code. Anyone with code access can forge session cookies, leading to authentication bypass.",
        "remediation": "Move the secret to an environment variable (SESSION_SECRET). Generate a cryptographically random 64-byte value for production."
      }
    }
  }
}
```

### JSON Validation Command
```bash
# Run after editing translation files to catch syntax errors
node -e "JSON.parse(require('fs').readFileSync('config/translations/fr.json','utf8')); console.log('fr.json OK')"
node -e "JSON.parse(require('fs').readFileSync('config/translations/en.json','utf8')); console.log('en.json OK')"
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in all views | i18n infrastructure exists but unused for SCA | Pre-existing | Phase 1 fills the data; Phases 2-4 wire templates |
| No seed data localization | localize() helper to overlay French from fr.json | Phase 1 adds this | Clean separation: seed data stays English, French comes from translation files |

**Deprecated/outdated:**
- The initial project research (`.planning/research/ARCHITECTURE.md`) recommended adding `fr_title`, `fr_description`, `fr_remediation` fields directly to seedData.js. This was overridden by the user's decision to use the fr.json lookup pattern instead. Do NOT follow the architecture document's "Approach A" recommendation.

## Open Questions

1. **Whether to add DAST/VM translation keys in the bulk pass**
   - What we know: User marked this as Claude's discretion. DAST/VM modules are out of scope for tonight's class (see REQUIREMENTS.md "Out of Scope").
   - What's unclear: The marginal cost is low but adds ~50 more keys to review.
   - Recommendation: Skip DAST/VM keys. The requirement explicitly says "Tonight is SCA-only; touching other modules risks regressions." Adding untested keys adds no value and creates potential for confusion.

2. **Exact text fields localize() should cover beyond title/description/remediation**
   - What we know: User marked this as Claude's discretion. The seed data has these fields per finding: `id`, `title`, `file_path`, `line_number`, `code_snippet`, `category`, `cwe`, `severity`, `description`, `tool`, `remediation`, `false_positive_reason`.
   - What's unclear: Whether `category` should be localized (e.g., "Hardcoded Credentials" -> "Identifiants codes en dur").
   - Recommendation: Do NOT localize `category`. User decision explicitly says "Category labels stay English: Hardcoded Credentials, Broken Access Control, Path Traversal, etc. -- match real SCA tool output." Only localize `title`, `description`, `remediation`. This keeps localize() simple and matches the user's intent that students learn industry-standard English terminology for categories.

3. **Complete French wording for all 12 finding translations**
   - What we know: User provided examples for some titles ("Secret de session code en dur", "Comparaison de mots de passe en clair"). Full prose in Quebec French is required for descriptions and remediation.
   - Recommendation: The planner should include a dedicated task for authoring all 12 finding translations (12 titles + 12 descriptions + 12 remediations = 36 French text blocks). This is the most time-intensive part of Phase 1.

## Seed Data Reference

The 12 SCA findings that need French translations (from `utils/seedData.js`):

| ID | English Title | Category | CWE | Severity |
|----|--------------|----------|-----|----------|
| 1 | Hardcoded Session Secret | Hardcoded Credentials | CWE-798 | Critical |
| 2 | Hardcoded AES Encryption Key | Hardcoded Credentials | CWE-321 | Critical |
| 3 | Plaintext Credentials Logged to Console | Sensitive Data Exposure | CWE-312 | High |
| 4 | Plaintext Password Comparison | Insecure Authentication | CWE-256 | Critical |
| 5 | Audit Logging Defaults to OFF | Security Misconfiguration | CWE-778 | High |
| 6 | IDOR: No Ownership Check on Enrollment Access | Broken Access Control | CWE-639 | High |
| 7 | No CSRF Protection on State-Changing Requests | CSRF | CWE-352 | High |
| 8 | Rate Limiting Only on Login Route | Security Misconfiguration | CWE-307 | Medium |
| 9 | No HTTP Security Headers | Security Misconfiguration | CWE-693 | Medium |
| 10 | Path Traversal in Backup Download | Path Traversal | CWE-22 | High |
| 11 | Outdated express-session with Known Vulnerabilities | Vulnerable Dependency | CWE-1035 | Medium |
| 12 | Session Cookie Missing secure Flag | Sensitive Cookie | CWE-614 | Medium |

## Complete Key Inventory

Summary of all translation keys to add, organized by namespace. This is the authoritative scope for the bulk JSON authoring task.

### sca.studentLab.* (~12 keys)
Page title, subtitle, progress counter labels, button text (Start Review, Continue, View/Edit), status badges (Submitted, Draft saved), code snippet label, classification label, form field labels, action buttons.

### sca.findingDetail.* (~20 keys)
Back link, section headers (Location, Code Snippet, Description, Remediation Guidance), review form labels, VM import labels, references section, student reviews header.

### sca.instructor.* (~15 keys)
Dashboard title, subtitle format, table headers, progress labels, matrix section title, VM action buttons.

### sca.studentDetail.* (~12 keys)
Back link, page title format, summary labels, table headers, status labels.

### sca.common.* (~12 keys)
Classification options (3), AJAX feedback messages (5), shared labels (findings, students, reviews).

### sca.guided.* (~3 keys)
Intro banner title, body text, dismiss button.

### sca.difficulty.* (~3 keys)
Facile, Moyen, Avance.

### sca.findings.{1-12}.* (~36 keys)
Title, description, remediation for each of 12 findings.

### login.* (~8 keys)
Demo account section header, role labels, subtitle, form labels, button, error title, info text.

### nav.* additions (~15 keys)
Navigation section titles, lab link labels, role display names.

**Estimated total: ~136 new keys** across both en.json and fr.json.

## Sources

### Primary (HIGH confidence)
- `utils/i18n.js` -- Direct code analysis of t(), languageMiddleware, module.exports (lines 1-91)
- `utils/seedData.js` -- Direct code analysis of 12 SCA finding definitions (lines 179-251)
- `config/translations/fr.json` -- Current 250+ French keys, namespace structure (290 lines)
- `config/translations/en.json` -- Current English keys matching fr.json structure (290 lines)
- `routes/sca.js` -- SCA route handlers showing how findings are queried and passed to views (182 lines)
- `views/sca/*.ejs` -- All 4 SCA EJS templates analyzed for hardcoded strings
- `views/login.ejs` -- Login page analyzed for demo account section
- `views/partials/header.ejs` -- Navigation sidebar analyzed for all link labels
- `routes/auth.js` -- set-language endpoint confirming session.language mechanics (line 190)
- `server.js` -- languageMiddleware usage confirmation (line 59)

### Secondary (MEDIUM confidence)
- `.planning/research/ARCHITECTURE.md` -- Previous project research (note: Approach A recommendation overridden by user decision)
- `.planning/research/PITFALLS.md` -- Previous project research confirming default language pitfall

### Tertiary (LOW confidence)
None -- all findings are from direct codebase analysis.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no external libraries, everything is existing custom code
- Architecture: HIGH -- patterns derived from direct codebase analysis, user decisions locked
- Pitfalls: HIGH -- all pitfalls verified by reading the actual source code

**Research date:** 2026-03-12
**Valid until:** 2026-03-19 (stable codebase, no expected upstream changes before tonight's class)
