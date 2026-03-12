# Technology Stack

**Project:** HEC Montreal SCA Lab Production Release
**Researched:** 2026-03-12
**Confidence:** HIGH -- all recommendations based on direct codebase analysis, no external dependencies

## Recommended Stack

No new dependencies. Every recommendation works within the existing stack.

### Core Framework (Existing -- No Changes)
| Technology | Version | Purpose | Status |
|------------|---------|---------|--------|
| Node.js | 22.x | Runtime | Locked by devcontainer image |
| Express | 4.18.x | HTTP server | Existing |
| EJS | 3.1.x | Templates | Existing |
| express-session | 1.17.x | Session management | Existing |

### i18n Infrastructure (Existing -- Needs Extension)
| Technology | Location | Purpose | Status |
|------------|----------|---------|--------|
| Custom i18n module | `utils/i18n.js` | Translation with dot-notation keys, `{param}` interpolation, English fallback | Existing, working |
| French translations | `config/translations/fr.json` | 290 keys covering common UI, auth, security, dashboard, etc. | Existing but missing SCA section |
| English translations | `config/translations/en.json` | Same structure as French | Existing but missing SCA section |
| Language middleware | `utils/i18n.js:languageMiddleware` | Injects `t()` and `currentLang` into `res.locals` | Existing, needs default-language fix |

### Real-time Updates (Existing -- Needs Extension)
| Technology | Location | Purpose | Status |
|------------|----------|---------|--------|
| HTTP polling | `classroom-manager.js` | Dashboard polls `/api/summary` every 60s, health every 30s | Existing |
| Client-side DOM update | Dashboard inline JS | Re-renders sections on fetch | Existing for classroom dashboard |
| setInterval + fetch | `views/partials/header.ejs` | Polls `/api/instructor-message` every 30s | Existing pattern |

### Codespaces Deployment (Existing -- Needs Verification)
| Technology | Location | Purpose | Status |
|------------|----------|---------|--------|
| devcontainer.json | `.devcontainer/devcontainer.json` | Container config, port forwarding, setup commands | Existing |
| classroom-manager.js | `scripts/classroom-manager.js` | Spawns 12 team instances + dashboard | Existing |
| Codespace URL detection | `classroom-manager.js:getExternalUrl()` | Generates correct URLs using CODESPACE_NAME env var | Existing |

## Key Technical Decisions

### 1. i18n: Extend Existing JSON Translation System

**Decision:** Add an `sca` section to `fr.json` (and `en.json` for fallback), then replace hardcoded strings in EJS views with `t()` calls.

**Why this approach (HIGH confidence):**

The existing i18n system is solid and already used across the platform. It supports:
- Nested dot-notation keys (`sca.lab.title`)
- Parameter interpolation (`{count}` syntax)
- English fallback when French key is missing
- Middleware that injects `t()` into every EJS template via `res.locals`

**What to do:**

1. **Add `sca` key block to `config/translations/fr.json`** with all SCA-specific strings:
   - Page titles, subtitles, button labels
   - Classification options (Vrai positif, Faux positif, Necessite une investigation)
   - Status labels (Soumis, Brouillon sauvegarde, etc.)
   - Form labels (Classification, Notes d'analyse, Remediation proposee)
   - Progress indicators ("X/Y resultats soumis", "X% complete")
   - Error messages and confirmation dialogs

2. **Mirror the same keys in `en.json`** to maintain structural parity.

3. **Replace hardcoded strings in 4 SCA views** with `<%= t('sca.xxx') %>`:
   - `views/sca/student-lab.ejs` -- ~25 hardcoded strings
   - `views/sca/instructor.ejs` -- ~20 hardcoded strings
   - `views/sca/finding-detail.ejs` -- ~20 hardcoded strings
   - `views/sca/student-detail.ejs` -- ~10 hardcoded strings

4. **Replace hardcoded strings in shared views**:
   - `views/partials/header.ejs` -- sidebar nav labels (~15 strings)
   - `views/login.ejs` -- login form labels (~8 strings)
   - `views/error.ejs` -- error messages (~3 strings)

5. **Change default language to French** in `utils/i18n.js`:
   ```javascript
   // Line 75: Change 'en' to 'fr'
   const lang = req.session && req.session.language ? req.session.language : 'fr';
   ```

6. **Set `<html lang="fr">` in header.ejs and login.ejs**.

**What NOT to do:**
- Do NOT add a language toggle UI -- out of scope, wastes time
- Do NOT install i18n libraries (i18next, i18n-node) -- the existing custom system works and is simpler
- Do NOT translate seed data descriptions in the database -- they display via `<%= finding.description %>` which is data, not UI strings
- Do NOT try to translate JavaScript alert/confirm dialogs tonight -- use inline DOM messages instead
- Do NOT create separate French EJS templates -- use the `t()` function in existing templates

**Quebec French specifics:**
- Use "courriel" not "email", "connexion" not "login" in user-facing text
- Use Quebec terminology: "Vrai positif" not "Positif confirme"
- The existing `fr.json` already uses appropriate Quebec French (e.g., "Televerser" not "Charger")

### 2. i18n: Handling Dynamic Content (SCA Finding Data)

**Decision:** Do NOT translate SCA finding data (titles, descriptions, code snippets, remediation). Translate only UI chrome.

**Why (HIGH confidence):**

SCA findings are seeded data stored in the database (`sca_findings` table). They contain:
- Technical English terms (CWE names, code variable names, file paths)
- Code snippets that must remain in English
- Descriptions referencing specific code patterns

Translating these would require:
- A parallel translation table or `_fr` columns in the database
- Changes to seed data logic
- Risk of translation errors in technical content

**The pragmatic approach:** Keep finding data in English (students at HEC understand English technical vocabulary). Translate the surrounding UI to French so the workflow feels native.

If enhanced finding descriptions are needed in French, add them to seed data directly -- not through the i18n system.

### 3. Real-Time Dashboard: Polling with setInterval

**Decision:** Add client-side polling (every 15-30s) to the instructor SCA view at `/sca`, hitting existing API endpoints.

**Why this approach (HIGH confidence):**

The codebase already has two proven polling patterns:
1. **Classroom manager dashboard** (`classroom-manager.js`): Client polls `/api/instances` every 30s and `/api/class-overview` every 60s, then re-renders DOM sections.
2. **Instructor broadcast** (`header.ejs`): Client polls `/api/instructor-message` every 30s.

Both patterns work identically: `setInterval(() => fetch(url).then(render), interval)`.

**What to do:**

1. **Create a new API endpoint** `GET /sca/api/progress` on the SCA routes that returns the matrix data as JSON:
   ```javascript
   router.get('/api/progress', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
     const findings = db.prepare('SELECT * FROM sca_findings').all();
     const students = db.prepare('SELECT * FROM users WHERE role = ?').all('student');
     const allReviews = db.prepare('SELECT * FROM sca_student_reviews').all();
     // Build matrix, compute stats...
     res.json({ findings, students, matrix, stats, timestamp: new Date().toISOString() });
   });
   ```

2. **Add a `<script>` block to `views/sca/instructor.ejs`** that polls this endpoint every 15-20 seconds and updates:
   - The summary stats bar (total reviews submitted)
   - The progress bars per finding
   - The student progress matrix cells
   - Class consensus indicators (how many confirmed vs FP)

3. **Use DOM manipulation** (same pattern as classroom-manager.js) -- not full page reload.

**What NOT to do:**
- Do NOT add WebSocket/Socket.io -- out of scope, adds dependency, massive complexity for 30-student class
- Do NOT use Server-Sent Events (SSE) -- adds complexity for no benefit at this scale
- Do NOT poll faster than every 15s -- unnecessary for classroom use, adds server load across 12 instances
- Do NOT poll from student views -- students see their own data (no need for real-time updates of others)

**Polling interval recommendation:** 20 seconds. Rationale:
- Fast enough that instructor sees new submissions within 20s
- Slow enough that 12 instances with ~3 students each don't overload anything
- Matches the existing broadcast polling pattern in the codebase

### 4. Codespaces Deployment Reliability

**Decision:** Verify and harden the existing devcontainer setup. No architectural changes.

**Why (HIGH confidence):**

The existing Codespaces setup is already well-architected:
- `devcontainer.json` declares all 13 ports
- `postCreateCommand` runs `npm install && node scripts/setup.js`
- `postStartCommand` runs `npm start` (classroom-manager)
- `classroom-manager.js` handles Codespace URL detection via `CODESPACE_NAME` and `GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN`
- Health checks with 30s polling + auto-restart capability

**What to verify/harden:**

1. **Port visibility**: Ensure student ports (3001-3012) are set to "public" in Codespaces port settings, or students won't be able to access their instances. The `devcontainer.json` sets `onAutoForward: "silent"` for team ports but does NOT set visibility. Default is private.

   Fix: Add `"visibility": "public"` to port attributes OR document the manual step to make ports public after Codespace creation.

   ```json
   "3001": { "label": "Team Alpha", "onAutoForward": "silent", "visibility": "public" }
   ```

   **CRITICAL:** Without public port visibility, students outside the Codespace owner's session cannot access the app. This is the most likely deployment failure.

2. **Startup race condition**: `postStartCommand` runs `npm start` which spawns 12 instances simultaneously. If `npm install` or setup hasn't fully completed, instances may fail. The existing `postCreateCommand` handles this (runs first), but verify the setup.js script completes without errors.

3. **Data seeding on first boot**: Each team instance runs `server.js` which calls `initializeDatabase()` and `seedDatabase()` if empty. This happens per-instance with isolated `DATA_DIR`. Verify seed data includes all 12 SCA findings per instance.

4. **Memory in Codespaces**: 12 Node.js processes + 1 dashboard = 13 processes. Default Codespace (4-core, 16GB) should handle this. If using 2-core, reduce to 6 teams via `TEAM_COUNT=6`.

5. **URL sharing**: The instructor needs to share team URLs with students. The classroom manager dashboard already shows these URLs. Verify they render correctly in Codespaces mode.

**What NOT to do:**
- Do NOT change the devcontainer image -- the existing `mcr.microsoft.com/devcontainers/javascript-node:22` is correct
- Do NOT add Docker Compose -- overengineered for this use case
- Do NOT change from `postStartCommand` to a lifecycle script -- the existing approach works
- Do NOT try to automate Codespace creation for students -- they just need the URL

### 5. Error Handling for Non-Technical Users

**Decision:** Replace English error strings with French translations using existing `t()` function. Add user-friendly fallbacks.

**What to do:**

1. **Add SCA-specific error keys to `fr.json`**:
   - `sca.errors.findingNotFound`: "Resultat non trouve"
   - `sca.errors.invalidClassification`: "Classification invalide"
   - `sca.errors.saveFailed`: "Erreur lors de la sauvegarde. Veuillez reessayer."
   - `sca.errors.networkError`: "Erreur de connexion. Verifiez votre connexion et reessayez."

2. **Update client-side JS messages** in `views/sca/student-lab.ejs`:
   - Replace `'Saving...'` with French equivalents
   - Replace `'Submitted!'` / `'Draft saved.'` with French
   - Replace `'Network error -- please try again.'` with French

3. **Update `views/error.ejs`** to use `t()` for "Back to Dashboard" link text.

## Translation Key Structure

Recommended key organization for the new `sca` section in `fr.json`:

```json
{
  "sca": {
    "lab": {
      "title": "Laboratoire d'analyse statique de code",
      "subtitle": "Examinez chaque resultat, classifiez-le et documentez votre raisonnement, puis soumettez.",
      "findingsSubmitted": "resultats soumis",
      "complete": "complete"
    },
    "instructor": {
      "title": "Analyse statique de code -- Tableau de bord instructeur",
      "findingsOverview": "Apercu des resultats",
      "studentProgressMatrix": "Matrice de progression des etudiants",
      "reviews": "evaluations",
      "submitted": "soumis",
      "confirmed": "confirme",
      "fp": "FP"
    },
    "finding": {
      "location": "Emplacement",
      "codeSnippet": "Extrait de code",
      "description": "Description",
      "remediationGuidance": "Guide de remediation",
      "studentReviews": "Evaluations des etudiants",
      "yourReview": "Votre evaluation",
      "references": "References",
      "vulnManager": "Gestionnaire de vulnerabilites",
      "importedToVM": "Importe dans le GV",
      "notImported": "Ce resultat n'a pas encore ete importe dans le gestionnaire de vulnerabilites.",
      "pushToVM": "Envoyer au GV"
    },
    "review": {
      "classification": "Classification",
      "selectClassification": "-- selectionner --",
      "truePositive": "Vrai positif (vulnerabilite confirmee)",
      "falsePositive": "Faux positif",
      "needsInvestigation": "Necessite une investigation supplementaire",
      "analysisNotes": "Vos notes d'analyse",
      "analysisPlaceholder": "Expliquez pourquoi vous avez classifie de cette facon...",
      "proposedRemediation": "Remediation proposee",
      "remediationPlaceholder": "Comment corrigeriez-vous cela?",
      "saveDraft": "Sauvegarder le brouillon",
      "submit": "Soumettre",
      "cancel": "Annuler",
      "submittedOn": "Soumis le"
    },
    "status": {
      "submitted": "Soumis",
      "draftSaved": "Brouillon sauvegarde",
      "notStarted": "Non commence",
      "startReview": "Commencer l'evaluation",
      "continue": "Continuer",
      "viewEdit": "Voir / Modifier"
    },
    "messages": {
      "saving": "Sauvegarde en cours...",
      "submitSuccess": "Soumis avec succes!",
      "draftSaveSuccess": "Brouillon sauvegarde.",
      "networkError": "Erreur de connexion. Veuillez reessayer.",
      "saveError": "Erreur lors de la sauvegarde."
    },
    "student": {
      "title": "Evaluations SCA",
      "reviewsSubmitted": "Evaluations soumises",
      "finding": "Resultat",
      "severity": "Severite",
      "classification": "Classification",
      "status": "Statut",
      "notes": "Notes",
      "view": "Voir"
    },
    "table": {
      "title": "Titre",
      "file": "Fichier",
      "severity": "Severite",
      "cwe": "CWE",
      "reviews": "Evaluations",
      "vm": "GV"
    }
  }
}
```

## Sidebar/Header Translation Keys

```json
{
  "nav": {
    "main": "Principal",
    "dashboard": "Tableau de bord",
    "classes": "Cours",
    "administration": "Administration",
    "securityPanel": "Panneau de securite",
    "auditLogs": "Journaux d'audit",
    "mfaSetup": "Configuration MFA",
    "backups": "Sauvegardes",
    "teaching": "Enseignement",
    "myClasses": "Mes cours",
    "learning": "Apprentissage",
    "myEnrollments": "Mes inscriptions",
    "securityLabs": "Laboratoires de securite",
    "staticAnalysis": "Analyse statique",
    "dynamicAnalysis": "Analyse dynamique",
    "vulnManagement": "Gestion des vulnerabilites",
    "pentestLab": "Laboratoire de pentest",
    "logout": "Deconnexion",
    "securityStatus": "Statut de securite"
  }
}
```

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| i18n library | Existing custom `utils/i18n.js` | i18next, i18n-node | No new dependencies constraint. Custom system already works with the exact feature set needed. |
| Real-time updates | setInterval + fetch (polling) | WebSocket (Socket.io) | Out of scope per PROJECT.md. Polling is sufficient for 30 students. Adds dependency. |
| Real-time updates | setInterval + fetch | Server-Sent Events (SSE) | More complex server-side setup, no significant benefit at this scale. |
| Template engine | EJS with `t()` calls | Separate French template files | Duplicates views, nightmare to maintain, defeats purpose of i18n system. |
| Translation storage | JSON files | Database table | Adds migration complexity. JSON files load once at startup, fast and simple. |
| Codespaces | Single Codespace with 12 instances | One Codespace per team | Massively more complex to manage. Current approach works for classroom setting. |

## Implementation Priority Order

Given tonight's time pressure, implement in this order:

1. **Translation JSON updates** (fr.json + en.json) -- Pure data, zero risk of breaking anything
2. **Default language flip** (one line in i18n.js) -- Instant win, affects all pages
3. **SCA student-lab.ejs translation** -- Most critical student-facing view
4. **Login page translation** -- First thing students see
5. **Header/sidebar translation** -- Persistent navigation
6. **SCA finding-detail.ejs translation** -- Primary student interaction page
7. **SCA instructor.ejs translation** -- Instructor-facing
8. **Instructor dashboard polling** -- Enhancement, not blocking
9. **SCA student-detail.ejs translation** -- Low-traffic instructor view
10. **Error page translation** -- Edge case

Items 1-6 are critical for tonight. Items 7-8 are important. Items 9-10 are nice-to-have.

## Codespaces Pre-Flight Checklist

Before class tonight, verify:

- [ ] `npm start` in Codespace spawns all 12 instances + dashboard
- [ ] All instances reach "online" status within 60s
- [ ] Each instance has 12 SCA findings seeded
- [ ] Student login works (alice_student / student123)
- [ ] SCA lab renders in French for student view
- [ ] Instructor dashboard at port 3000 shows all team health
- [ ] Team URLs are accessible (port visibility set to public)
- [ ] Instructor can see student progress matrix
- [ ] Student can save draft and submit review
- [ ] French error messages display on invalid actions

## Sources

- Direct codebase analysis (all files read and verified)
- `utils/i18n.js` -- existing i18n implementation
- `config/translations/fr.json` -- existing French translations (290 keys)
- `views/sca/*.ejs` -- all 4 SCA templates (hardcoded English confirmed)
- `views/partials/header.ejs` -- hardcoded sidebar navigation
- `scripts/classroom-manager.js` -- existing polling patterns
- `.devcontainer/devcontainer.json` -- Codespaces configuration
- `server.js` -- middleware chain, language middleware already mounted
- `routes/sca.js` -- SCA route handlers, API patterns
- `package.json` -- dependency list (confirmed no i18n library)
