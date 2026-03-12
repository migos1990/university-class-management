# Phase 2: Shared UI Translation - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Translate login page, sidebar navigation, and error page to Quebec French. Students see French from the moment they open the application. All translation keys already exist in fr.json from Phase 1 — this phase wires `t()` calls into EJS templates.

</domain>

<decisions>
## Implementation Decisions

### Security status bar
- Security badges stay in English: "MFA: ON", "RBAC: ON", "Passwords: Encrypted", etc. — industry-standard terms students should learn
- The "Security Status:" label translates to "État de sécurité :" — it's UI chrome, not a technical term
- Sidebar subtitle under "HEC Montréal" translates from "Application Security" to "Sécurité applicative"

### Navigation translation scope
- Translate ALL sidebar items — not just student-visible ones
- Section titles in French: "Principal", "Administration", "Enseignement", "Apprentissage", "Laboratoires de sécurité" (or Claude's best fit)
- Lab names in French: "Analyse statique", "Analyse dynamique", "Gestion des vulnérabilités", "Test d'intrusion"
- Admin links in French: "Panneau de sécurité", "Journaux d'audit", "Configuration AMF", "Sauvegardes" (or Claude's best fit)
- General links: "Tableau de bord", "Cours", "Déconnexion"
- Instructor broadcast banner dismiss button: translate to French ("Fermer")

### Error page
- Distinct French messages per error code:
  - 404: "Page introuvable" with guidance
  - 403: "Accès refusé" with guidance
  - 429: "Trop de tentatives" with guidance
  - 500: Generic "Erreur du serveur" with guidance
- "Back to Dashboard" button: "Retour au tableau de bord" — matches nav terminology
- Stack trace label stays English (developer-facing, not student-visible)

### Role display
- Translate role labels via t() mapping: student → "Étudiant(e)", professor → "Professeur(e)", admin → "Administrateur(-trice)"
- Inclusive parenthetical form for gendered roles — matches Phase 1 demo account labels
- Logout button: "Déconnexion"

### Login page
- Subtitle: translate "Application Security Learning Platform" to French
- Footer text: translate "Educational application security demonstration platform" to French
- Error message: "Échec de connexion" for "Login Failed"
- Form labels: "Nom d'utilisateur", "Mot de passe", "Connexion" (button)
- Demo accounts section uses Phase 1 decided format: "Administrateur", "Professeur", "Étudiant(e)"

### HTML metadata
- Change `<html lang="en">` to `<html lang="fr">` in all three templates (login.ejs, header.ejs, error.ejs)
- Browser tab titles in French: "Connexion - HEC Montréal Sécurité applicative", "Erreur - HEC Montréal Sécurité applicative"

### Claude's Discretion
- Exact French wording for nav section titles and admin links (within Quebec French conventions)
- Exact French phrasing for error page guidance text per status code
- Whether to translate the header.ejs default title fallback ("HEC Montréal - Application Security")

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/i18n.js`: t() function already available in all EJS views via `res.locals.t` — just replace hardcoded strings with `t('key')` calls
- `config/translations/fr.json`: All needed keys already added in Phase 1 (nav.*, auth.*, errors.*, dashboard.*)
- `res.locals.currentLang`: Language code available in all views for conditional logic if needed

### Established Patterns
- EJS templates use `<%= t('key') %>` for translation lookups
- Dot-separated key namespaces: `nav.dashboard`, `auth.login`, `errors.notFound`
- Missing translation falls back to English via i18n.js warning pattern

### Integration Points
- `views/login.ejs`: Standalone page (no partials), all strings hardcoded English — replace with t() calls
- `views/partials/header.ejs`: Included by all authenticated pages — sidebar nav, security bar, user profile section
- `views/error.ejs`: Standalone error page rendered by global error handler in server.js and rate limiter in middleware/rateLimiter.js
- `server.js` error handlers pass `message` and `error` object to error.ejs — may need to translate messages at the handler level or in the template

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches within the decisions above.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 02-shared-ui-translation*
*Context gathered: 2026-03-12*
