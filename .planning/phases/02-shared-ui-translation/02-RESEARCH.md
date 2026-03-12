# Phase 2: Shared UI Translation - Research

**Researched:** 2026-03-12
**Domain:** EJS template i18n (string replacement with existing translation infrastructure)
**Confidence:** HIGH

## Summary

Phase 2 is a pure template-editing phase. All translation keys already exist in `config/translations/fr.json` and `config/translations/en.json` from Phase 1. The `t()` function is already available in every EJS view via `res.locals.t`. The work is mechanical: replace every hardcoded English string in three template files (`login.ejs`, `partials/header.ejs`, `error.ejs`) with `<%= t('key') %>` calls, change `<html lang="en">` to `<html lang="fr">`, and update browser tab titles.

There are a few integration points that require care: (1) the error handler in `server.js` passes a hardcoded English `message` string to error.ejs -- the template must translate this at render time rather than relying on the server to send French; (2) the rate limiter in `middleware/rateLimiter.js` also renders error.ejs with hardcoded English -- same template-side translation strategy applies; (3) the auth route renders login.ejs with hardcoded English error messages. Additionally, some nav items in the sidebar (Security Panel, MFA Setup, Static Analysis, Dynamic Analysis, Vuln Management, Pentest Lab, My Classes, My Enrollments) need new translation keys since Phase 1 used different key names.

**Primary recommendation:** Replace hardcoded strings in templates with `t()` calls using existing keys. For the ~8 missing sidebar-specific keys, add them to both JSON files. Handle error page translation by mapping `error.status` codes to translation keys inside the EJS template itself.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Security badges stay in English: "MFA: ON", "RBAC: ON", "Passwords: Encrypted", etc. -- industry-standard terms students should learn
- The "Security Status:" label translates to "Etat de securite :" -- it is UI chrome, not a technical term
- Sidebar subtitle under "HEC Montreal" translates from "Application Security" to "Securite applicative"
- Translate ALL sidebar items -- not just student-visible ones
- Section titles in French: "Principal", "Administration", "Enseignement", "Apprentissage", "Laboratoires de securite" (or Claude's best fit)
- Lab names in French: "Analyse statique", "Analyse dynamique", "Gestion des vulnerabilites", "Test d'intrusion"
- Admin links in French: "Panneau de securite", "Journaux d'audit", "Configuration AMF", "Sauvegardes" (or Claude's best fit)
- General links: "Tableau de bord", "Cours", "Deconnexion"
- Instructor broadcast banner dismiss button: translate to French ("Fermer")
- Distinct French messages per error code: 404 "Page introuvable", 403 "Acces refuse", 429 "Trop de tentatives", 500 "Erreur du serveur" -- each with guidance
- "Back to Dashboard" button: "Retour au tableau de bord" -- matches nav terminology
- Stack trace label stays English (developer-facing, not student-visible)
- Translate role labels via t() mapping: student -> "Etudiant(e)", professor -> "Professeur(e)", admin -> "Administrateur(-trice)"
- Inclusive parenthetical form for gendered roles -- matches Phase 1 demo account labels
- Logout button: "Deconnexion"
- Login page subtitle: translate "Application Security Learning Platform" to French
- Login page footer text: translate "Educational application security demonstration platform" to French
- Login page error message: "Echec de connexion" for "Login Failed"
- Login form labels: "Nom d'utilisateur", "Mot de passe", "Connexion" (button)
- Demo accounts section uses Phase 1 decided format: "Administrateur", "Professeur", "Etudiant(e)"
- Change `<html lang="en">` to `<html lang="fr">` in all three templates (login.ejs, header.ejs, error.ejs)
- Browser tab titles in French: "Connexion - HEC Montreal Securite applicative", "Erreur - HEC Montreal Securite applicative"

### Claude's Discretion
- Exact French wording for nav section titles and admin links (within Quebec French conventions)
- Exact French phrasing for error page guidance text per status code
- Whether to translate the header.ejs default title fallback ("HEC Montreal - Application Security")

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| TRAN-06 | Header/sidebar navigation translated to French (all nav links, role badges, team name) | Existing keys: `nav.main`, `nav.administration`, `nav.teaching`, `nav.learning`, `nav.securityLabs`, `common.dashboard`, `nav.classes`, `common.logout`, `nav.roleAdmin`, `nav.roleProf`, `nav.roleStudent`. Missing keys needed for: securityPanel, mfaSetup, staticAnalysis, dynamicAnalysis, vulnManagement, pentestLab, myClasses, myEnrollments, securityStatus label, sidebar subtitle. The `t()` function is available in all views. |
| TRAN-07 | Login page fully translated to French | Existing keys cover all needed strings: `login.subtitle`, `login.formTitle`, `auth.username`, `auth.password`, `auth.loginButton`/`common.login`, `login.demoAccounts`, `login.demoAdmin`, `login.demoProf`, `login.demoStudent`. The login.ejs template is standalone with all strings hardcoded. |
| TRAN-08 | Error page translated to French | Existing keys: `errors.pageNotFound`, `errors.serverError`, `errors.forbidden`, `errors.goHome`. Need new keys for: per-status-code titles, per-status-code guidance text, and 429 rate limit message. Template must do status-code-based translation since server passes English strings. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| EJS | (existing) | Template engine | Already in use; `<%= t('key') %>` pattern established |
| utils/i18n.js | (custom) | Translation function | `t(lang, key, params)` with English fallback, parameter interpolation via `{param}` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| config/translations/fr.json | (Phase 1) | French translation strings | All `t()` calls resolve here |
| config/translations/en.json | (Phase 1) | English fallback strings | Fallback when French key missing |

### Alternatives Considered
None -- this phase uses the existing stack exclusively. No new dependencies per project constraint.

**Installation:**
```bash
# No installation needed -- all infrastructure exists from Phase 1
```

## Architecture Patterns

### Established Translation Pattern
The project uses a simple key-value translation system:
```
res.locals.t = (key, params) => t(lang, key, params)
```

In templates:
```ejs
<%= t('nav.dashboard') %>
```

With parameter interpolation:
```ejs
<%= t('sca.studentLab.progress', { count: 5, total: 12 }) %>
```

### Pattern 1: Direct String Replacement
**What:** Replace every hardcoded English string with a `t('key')` call
**When to use:** For static text that has a 1:1 French equivalent
**Example:**
```ejs
<!-- Before -->
<span>Dashboard</span>

<!-- After -->
<span><%= t('common.dashboard') %></span>
```

### Pattern 2: Status-Code-Based Translation in Error Template
**What:** Map HTTP status codes to translation keys inside the EJS template, rather than translating at the server level
**When to use:** When the server passes English strings (like `message: 'Page not found'`) that cannot be easily changed without modifying multiple server-side call sites
**Example:**
```ejs
<%
  // Map status codes to translation keys
  const statusCode = error && error.status ? error.status : 500;
  const titleMap = {
    404: t('errors.notFound.title'),
    403: t('errors.forbidden.title'),
    429: t('errors.tooManyAttempts.title'),
  };
  const guidanceMap = {
    404: t('errors.notFound.guidance'),
    403: t('errors.forbidden.guidance'),
    429: t('errors.tooManyAttempts.guidance'),
  };
  const errorTitle = titleMap[statusCode] || t('errors.serverError.title');
  const errorGuidance = guidanceMap[statusCode] || t('errors.serverError.guidance');
%>
<h1><%= errorTitle %></h1>
<p class="error-message"><%= errorGuidance %></p>
```

### Pattern 3: Role Translation via t() Mapping
**What:** Map the English role string from the database to a translated display name
**When to use:** For user.role which is stored as 'admin', 'professor', 'student' in the database
**Example:**
```ejs
<%
  const roleKey = {
    admin: 'nav.roleAdmin',
    professor: 'nav.roleProf',
    student: 'nav.roleStudent'
  };
%>
<div class="user-role"><%= t(roleKey[user.role] || user.role) %></div>
```

### Anti-Patterns to Avoid
- **Translating at the server level for error messages:** The error handler in `server.js` and the rate limiter in `rateLimiter.js` both pass English strings. Do NOT modify these server files; translate at the template level by using the status code to select the right translation key. This is additive-only (project constraint) and avoids touching shared infrastructure.
- **Adding t() calls inside `<style>` or `<script>` blocks:** Only translate visible user-facing text in HTML elements.
- **Forgetting the lang attribute:** All three files currently have `<html lang="en">` -- must change to `<html lang="fr">`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation system | Custom i18n | Existing `utils/i18n.js` | Already working, tested in Phase 1 |
| Language detection | Accept-Language parsing | `req.session.language` defaulting to 'fr' | Already configured in languageMiddleware |
| Missing key handling | Manual fallback logic | i18n.js built-in English fallback | Handles gracefully with console warning |

**Key insight:** This phase adds ZERO new infrastructure. Every tool is already in place.

## Common Pitfalls

### Pitfall 1: Ignoring the Error Handler's English Strings
**What goes wrong:** The `server.js` error handler (line 235-242) passes `message: err.message || 'An error occurred'` and the 404 handler (line 245-249) passes `message: 'Page not found'`. If you only replace `<h1><%= message %></h1>` with a t() call, you lose the ability to show dynamic error messages.
**Why it happens:** Template receives English from server; naively wrapping in t() won't match any key.
**How to avoid:** Use status-code-based lookup in the template (Pattern 2 above). Ignore the `message` variable for the h1; use it only as a fallback for unexpected error types.
**Warning signs:** Error page shows translation keys instead of French text.

### Pitfall 2: Rate Limiter Renders Error Page with Hardcoded English
**What goes wrong:** `middleware/rateLimiter.js` line 46-52 renders error.ejs with `message: 'Too Many Login Attempts'` and `error.details` containing an English sentence with dynamic data.
**Why it happens:** The rate limiter constructs its own English strings server-side.
**How to avoid:** In the error template, detect status 429 and show the translated title/guidance. For the dynamic "try again in X minutes" text, the `error.details` string can be hidden if a translated equivalent is provided, OR the template can use `error.details` as-is (it contains useful timing data). Best approach: add a new translation key with `{minutes}` parameter and construct the French string in the template using the remaining minutes from error.details.
**Warning signs:** 429 error page shows English "Too Many Login Attempts" instead of French.

### Pitfall 3: Missing Translation Keys for Sidebar Items
**What goes wrong:** Phase 1 added nav keys like `nav.scaLab`, `nav.dastLab`, `nav.pentestLab`, `nav.vmLab` but the sidebar uses different display names. Also, some sidebar items have no corresponding key.
**Why it happens:** Phase 1 keys were designed for the nav namespace but sidebar has items like "Security Panel", "MFA Setup", "My Classes", "My Enrollments" that don't map to existing keys.
**How to avoid:** Audit every sidebar string and map to existing keys or add new ones.
**Warning signs:** Sidebar shows raw keys like `nav.securityPanel` instead of French text.

### Pitfall 4: Forgetting to Translate the Title Tag
**What goes wrong:** Browser tab shows English text.
**Why it happens:** The `<title>` tag is easy to overlook since it's not visible on the page.
**How to avoid:** Explicitly change all three `<title>` tags per user decisions.

### Pitfall 5: Breaking EJS Syntax with Quotes in French
**What goes wrong:** French strings containing apostrophes (e.g., "Nom d'utilisateur") could break EJS if placed directly in attributes.
**Why it happens:** French uses apostrophes frequently.
**How to avoid:** All strings come from `t()` which returns from JSON (already properly escaped). The `<%= %>` EJS tag HTML-escapes output by default. No issue as long as we use `<%= t('key') %>` and NOT `<%- t('key') %>`.

## Code Examples

### Login Page: Full t() Replacement Pattern
```ejs
<!-- login.ejs: title tag -->
<title><%= t('login.formTitle') %> - HEC Montr&eacute;al <%= t('login.subtitle') %></title>

<!-- login.ejs: subtitle -->
<p class="subtitle"><%= t('login.subtitle') %></p>

<!-- login.ejs: error alert -->
<div class="alert-danger-title"><%= t('auth.invalidCredentials') %></div>

<!-- login.ejs: form labels -->
<label for="username"><%= t('auth.username') %></label>
<label for="password"><%= t('auth.password') %></label>
<button type="submit" class="btn"><%= t('common.login') %></button>

<!-- login.ejs: demo accounts -->
<h3><%= t('login.demoAccounts') %> :</h3>
<p><strong><%= t('login.demoAdmin') %></strong></p>
<p><strong><%= t('login.demoProf') %></strong></p>
<p><strong><%= t('login.demoStudent') %></strong></p>
```

### Sidebar: Navigation with t() Calls
```ejs
<!-- Section title -->
<div class="nav-section-title"><%= t('nav.main') %></div>

<!-- Nav link -->
<a href="/dashboard" class="nav-link">
  <span class="nav-icon">&#x1F4CA;</span>
  <span><%= t('common.dashboard') %></span>
</a>

<!-- Role display -->
<div class="user-role"><%= t('nav.role' + user.role.charAt(0).toUpperCase() + user.role.slice(1)) %></div>
<!-- OR use a lookup map as in Pattern 3 -->

<!-- Logout -->
<a href="/auth/logout" class="logout-btn"><%= t('common.logout') %></a>
```

### Error Page: Status-Code-Based Translation
```ejs
<html lang="fr">
<head>
  <title><%= t('common.error') %> - HEC Montr&eacute;al <%= t('login.subtitle') %></title>
</head>
```

## Key-to-Template Mapping

### Existing Keys That Map Directly

| Template | Hardcoded English | Translation Key | French Value |
|----------|------------------|-----------------|--------------|
| login.ejs | "Application Security Learning Platform" | `login.subtitle` | "Plateforme pedagogique de securite applicative" |
| login.ejs | "Login Failed" | `auth.invalidCredentials` | (use for error title) |
| login.ejs | "Username" | `auth.username` | "Nom d'utilisateur" |
| login.ejs | "Password" | `auth.password` | "Mot de passe" |
| login.ejs | "Login" (button) | `common.login` | "Connexion" |
| login.ejs | "Default Accounts:" | `login.demoAccounts` | "Comptes de demonstration" |
| login.ejs | "Admin: admin / admin123" | `login.demoAdmin` | "Administrateur : admin / admin123" |
| login.ejs | "Professor: prof_jones / prof123" | `login.demoProf` | "Professeur : prof_jones / prof123" |
| login.ejs | "Student: alice_student / student123" | `login.demoStudent` | "Etudiant(e) : alice_student / student123" |
| login.ejs | "Educational application..." | (need new key or use `login.subtitle`) | (see below) |
| header.ejs | "Application Security" | (need key: `nav.appSubtitle`) | "Securite applicative" |
| header.ejs | "Main" | `nav.main` | "Principal" |
| header.ejs | "Dashboard" | `common.dashboard` | "Tableau de bord" |
| header.ejs | "Classes" | `nav.classes` | "Cours" |
| header.ejs | "Administration" | `nav.administration` | "Administration" |
| header.ejs | "Teaching" | `nav.teaching` | "Enseignement" |
| header.ejs | "Learning" | `nav.learning` | "Apprentissage" |
| header.ejs | "Security Labs" | `nav.securityLabs` | "Laboratoires de securite" |
| header.ejs | "Logout" | `common.logout` | "Deconnexion" |
| header.ejs | "Security Status:" | (need key) | "Etat de securite :" |
| header.ejs | "Dismiss" | `common.close` | "Fermer" |
| error.ejs | "Back to Dashboard" | (need key) | "Retour au tableau de bord" |

### Keys That Need to Be Added to Both JSON Files

| Key | English | French | Reason |
|-----|---------|--------|--------|
| `nav.securityPanel` | "Security Panel" | "Panneau de securite" | Sidebar admin link |
| `nav.mfaSetup` | "MFA Setup" | "Configuration AMF" | Sidebar admin link |
| `nav.staticAnalysis` | "Static Analysis" | "Analyse statique" | Sidebar lab link |
| `nav.dynamicAnalysis` | "Dynamic Analysis" | "Analyse dynamique" | Sidebar lab link |
| `nav.vulnManagement` | "Vuln Management" | "Gestion des vulnerabilites" | Sidebar lab link |
| `nav.pentestLab` | "Pentest Lab" | "Test d'intrusion" | Sidebar lab link |
| `nav.myClasses` | "My Classes" | "Mes cours" | Sidebar professor link |
| `nav.myEnrollments` | "My Enrollments" | "Mes inscriptions" | Sidebar student link |
| `nav.appSubtitle` | "Application Security" | "Securite applicative" | Sidebar header subtitle |
| `nav.securityStatus` | "Security Status:" | "Etat de securite :" | Security bar label |
| `login.footerText` | "Educational application security demonstration platform" | "Plateforme pedagogique de demonstration en securite applicative" | Login page footer |
| `login.loginFailed` | "Login Failed" | "Echec de connexion" | Login error title |
| `errors.notFoundTitle` | "Page not found" | "Page introuvable" | 404 error title |
| `errors.forbiddenTitle` | "Access denied" | "Acces refuse" | 403 error title |
| `errors.tooManyAttemptsTitle` | "Too many attempts" | "Trop de tentatives" | 429 error title |
| `errors.serverErrorTitle` | "Server error" | "Erreur du serveur" | 500 error title |
| `errors.notFoundGuidance` | "The page you are looking for does not exist or has been moved." | "La page que vous recherchez n'existe pas ou a ete deplacee." | 404 guidance |
| `errors.forbiddenGuidance` | "You do not have permission to access this page." | "Vous n'avez pas la permission d'acceder a cette page." | 403 guidance |
| `errors.tooManyAttemptsGuidance` | "You have exceeded the maximum number of login attempts. Please try again in {minutes} minute(s)." | "Vous avez depasse le nombre maximal de tentatives de connexion. Veuillez reessayer dans {minutes} minute(s)." | 429 guidance with interpolation |
| `errors.serverErrorGuidance` | "An unexpected error occurred. Please try again later." | "Une erreur inattendue s'est produite. Veuillez reessayer plus tard." | 500 guidance |
| `errors.backToDashboard` | "Back to Dashboard" | "Retour au tableau de bord" | Error page button |
| `nav.defaultTitle` | "HEC Montreal - Application Security" | "HEC Montreal - Securite applicative" | header.ejs default title fallback |

**Note:** Some existing keys use slightly different names. The planner should cross-reference carefully:
- `nav.scaLab` = "Labo ACS" but user wants "Analyse statique" -- use new key `nav.staticAnalysis` instead
- `nav.dastLab` = "Labo DAST" but user wants "Analyse dynamique" -- use new key `nav.dynamicAnalysis`
- `nav.vmLab` = "Gestionnaire de vulnerabilites" but user wants "Gestion des vulnerabilites" -- use new key `nav.vulnManagement`
- `nav.pentestLab` = "Labo Pentest" but user wants "Test d'intrusion" -- use new key `nav.pentestLab` (overwrite existing value)

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in templates | `t('key')` calls via i18n middleware | Phase 1 (2026-03-12) | All new UI work uses t() |

**Deprecated/outdated:**
- Nothing deprecated -- Phase 1 infrastructure is brand new

## Integration Points Detail

### server.js Error Handler (lines 235-249)
```javascript
// Error handler passes English 'message'
app.use((err, req, res, next) => {
  res.render('error', {
    message: err.message || 'An error occurred',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

// 404 handler passes English 'message'
app.use((req, res) => {
  res.status(404).render('error', {
    message: 'Page not found',
    error: { status: 404 }
  });
});
```
**Strategy:** Do NOT modify server.js. The error.ejs template should ignore the `message` variable for display and use status-code-based t() lookups instead.

### middleware/rateLimiter.js (lines 46-52)
```javascript
return res.status(429).render('error', {
  message: 'Too Many Login Attempts',
  error: {
    status: 429,
    details: `You have exceeded the maximum number of login attempts (${MAX_ATTEMPTS}). Please try again in ${remainingMinutes} minute(s).`
  }
});
```
**Strategy:** Template detects status 429 and shows translated title. For the dynamic minutes value, either: (a) parse it from `error.details` with a regex, or (b) accept that the details line will show in English while the title and guidance show in French. Option (a) is fragile; option (b) is pragmatic. **Recommendation:** The template should show translated title + translated generic guidance ("Trop de tentatives. Veuillez reessayer dans quelques minutes.") and NOT try to parse the English details string.

### routes/auth.js Login Errors (lines 28, 49, 83)
```javascript
res.render('login', { error: 'Invalid username or password' });
res.render('login', { error: 'An error occurred during login' });
```
**Strategy:** The login template currently shows `<%= error %>` for the error detail. Since auth.js passes English strings, the template should either: (a) show a generic French error title (`t('login.loginFailed')`) for ALL errors and use the English `error` as a hidden detail, or (b) translate at the auth.js level. **Recommendation:** Show `t('login.loginFailed')` as the title and `t('auth.invalidCredentials')` as the detail, ignoring the server-provided English string entirely. This is safe because the login page only shows credential errors.

## Open Questions

1. **Role label format: "Administrateur(-trice)" vs "Administrateur"**
   - What we know: Phase 1 demo account labels use "Administrateur", "Professeur", "Etudiant(e)"
   - What's unclear: CONTEXT.md says use "Administrateur(-trice)" for role badges, but `nav.roleAdmin` key from Phase 1 is just "Administrateur"
   - Recommendation: Use existing Phase 1 keys as-is ("Administrateur", "Professeur", "Etudiant(e)") since these match the demo account labels and the CONTEXT.md decision says "matches Phase 1 demo account labels"

2. **Error details for rate-limited users**
   - What we know: The rate limiter passes dynamic English text with minutes remaining
   - What's unclear: Whether to show exact minutes or generic "try again later"
   - Recommendation: Show generic French guidance. Exact minutes are nice but require fragile parsing of English strings. The status code (429) is sufficient for the user to understand.

## Sources

### Primary (HIGH confidence)
- Direct code inspection of `views/login.ejs`, `views/partials/header.ejs`, `views/error.ejs`
- Direct code inspection of `utils/i18n.js` (translation infrastructure)
- Direct code inspection of `config/translations/fr.json` and `config/translations/en.json`
- Direct code inspection of `server.js` (error handlers, lines 235-249)
- Direct code inspection of `middleware/rateLimiter.js` (rate limit error rendering)
- Direct code inspection of `routes/auth.js` (login error rendering)

### Secondary (MEDIUM confidence)
- None needed -- all findings from direct code inspection

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - direct code inspection, no external libraries
- Architecture: HIGH - established pattern from Phase 1, mechanically applied
- Pitfalls: HIGH - identified from direct code reading of all integration points

**Research date:** 2026-03-12
**Valid until:** 2026-04-12 (stable -- no external dependencies to change)
