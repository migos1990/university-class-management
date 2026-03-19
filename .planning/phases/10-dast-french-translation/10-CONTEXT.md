# Phase 10: DAST French Translation - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

DAST lab gets the same full-French experience as the SCA lab. All 6 DAST scenario descriptions, instructions, steps, and results display in Quebec French. All 3 DAST views (student-lab, scenario-detail, instructor) display in Quebec French. Covers DAST-01 and DAST-02.

</domain>

<decisions>
## Implementation Decisions

### Scenario data translation approach
- Extend localize() with a new `dastLocalize()` function in utils/i18n.js for DAST scenarios
- Overlay 4 fields per scenario: title, description, steps (as JSON array), expected_finding
- Call dastLocalize() in route handlers (routes/dast.js) before passing data to res.render() — matches SCA pattern
- fr.json key structure: `dast.scenarios.{id}.{field}` — mirrors `sca.findings.{id}.{field}` pattern
- Steps stored as JSON array under `dast.scenarios.{id}.steps` — dastLocalize() replaces the full array

### What stays in English (industry terms)
- Severity badges (Critical, High, Medium, Low) — unchanged, same as SCA decision
- OWASP categories (A01:2021, etc.) — industry standard
- Vulnerability type names (Insecure Direct Object Reference, Cross-Site Request Forgery, etc.) — students should learn English CVE/security terminology

### Step-by-step instructions translation style
- Full French prose, keep technical terms inline as-is
- URLs (/auth/verify-mfa, /classes), usernames (alice_student), passwords (student123), tool names (Burp Suite), file paths (routes/classes.js) stay as-is in the French text
- Example: "Connectez-vous en tant que alice_student (mot de passe : student123)"

### View chrome — full t() replacement
- All 3 DAST views get full t() i18n key replacement: headings, form labels, buttons, status badges, table headers
- ~40-50 new i18n keys in fr.json under `dast.` namespace
- All keys added upfront in fr.json (and en.json for fallback) — matches Phase 1 pattern

### Precondition messages
- Replace hardcoded English messages in routes/dast.js precondition endpoint with t() calls
- Server-side translation using t(req.session.language, 'dast.precondition.{key}') — returns translated string directly in JSON
- No client-side i18n lookup needed for preconditions

### Client-side JS strings
- EJS-embedded constants pattern from Phase 7: `const MESSAGES = { saving: '<%= t("dast.js.saving") %>' }`
- All AJAX feedback messages translated: saving, submitted, draft saved, network error, error saving
- All confirm() and alert() dialogs translated (e.g., "Pousser ce scénario vers le gestionnaire de vulnérabilités ?")
- Match SCA student-lab feedback pattern exactly (green for success, red for error)

### Claude's Discretion
- Exact French translation wording for all ~50 i18n keys and 6 scenarios
- How to structure dastLocalize() internally (separate function vs. parameterized localize())
- Whether to add en.json keys for DAST (for fallback completeness) or rely on existing English seed data
- Order of implementation (keys first vs. views first)

</decisions>

<specifics>
## Specific Ideas

- Step translation example: "Connectez-vous en tant que alice_student (mot de passe : student123)" — French prose wrapping English technical terms
- dast.scenarios.{id}.steps stored as JSON array in fr.json, e.g., `["Connectez-vous en tant que alice_student...", "Naviguez vers..."]`
- Precondition API returns pre-translated French string in JSON response — client JS just displays it directly

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/i18n.js:92-109`: Existing `localize()` function for SCA findings — template for dastLocalize()
- `config/translations/fr.json`: Already has `dastLab` key; DAST namespace ready to expand
- `config/translations/en.json`: Parallel structure for fallback
- SCA views (`views/sca/student-lab.ejs`, `views/sca/finding-detail.ejs`): Reference implementations for t() usage patterns

### Established Patterns
- `localize()` overlays title/description/remediation from fr.json keyed by finding ID
- `t(lang, key, params)` for view chrome with `{param}` interpolation
- EJS-embedded JS constants for client-side i18n (Phase 7 pattern in SCA student-lab)
- `res.locals.t` available in all templates via languageMiddleware
- Session language defaults to 'fr'

### Integration Points
- `utils/i18n.js`: Add dastLocalize() function, export it
- `routes/dast.js`: Import dastLocalize(), call on scenarios before res.render() in GET / and GET /scenarios/:id
- `routes/dast.js`: Import t(), use in precondition endpoint for translated messages
- `config/translations/fr.json`: Add ~50 keys under dast.* namespace (view chrome + 6 scenarios × 4 fields)
- `config/translations/en.json`: Add parallel English keys for fallback
- `views/dast/student-lab.ejs`: Replace all hardcoded English with t() calls + EJS-embedded MESSAGES
- `views/dast/scenario-detail.ejs`: Replace all hardcoded English with t() calls + EJS-embedded MESSAGES
- `views/dast/instructor.ejs`: Replace all hardcoded English with t() calls + EJS-embedded MESSAGES

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 10-dast-french-translation*
*Context gathered: 2026-03-19*
