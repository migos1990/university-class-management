# Phase 17: QA Audit Fixes - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix 6 QA audit issues: 5x finding deduplication (CRITICAL), untranslated English on dashboards/VM pages (HIGH), instructor accessing student dashboard (MEDIUM), /classes 404 (MEDIUM), locked CTF challenge raw JSON error (LOW), "Mes inscriptions" nav link loop (LOW).

</domain>

<decisions>
## Implementation Decisions

### Deduplication fix
- Claude investigates and determines root cause (seed data vs template rendering vs multiple calls)
- Keep the current DELETE-then-INSERT seed pattern — clean slate on boot
- No startup assertion needed — existing smoke test (`npm test`) validates counts
- After fix, verify all four views: SCA student, SCA instructor, DAST, VM — confirm correct counts (12, 12, 6, 12)

### Dashboard & VM translation
- Full French translation across all dashboards (student, professor, admin) using `t()` for UI chrome
- Class names and descriptions get French overlay via `localize()` pattern — same as SCA/DAST findings
- Admin dashboard fully translated: 'Actions rapides', 'Parametres de securite', 'Journaux d'audit', etc.
- VM vulnerability titles translated via `vmLocalize()` overlay function — consistent with SCA `localize()` and DAST `dastLocalize()`
- VM status labels translated to French: 'Ouvert', 'En cours', 'Resolu', 'Ferme'
- Severity badges stay English (locked decision from Phase 10): Critical, High, Medium, Low

### Role gate behavior
- Dashboard routes only: /dashboard/* redirects wrong-role users to their correct dashboard (silent redirect, no error)
- Other role-gated routes (answer key, admin pages) keep existing 403 behavior — real security boundaries
- requireRole middleware stays unchanged globally

### CTF locked challenge page
- GET for locked challenges: custom CTF-themed locked page with lock icon, 'Defi verrouille', explanation of unlock requirements, link back to challenge board
- POST /pentest/submit for locked challenges: keep JSON response — frontend JS handles display

### Nav link fixes
- Remove 'Mes inscriptions' link entirely — redundant with student dashboard
- Final student nav: Tableau de bord, Labo SCA, Labo DAST, Vulnerabilites, CTF
- Keep /classes redirect to /dashboard — graceful fallback for bookmarks/old links

### Claude's Discretion
- Root cause investigation approach for deduplication
- Exact CTF locked page styling (consistent with existing CTF aesthetic)
- Translation key naming conventions for new `t()` keys
- Number of new i18n keys needed (estimate ~60-80)

</decisions>

<specifics>
## Specific Ideas

- CTF locked page should fit the hacker/CTF aesthetic of the existing challenge board
- Dashboard redirect on wrong role should be silent — no flash message, just take them where they belong
- vmLocalize() should follow the exact same pattern as dastLocalize() from Phase 10

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `localize()` in utils/localize.js: SCA finding overlay function — pattern to follow for class data and VM
- `dastLocalize()`: DAST scenario overlay — pattern to follow for vmLocalize()
- `t()` helper: i18n translation function, already wired into all EJS templates via res.locals
- `requireRole` middleware in middleware/rbac.js: role checking, currently returns 403
- error.ejs template: generic error page, used for 403/404

### Established Patterns
- i18n: `fr.json` holds all translation keys, `t('key.path')` in templates
- Content overlay: `localize(data, req)` / `dastLocalize(data, req)` applied in route handlers before render
- Role gating: `requireRole(['student'])` middleware on route definition
- CSS: shared `public/styles.css` (extracted in Phase 15)

### Integration Points
- seedData.js: `initializeDatabase()` called from config/database.js — deduplication fix target
- routes/dashboard.js: role redirect logic on lines 12-24, role gates on lines 31, 71, 96
- routes/pentest.js: locked challenge check on lines 250-254 (GET) and 322-323 (POST)
- views/partials/header.ejs: nav links — remove 'Mes inscriptions' here
- locales/fr.json: add new translation keys for dashboards, admin, VM

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 17-qa-audit-fixes*
*Context gathered: 2026-03-26*
