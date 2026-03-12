# Phase 1: Translation Foundation - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the application default to French and build all translation infrastructure for subsequent phases. This includes: flipping the default language to French, adding all SCA and UI translation keys to fr.json (and en.json), and creating a localize() helper for seed data. No template wiring — that's Phases 2-4.

</domain>

<decisions>
## Implementation Decisions

### Seed data localization approach
- Use fr.json lookup pattern: keys like `sca.findings.1.title`, `sca.findings.1.description`, `sca.findings.1.remediation`
- localize() helper takes a finding object and language, returns the finding with translated text fields from fr.json via existing t() function
- Falls back to English (original seed data values) when French key is missing
- Log console.warn() on missing French translations (matches existing i18n.js warning pattern)
- Code snippets stay in English — they're actual source code, not prose
- localize() lives in utils/i18n.js alongside existing t() function

### Quebec French SCA terminology
- **Severity levels stay English:** Critical, High, Medium, Low — industry-standard terms students should learn
- **Category labels stay English:** Hardcoded Credentials, Broken Access Control, Path Traversal, etc. — match real SCA tool output
- **Finding titles translated to French:** e.g., "Secret de session codé en dur", "Comparaison de mots de passe en clair"
- **Finding descriptions and remediation translated to French:** full prose in Quebec French
- **Classification dropdowns in French:** "Vrai positif", "Faux positif", "Nécessite une investigation" (per TRAN-09)
- **CWE identifiers and tool names stay English:** CWE-798, Semgrep, npm audit, Manual Review

### fr.json key scope
- Phase 1 adds ALL translation keys needed by Phases 2-4 in one bulk pass
- Covers: sca.studentLab.*, sca.findingDetail.*, sca.instructor.*, sca.studentDetail.*, sca.findings.1-12.*, sca.common.*, sca.guided.*, sca.difficulty.*
- Both en.json and fr.json updated in sync (complete English keys too, for clean fallback chain)
- Existing fr.json keys (nav, auth, errors, dashboard, etc.) trusted as-is — no re-audit

### Demo account labels
- French role labels with English usernames: "Administrateur: admin / admin123", "Professeur: prof_jones / prof123", "Étudiant(e): alice_student / student123"
- Section header: "Comptes de démonstration"
- Demo credentials kept prominent (safety net for class)
- No extra notes about team instances — keep it simple

### Claude's Discretion
- Which text fields localize() covers beyond title/description/remediation (e.g., category if beneficial)
- Exact namespace structure within fr.json SCA keys
- Whether to add DAST/VM translation keys while doing the bulk pass (not required but low cost)
- Exact French wording for all 12 finding translations (within Quebec French conventions decided above)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/i18n.js`: t() translation function with nested key lookup, parameter interpolation, and English fallback — localize() should use this
- `utils/i18n.js`: languageMiddleware already exposes t() and currentLang to all EJS views via res.locals
- `config/translations/fr.json`: 250+ existing French keys covering common UI, auth, security panel, dashboards, backups, BYOK, audit logs, errors, MFA
- `config/translations/en.json`: Matching English keys — both files need SCA keys added in sync

### Established Patterns
- i18n key structure: dot-separated namespaces (e.g., `security.panel.title`, `dashboard.admin.totalUsers`)
- Missing translation warning: console.warn() in i18n.js:49 — localize() should follow same pattern
- CommonJS modules: require()/module.exports throughout
- 2-space indentation, single quotes, semicolons

### Integration Points
- `utils/i18n.js:75`: languageMiddleware defaults to 'en' — change to 'fr'
- `utils/seedData.js`: 12 SCA findings with English text fields (title, description, remediation) — localize() overlays French from fr.json
- `routes/sca.js`: SCA route module — will call localize() on findings before passing to views (Phase 3 wiring)
- 4 SCA EJS views: student-lab.ejs, finding-detail.ejs, instructor.ejs, student-detail.ejs — will use t() keys (Phases 3-4)

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

*Phase: 01-translation-foundation*
*Context gathered: 2026-03-12*
