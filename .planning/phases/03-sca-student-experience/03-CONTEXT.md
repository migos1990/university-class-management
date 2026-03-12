# Phase 3: SCA Student Experience - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Students complete the entire SCA lab workflow in French — browsing findings, reading enriched descriptions, classifying vulnerabilities, writing notes, and submitting — with guided support throughout. This phase translates the student-lab and finding-detail views, enriches finding content, and adds pedagogical scaffolding (intro banner, difficulty indicators, contextual hints). Instructor views and live stats are Phase 4.

</domain>

<decisions>
## Implementation Decisions

### Guided intro banner
- Full-width blue info card (#e8f0ff with HEC navy text) at top of student-lab page, between page header and progress card
- Dismiss via localStorage — once dismissed, never shows again for that browser
- Content uses existing fr.json keys: `sca.guided.introBannerTitle` ("Comment aborder cet exercice") and `sca.guided.introBannerText` (current text is sufficient, no changes needed)
- Dismiss button uses `sca.guided.dismiss` ("Compris")

### Difficulty indicators
- Assigned by vulnerability type:
  - Facile: hardcoded secrets, plaintext comparisons — obvious patterns (e.g., findings 1, 2, 3, 4)
  - Moyen: access control, CSRF, IDOR — requires understanding request flow (e.g., findings 6, 7, 8)
  - Avancé: config/dependency issues, missing headers, session flags — requires broader security knowledge (e.g., findings 5, 9, 10, 11, 12)
- Color-coded badges: green (#e8f8e8/#1e8449) for Facile, orange (#fff0e0/#c0732a) for Moyen, red (#ffe0e0/#c0392b) for Avancé
- Badge appears on both the student-lab list cards AND the finding-detail page
- Finding list sorted by difficulty: Facile first, then Moyen, then Avancé
- Difficulty stored as a field in seed data or mapped via a lookup in the route handler

### Contextual hints
- Collapsible "Besoin d'aide ?" section on finding-detail page only (not on the lab list)
- Placed below the description section, before remediation guidance
- 2-3 guiding analysis questions per finding — steer thinking without giving the classification answer
- Example: "Que se passe-t-il si un attaquant accède au code source ?", "Cette valeur devrait-elle être dans le code ou dans l'environnement ?"
- New per-finding hint keys needed in fr.json: `sca.findings.X.hints` (array or numbered keys)
- Expand/collapse via vanilla JS toggle (consistent with existing toggleForm pattern)

### Description enrichment
- Append 1-2 business impact sentences to existing `sca.findings.X.description` values in fr.json
- Frame impact in THIS university app's context: student grades, enrollment data, session hijacking on this platform
- Example: "Dans cette application, cela pourrait compromettre toutes les sessions actives, permettant à un attaquant de se faire passer pour n'importe quel étudiant ou professeur."
- No separate field — enrich the existing description text directly
- English en.json descriptions updated in sync for fallback consistency

### Translation wiring
- Replace all hardcoded English strings in student-lab.ejs and finding-detail.ejs with `t()` calls using existing fr.json keys
- Classification dropdown labels use: `sca.common.truePositive`, `sca.common.falsePositive`, `sca.common.needsInvestigation`
- AJAX feedback messages in French: `sca.common.savedDraft`, `sca.common.submittedSuccess`, `sca.common.errorSaving`, `sca.common.networkError`
- Call `localize()` on findings in routes/sca.js before passing to views (overlays French title/description/remediation)

### Claude's Discretion
- Exact difficulty assignment for each of the 12 findings (within the category guidelines above)
- Exact French wording for each finding's 2-3 analysis hint questions
- Exact business impact sentences appended to each description
- Whether to use numbered keys (`sca.findings.X.hint1`) or an array pattern for hints
- Sorting implementation approach (route-level sort vs template-level)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/i18n.js`: t() function available in all EJS views via `res.locals.t` — replace hardcoded strings with `t('key')` calls
- `utils/i18n.js`: localize() helper overlays French title/description/remediation from fr.json onto seed data objects
- `config/translations/fr.json`: All SCA keys already exist (studentLab.*, findingDetail.*, guided.*, difficulty.*, findings.1-12.*, common.*)
- `views/sca/student-lab.ejs`: toggleForm() vanilla JS pattern for expand/collapse — reuse for hint sections

### Established Patterns
- EJS templates use `<%= t('key') %>` for translation lookups
- Dot-separated key namespaces: `sca.studentLab.title`, `sca.findingDetail.classification`
- Inline styles throughout SCA templates (no external CSS framework)
- Badge styling: `.badge-sm` class with background/color pairs for severity levels
- AJAX form submission pattern with FormData in student-lab.ejs — update feedback messages to use t() keys

### Integration Points
- `routes/sca.js:42-60`: Student GET handler — call localize() on findings, add difficulty data, sort by difficulty before passing to view
- `views/sca/student-lab.ejs`: Full template needs t() wiring + intro banner + difficulty badges + sort rendering
- `views/sca/finding-detail.ejs`: Full template needs t() wiring + difficulty badge + collapsible hint section
- `config/translations/fr.json`: Add per-finding hint keys, enrich existing description values

</code_context>

<specifics>
## Specific Ideas

- Difficulty badge design follows traffic-light pattern: green (Facile), orange (Moyen), red (Avancé) — intuitive for students
- Hints use the "Piste d'analyse" heading with bullet-pointed guiding questions
- Business impact framed as "Dans cette application..." to connect abstract vulnerabilities to the code students are actually reading
- Sorting easy-first builds student confidence — they tackle recognizable patterns (hardcoded secrets) before complex issues (missing security headers)

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 03-sca-student-experience*
*Context gathered: 2026-03-12*
