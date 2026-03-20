# Phase 12: Instructor Answer Key - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Instructor has a French-language reference showing expected classifications, reasoning, and discussion prompts for all 12 SCA findings, enabling confident in-class facilitation. Two delivery surfaces: a standalone answer key page (accordion by difficulty) and an inline collapsible section on each finding detail page. Role-gated to professor/admin only — never visible to students. Covers AKEY-01 through AKEY-06.

</domain>

<decisions>
## Implementation Decisions

### Answer key content
- Classification labels match student options exactly: Vrai positif, Faux positif, Nécessite une investigation
- Reasoning: 2-3 concise sentences per finding explaining why this classification, what evidence to look for
- Discussion prompts: 1-2 open questions per finding to spark class discussion ("Quel serait l'impact si...?", "Comment un attaquant pourrait-il...?")
- Content written fresh in Quebec French — not translated from SOLUTION-GUIDE.md (which covers the full platform and is too verbose for a quick reference)

### Standalone page layout
- Findings grouped by difficulty: Facile / Moyen / Avancé sections
- Accordion pattern — all findings collapsed by default (prevents accidental spoilers when projecting)
- Collapsed card shows: finding title + severity badge + difficulty badge (enough to identify without revealing the answer)
- Brief classification distribution summary at the top of the page (e.g., "8 vrais positifs, 3 faux positifs, 1 nécessite investigation")
- "Retour au tableau de bord" back link at the top, consistent with finding-detail.ejs back-to-lab link

### Inline answer on finding detail
- Shows classification badge + 2-3 sentence reasoning only — discussion prompts stay on standalone page
- Placed below the student review form — instructor sees student answer first, then can compare with expected answer
- Server-side gated: EJS `<% if (user.role === 'professor' || user.role === 'admin') { %>` — HTML never sent to students, not even in page source
- Collapsed by default: subtle light-colored banner with lock icon and "Corrigé (cliquer pour afficher)" text
- Collapsible via client-side toggle (no page reload)

### Dashboard discoverability
- Button with icon in the page header area (near the "Tableau de bord SCA" title)
- Dark blue (#002855) button style consistent with existing action buttons (.btn-import)
- Key/book icon + "Corrigé" label
- Dashboard-only entry point — no header nav item (instructor is already on the dashboard when they need it)

### Claude's Discretion
- Exact i18n key structure and naming for answer key content
- How answer key data is stored (i18n keys in fr.json, seed data extension, or separate data file)
- Expand/collapse animation details
- Icon choice (emoji vs SVG) for the lock/key icon
- Exact CSS styling of the accordion and inline banner
- Which of the 12 findings are classified as Vrai positif vs Faux positif vs Nécessite investigation (Claude writes the pedagogically sound answer content)

</decisions>

<specifics>
## Specific Ideas

- Accordion prevents accidental screen-share spoilers — instructor can expand one finding at a time during class discussion
- Inline answer placement below the review form creates a natural "student answer → expected answer" comparison flow
- Server-side gating (not CSS hidden) ensures a curious student inspecting page source cannot find answers
- Classification distribution summary at the top helps instructor set expectations ("la plupart sont des vrais positifs, mais attention aux faux positifs")

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `GET /sca/answer-key` stub route already exists in routes/sca.js:302 with `requireAuth, requireRole(['admin', 'professor'])` — replace JSON stub with EJS render
- `test/answer-key-gating.test.js` — integration test for role-gating already passing
- `views/sca/instructor.ejs` — existing badge CSS (.sev-*, .badge-sm), button styles (.btn-import), and page header pattern to reuse
- `views/sca/finding-detail.ejs:68-79` — existing role-check pattern (`if (user.role === 'student')`) and collapsible hints section (toggleHints()) as reference for inline answer toggle
- `<details><summary>` HTML pattern used in instructor.ejs:25 — native browser accordion, no JS needed

### Established Patterns
- `t()` function for i18n view chrome; `localize()` overlays for SCA finding data
- `requireRole(['admin', 'professor'])` for instructor-only routes (20+ usages)
- EJS-embedded JS constants for AJAX feedback (MSG_* pattern)
- Inline styles throughout templates (no shared CSS file yet — Phase 15)
- DIFFICULTY_MAP/DIFFICULTY_ORDER constants for finding difficulty sorting

### Integration Points
- `routes/sca.js:301-304` — Replace stub with render of new answer-key.ejs view
- `views/sca/answer-key.ejs` — New template for standalone answer key page
- `views/sca/finding-detail.ejs` — Add inline collapsible answer section (professor/admin only)
- `views/sca/instructor.ejs` — Add "Corrigé" button in page header
- `config/translations/fr.json` — Add i18n keys for answer key UI chrome
- `config/translations/en.json` — Add parallel English keys for fallback

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 12-instructor-answer-key*
*Context gathered: 2026-03-19*
