# Phase 4: SCA Instructor Experience - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Translate the instructor dashboard and student-detail views to French, and add live class progress stats that auto-refresh. All translation keys already exist in fr.json from Phase 1. This phase wires t() calls into instructor.ejs and student-detail.ejs, calls localize() on findings for French titles, and adds a new stats bar with polling. Instructor broadcast messages, consensus indicators, and severity distribution visuals are Phase 4 v2 features.

</domain>

<decisions>
## Implementation Decisions

### Progress stats design
- Horizontal row of 3 stat cards above the Findings Overview table (top of page, first thing instructor sees)
- Big bold number with small label below each card (e.g., "18/30" with "Étudiants ayant commencé")
- White card background with HEC navy (#002855) text — consistent with existing card styling
- No icons or emoji — minimal, scannable
- Three stats: students started, average completion %, submissions per 5 minutes (pace)

### Auto-refresh behavior
- 30-second polling interval via setInterval
- Stats bar only refreshes — findings table and student matrix stay static until page reload
- Dedicated JSON endpoint: GET /sca/stats returning {studentsStarted, totalStudents, avgCompletion, pace}
- Small "Mis à jour : HH:MM:SS" timestamp below the stats bar, updated on each successful poll
- Vanilla JS fetch() for the AJAX call — no new dependencies

### Class pace definition
- "Rythme global" = count of submissions in the last 5 minutes
- Displayed as "X soumissions / 5 min"
- No directional trend indicator — just the raw number
- "Students started" = students with at least 1 review record (any status: pending or submitted)
- "Average completion" = mean of (submitted reviews / total findings) across all students, as percentage

### Instructor finding localization
- Call localize() on findings in the instructor route handler before passing to instructor.ejs — French titles everywhere
- Call localize() on findings in the student-detail route handler before passing to student-detail.ejs
- Severity badges stay English (consistent with Phase 1 decision)

### VM action translations
- Translate confirm() dialog: "Envoyer ce constat au gestionnaire de vulnérabilités ?"
- Translate button states: "Envoyer au GV" → "Importation..." → "Dans GV"
- Translate error alert: "Erreur réseau" / "Échec de l'importation"
- All keys already exist in fr.json under sca.instructor.*

### Translation wiring
- Replace all hardcoded English strings in instructor.ejs and student-detail.ejs with t() calls
- Use existing fr.json keys: sca.instructor.* for dashboard, sca.studentDetail.* for student detail
- Classification badges use sca.common.* keys (same as student views from Phase 3)
- Page titles in French via t() calls
- "← SCA Dashboard" back link in student-detail: use sca.studentDetail.backToDashboard

### Claude's Discretion
- Exact stat card spacing, padding, and font sizes
- Whether the stats endpoint shares query logic with the main instructor route or has its own optimized queries
- Exact French wording for the confirm() dialog and alert messages if keys need adjustment
- How to pass t() translations to client-side JS for the confirm/alert/button text (inline script variables or data attributes)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/i18n.js`: t() function available via res.locals.t in all EJS views — replace hardcoded strings
- `utils/i18n.js`: localize() helper overlays French title/description/remediation from fr.json onto finding objects
- `config/translations/fr.json`: sca.instructor.* (17 keys) and sca.studentDetail.* (10 keys) already exist
- `views/sca/student-lab.ejs`: AJAX fetch pattern with French feedback messages — reuse pattern for stats polling

### Established Patterns
- EJS templates use `<%= t('key') %>` for translations
- Inline styles throughout SCA templates (no external CSS framework)
- `.badge-sm` class with severity/classification color pairs
- `details/summary` for expandable content (used in student-detail notes)
- DIFFICULTY_MAP constant in routes/sca.js for finding metadata

### Integration Points
- `routes/sca.js:77-101`: Instructor GET handler — add localize() call on findings, add stats computation
- `routes/sca.js:176-192`: Student-detail GET handler — add localize() call on findings
- New route: `GET /sca/stats` — JSON endpoint for polling (students started, avg completion, pace)
- `views/sca/instructor.ejs`: Full template needs t() wiring + stats bar + polling JS
- `views/sca/student-detail.ejs`: Full template needs t() wiring + localize() finding titles

</code_context>

<specifics>
## Specific Ideas

- Stats bar should be visible and scannable "from across the room" — big numbers that the instructor can glance at while walking around
- Pace stat framed as "X soumissions / 5 min" gives a real-time pulse of classroom activity
- Timestamp "Mis à jour : 14:32:05" reassures the instructor the data is live without any distracting animation

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 04-sca-instructor-experience*
*Context gathered: 2026-03-12*
