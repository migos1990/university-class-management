# Phase 11: Instructor Tools - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Instructor can see at a glance which students are active, what they're working on, and their overall SCA progress. A new student progress summary table on the SCA instructor dashboard shows per-student completion, last activity time, current finding, and status badges — all updating live via 30s polling. Covers INST-01 and INST-02.

</domain>

<decisions>
## Implementation Decisions

### Progress summary layout
- Summary table format: one row per student, sorted by completion % descending (most progress at top)
- Fixed sort order — no click-to-sort column headers
- Five columns: Etudiant (linked to /sca/student/:id), Progression (progress bar + "X/12 soumis"), Derniere act. (relative time-ago), Analyse en cours (finding title or "—"), Statut (badge)
- Always visible — not collapsible
- Section heading includes active count: "Suivi des etudiants — 5 actifs / 8 etudiants"
- Table wrapped in overflow-x:auto for narrow screens (same pattern as existing matrix)

### Activity tracking
- Track last_active_at on any SCA action: GET /sca/findings/:id (viewing), POST /sca/findings/:id/review (save/submit), GET /sca/ (student lab page)
- Non-SCA actions (dashboard, DAST, VM, login) are NOT tracked
- "Current finding" = last finding detail page the student viewed (recorded on GET /sca/findings/:id)
- Current finding persists even when student navigates away from finding detail

### Activity indicators
- Three-state status badges:
  - Actif (green #d4edda) = activity in last 5 minutes
  - Inactif (amber #fff3cd) = has reviews but idle >5 minutes
  - Pas commence (gray #e9ecef) = zero SCA reviews
- Last active displayed as relative time-ago in French: "il y a 2 min", "il y a 15 min", "il y a 1 h"
- Students with no activity show "Pas commence" instead of a time-ago value

### Cross-lab scope
- Progress tracks SCA submissions only (X/12 findings submitted)
- Only reviews with status='submitted' count toward completion — drafts are work in progress
- DAST and other labs excluded from this progress view

### Dashboard placement
- New section positioned between the 3 stats cards and the Findings Overview table
- Page order: Stats cards -> Student Progress (NEW) -> Findings Overview -> Student Progress Matrix
- Card wrapper styling consistent with existing sections

### Data endpoint
- Extend existing GET /sca/stats response with a "students" array
- Each student object: id, username, submitted count, lastActiveAt, currentFinding (id), currentFindingTitle
- Single AJAX call updates both stats cards and student table on 30s polling interval

### Claude's Discretion
- In-memory storage mechanism for last_active_at and current_finding (database adapter updates vs. separate tracking object)
- Exact i18n key names and French translations for new UI elements
- Progress bar styling (reuse existing .progress-bar-wrap/fill or new variant)
- Time-ago calculation logic (client-side vs. server-side)
- How to extract display name from username (e.g., strip "_student" suffix)

</decisions>

<specifics>
## Specific Ideas

- Active count in heading updates with each polling cycle, matching the stats cards refresh
- Progress bar reuses the existing dark blue (#002855) fill color from the findings overview progress bars
- Username display strips "_student" suffix (existing pattern in the matrix: `s.username.replace('_student','')`)
- Badge styles match existing classification badges (.cls-confirmed green, .cls-needs amber, .cls-none gray)

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `views/sca/instructor.ejs:173-190`: Existing refreshStats() function with 30s polling — extend to update student table
- `views/sca/instructor.ejs:19-20`: Existing progress bar CSS (.progress-bar-wrap, .progress-bar-fill) — reuse for per-student progress
- `views/sca/instructor.ejs:15-18`: Existing classification badge CSS (.cls-confirmed, .cls-false_positive, .cls-needs, .cls-none) — adapt for status badges
- `views/sca/instructor.ejs:109`: Username display pattern: `s.username.replace('_student','')`

### Established Patterns
- Stats endpoint at GET /sca/stats returns JSON, polled every 30s by client-side JS
- EJS-embedded JS constants for French strings (MSG_* pattern)
- Inline styles throughout templates
- `requireRole(['admin', 'professor'])` for instructor-only endpoints
- `t()` function for i18n view chrome

### Integration Points
- `routes/sca.js:108-136`: GET /sca/stats endpoint — extend with students array
- `routes/sca.js:139`: GET /sca/findings/:id — add last_active_at and current_finding tracking for students
- `routes/sca.js:51`: GET /sca/ — add last_active_at tracking for students
- `routes/sca.js:186+`: POST /sca/findings/:id/review — add last_active_at tracking
- `views/sca/instructor.ejs`: Add student progress table section between stats cards and findings overview
- `config/translations/fr.json`: Add i18n keys under sca.instructor.* for new UI elements
- `config/translations/en.json`: Add parallel English keys for fallback

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 11-instructor-tools*
*Context gathered: 2026-03-19*
