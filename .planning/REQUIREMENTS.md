# Requirements: HEC Montreal SCA Lab Production Release

**Defined:** 2026-03-12
**Core Value:** The SCA lab must work flawlessly end-to-end in French — from Codespace boot to student submission to instructor review — with zero friction for non-technical students.

## v1 Requirements

Requirements for tonight's class. Each maps to roadmap phases.

### Translation

- [ ] **TRAN-01**: App defaults to French for all new sessions
- [ ] **TRAN-02**: SCA student-lab view fully translated to French (progress text, button labels, form fields, AJAX feedback)
- [ ] **TRAN-03**: SCA finding-detail view fully translated to French (code snippet labels, classification options, notes placeholders)
- [ ] **TRAN-04**: SCA instructor dashboard fully translated to French (table headers, matrix labels, import buttons)
- [ ] **TRAN-05**: SCA student-detail view fully translated to French
- [ ] **TRAN-06**: Header/sidebar navigation translated to French (all nav links, role badges, team name)
- [ ] **TRAN-07**: Login page fully translated to French
- [ ] **TRAN-08**: Error page translated to French
- [ ] **TRAN-09**: Classification dropdown labels in French ("Vrai positif", "Faux positif", "Necessite une investigation")
- [ ] **TRAN-10**: AJAX save/submit feedback messages in French

### SCA Content Enhancement

- [ ] **SCAC-01**: All 12 SCA finding descriptions enriched with business impact and educational context in French
- [ ] **SCAC-02**: Guided workflow intro banner on student-lab view in French (dismissible, explains approach)
- [ ] **SCAC-03**: Finding difficulty indicators ("Facile", "Moyen", "Avance") on each finding
- [ ] **SCAC-04**: Contextual hints per finding with scaffolded analysis guidance in French

### Instructor Dashboard

- [ ] **INST-01**: Live class progress stats on SCA instructor view (students started, average completion %, pace)

### Deployment Verification

- [ ] **DEPL-01**: Codespaces first-boot works cleanly (seeding, SSL, all team instances start)
- [ ] **DEPL-02**: End-to-end student journey verified (login -> SCA lab -> review finding -> save draft -> submit -> instructor sees submission)
- [ ] **DEPL-03**: Codespaces port visibility configured for student access

## v2 Requirements

Deferred to future class sessions. Tracked but not in current roadmap.

### Instructor Dashboard

- **INST-02**: Class consensus indicators per finding (% confirmed vs FP vs needs investigation)
- **INST-03**: Severity distribution visual card on instructor dashboard
- **INST-04**: Instructor broadcast message form on SCA dashboard

### SCA Content

- **SCAC-05**: Per-finding time tracking (how long students spend analyzing each finding)

### Translation

- **TRAN-11**: EN/FR language toggle UI for bilingual flexibility
- **TRAN-12**: Other lab modules (DAST, Pentest, VM) translated to French

## Out of Scope

| Feature | Reason |
|---------|--------|
| WebSocket real-time updates | Polling at 30s intervals is sufficient; WebSocket adds complexity and dependency risk |
| Grading/scoring system | Tonight's exercise is formative, not summative; scoring changes student behavior negatively |
| Auto-grading or "correct answer" comparison | SCA triage is subjective; auto-grading teaches wrong lesson that security has one right answer |
| Mobile responsive design | Students use laptops in class |
| New npm dependencies | Time pressure + stability constraint; work within existing stack |
| DAST/Pentest/VM module polish | Tonight is SCA-only; touching other modules risks regressions |
| Solution guide visible to students | Premature answers undermine learning; instructor references SOLUTION-GUIDE.md during discussion |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| TRAN-01 | Phase TBD | Pending |
| TRAN-02 | Phase TBD | Pending |
| TRAN-03 | Phase TBD | Pending |
| TRAN-04 | Phase TBD | Pending |
| TRAN-05 | Phase TBD | Pending |
| TRAN-06 | Phase TBD | Pending |
| TRAN-07 | Phase TBD | Pending |
| TRAN-08 | Phase TBD | Pending |
| TRAN-09 | Phase TBD | Pending |
| TRAN-10 | Phase TBD | Pending |
| SCAC-01 | Phase TBD | Pending |
| SCAC-02 | Phase TBD | Pending |
| SCAC-03 | Phase TBD | Pending |
| SCAC-04 | Phase TBD | Pending |
| INST-01 | Phase TBD | Pending |
| DEPL-01 | Phase TBD | Pending |
| DEPL-02 | Phase TBD | Pending |
| DEPL-03 | Phase TBD | Pending |

**Coverage:**
- v1 requirements: 18 total
- Mapped to phases: 0
- Unmapped: 18

---
*Requirements defined: 2026-03-12*
*Last updated: 2026-03-12 after initial definition*
