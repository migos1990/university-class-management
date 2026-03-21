# Requirements: HEC Montreal Application Security Platform v1.1

**Defined:** 2026-03-12
**Expanded:** 2026-03-19 (product review)
**Core Value:** The SCA lab must work flawlessly end-to-end in French -- from Codespace boot to student submission to instructor review -- with zero friction for non-technical students.

## v1.1 Requirements

Requirements for v1.1 Polish & Pedagogy release. Each maps to roadmap phases.

### Code Snippets

- [x] **SNIP-01**: Student can see 5-10 lines of relevant source code in the finding detail view
- [x] **SNIP-02**: Vulnerable line is visually called out within the code snippet (background highlight + left border)
- [x] **SNIP-03**: Code snippet displays line numbers corresponding to actual file line numbers
- [x] **SNIP-04**: Code snippet has syntax coloring via Prism.js (keywords, strings, comments differentiated)
- [x] **SNIP-05**: Student-lab card shows a compact one-line preview of the vulnerable code

### Quick Wins

- [x] **QWIN-01**: Security status bar badges display in French on every page
- [x] **QWIN-02**: SCA completion celebration banner shown when student submits all 12 findings
- [x] **QWIN-03**: Finding detail page has prev/next navigation arrows between findings
- [x] **QWIN-04**: POST /api/instructor-message and GET /api/summary require authentication

### Testing

- [x] **TEST-01**: Integration tests verify SCA review submission workflow (student submits classification, data persists)
- [x] **TEST-02**: Integration tests verify answer key role-gating (student denied, instructor allowed)
- [x] **TEST-03**: Integration tests verify /api/instructor-message and /api/summary require auth

### Security Boundary Documentation

- [x] **SDOC-01**: SECURITY-BOUNDARY.md documents all 12 intentional vulnerabilities (purpose, location) separately from real security findings

### DAST French Translation

- [x] **DAST-01**: All 6 DAST scenario descriptions, instructions, and results display in Quebec French
- [x] **DAST-02**: All DAST views (scenario list, scenario detail, results) display in Quebec French

### Instructor Tools

- [x] **INST-01**: Instructor dashboard shows each student's last_active_at and current finding being analyzed
- [x] **INST-02**: Instructor dashboard includes a progress summary card showing per-student completion

### Answer Key

- [x] **AKEY-01**: Instructor can view a standalone answer key page with all 12 findings' expected classifications
- [x] **AKEY-02**: Answer key displays reasoning explaining why each finding has its expected classification
- [x] **AKEY-03**: Answer key includes discussion prompts for in-class use per finding
- [x] **AKEY-04**: Answer key is role-gated (visible only to professor/admin, never to students)
- [x] **AKEY-05**: Instructor can see an inline collapsible answer section in the finding detail view
- [x] **AKEY-06**: All answer key content is in Quebec French

### Documentation

- [x] **DOCS-01**: README reflects current v1.1 project state (features, setup, usage)
- [x] **DOCS-02**: Instructor-facing documentation describes how to use the answer key and new features

### Code Quality

- [x] **QUAL-01**: ESLint 9 and Prettier 3 are configured with npm scripts (`npm run lint`, `npm run format`)
- [ ] **QUAL-02**: Codebase passes ESLint and Prettier with zero errors/warnings
- [ ] **QUAL-03**: Dead code and unused variables removed
- [x] **QUAL-04**: Intentional vulnerabilities (12 SCA findings) and SQL pattern-matching DB adapter are preserved unchanged

### CSS Extraction

- [ ] **CSS-01**: Common CSS patterns (severity badges, card layouts, status indicators) moved from inline styles to public/styles.css

### CTF Pentest Lab

- [ ] **CTF-01**: 12 CTF challenges available, each corresponding to an SCA finding, with flags planted in the codebase
- [ ] **CTF-02**: Progressive unlock system (4 Easy at start, solve 2 Easy unlocks 3 Medium, solve 2 Medium unlocks 5 Advanced)
- [ ] **CTF-03**: Scoring system (Easy=100, Medium=200, Advanced=300 pts; hints deduct 10/20 pts; max 2,500)
- [ ] **CTF-04**: Instructor leaderboard with ranked student progress and challenge heatmap
- [ ] **CTF-05**: Flag capture celebration animation (radial pulse + counter tick-up) with tier unlock banner
- [ ] **CTF-06**: Sticky hunt reminder bar on all pages showing active challenge
- [ ] **CTF-07**: Two-click hint confirmation to prevent accidental point loss
- [ ] **CTF-08**: All CTF content (challenge descriptions, hints, UI) in Quebec French
- [ ] **CTF-09**: Old pentest form-filling module replaced (old routes/views/tables removed)

## Future Requirements

Deferred to v2+. Tracked but not in current roadmap.

### Analytics & Monitoring

- **ANAL-01**: Class consensus indicators per finding (% confirmed vs FP vs needs investigation)
- **ANAL-02**: Severity distribution visual card on instructor dashboard
- **ANAL-03**: Per-finding time tracking (how long students spend analyzing each finding)

### Communication

- **COMM-01**: Instructor broadcast message form on SCA dashboard

### Internationalization

- **I18N-01**: EN/FR language toggle UI for bilingual flexibility
- **I18N-02**: VM lab translated to French (DAST moved to Phase 10)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Live code editor in findings | High complexity, students should review not edit |
| Auto-grading / correct answer comparison | SCA triage is subjective; formative exercise |
| Student-visible solutions | Answer key is instructor-only by design |
| Comprehensive JSDoc/TypeScript migration | 11,800 LOC rewrite for zero classroom benefit |
| CSS framework adoption | Inline styles are the established convention (CSS-01 extracts shared patterns only) |
| highlight.js | No native line-highlight support; Prism.js is superior |
| Session persistence (file-based store) | "No new dependencies" constraint |
| database.js refactor | Too large mid-semester |
| Mobile responsive design | Students use laptops in class |
| WebSocket real-time updates | 30s polling is sufficient |
| Language toggle UI | All students are French-speaking |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SNIP-01 | Phase 6 | Complete |
| SNIP-02 | Phase 6 | Complete |
| SNIP-03 | Phase 6 | Complete |
| SNIP-04 | Phase 6 | Complete |
| SNIP-05 | Phase 6 | Complete |
| QWIN-01 | Phase 7 | Complete |
| QWIN-02 | Phase 7 | Complete |
| QWIN-03 | Phase 7 | Complete |
| QWIN-04 | Phase 7 | Complete |
| TEST-01 | Phase 8 | Complete |
| TEST-02 | Phase 8 | Complete |
| TEST-03 | Phase 8 | Complete |
| SDOC-01 | Phase 9 | Complete |
| DAST-01 | Phase 10 | Complete |
| DAST-02 | Phase 10 | Complete |
| INST-01 | Phase 11 | Complete |
| INST-02 | Phase 11 | Complete |
| AKEY-01 | Phase 12 | Complete |
| AKEY-02 | Phase 12 | Complete |
| AKEY-03 | Phase 12 | Complete |
| AKEY-04 | Phase 12 | Complete |
| AKEY-05 | Phase 12 | Complete |
| AKEY-06 | Phase 12 | Complete |
| DOCS-01 | Phase 13 | Complete |
| DOCS-02 | Phase 13 | Complete |
| QUAL-01 | Phase 14 | Complete |
| QUAL-02 | Phase 14 | Pending |
| QUAL-03 | Phase 14 | Pending |
| QUAL-04 | Phase 14 | Complete |
| CSS-01 | Phase 15 | Pending |
| CTF-01 | Phase 16 | Pending |
| CTF-02 | Phase 16 | Pending |
| CTF-03 | Phase 16 | Pending |
| CTF-04 | Phase 16 | Pending |
| CTF-05 | Phase 16 | Pending |
| CTF-06 | Phase 16 | Pending |
| CTF-07 | Phase 16 | Pending |
| CTF-08 | Phase 16 | Pending |
| CTF-09 | Phase 16 | Pending |

**Coverage:**
- v1.1 requirements: 40 total
- Mapped to phases: 40
- Unmapped: 0

---
*Requirements defined: 2026-03-12*
*Expanded: 2026-03-19 after product review*
*Last updated: 2026-03-19 after roadmap reorder*
