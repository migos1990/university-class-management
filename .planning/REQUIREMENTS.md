# Requirements: HEC Montreal SCA Lab v1.1

**Defined:** 2026-03-12
**Core Value:** The SCA lab must work flawlessly end-to-end in French -- from Codespace boot to student submission to instructor review -- with zero friction for non-technical students.

## v1.1 Requirements

Requirements for v1.1 Polish & Pedagogy release. Each maps to roadmap phases.

### Code Snippets

- [ ] **SNIP-01**: Student can see 5-10 lines of relevant source code in the finding detail view
- [ ] **SNIP-02**: Vulnerable line is visually called out within the code snippet (background highlight + left border)
- [ ] **SNIP-03**: Code snippet displays line numbers corresponding to actual file line numbers
- [ ] **SNIP-04**: Code snippet has syntax coloring via Prism.js (keywords, strings, comments differentiated)
- [ ] **SNIP-05**: Student-lab card shows a compact one-line preview of the vulnerable code

### Answer Key

- [ ] **AKEY-01**: Instructor can view a standalone answer key page with all 12 findings' expected classifications
- [ ] **AKEY-02**: Answer key displays reasoning explaining why each finding has its expected classification
- [ ] **AKEY-03**: Answer key includes discussion prompts for in-class use per finding
- [ ] **AKEY-04**: Answer key is role-gated (visible only to professor/admin, never to students)
- [ ] **AKEY-05**: Instructor can see an inline collapsible answer section in the finding detail view
- [ ] **AKEY-06**: All answer key content is in Quebec French

### Documentation

- [ ] **DOCS-01**: README reflects current v1.1 project state (features, setup, usage)
- [ ] **DOCS-02**: Instructor-facing documentation describes how to use the answer key and new features

### Code Quality

- [ ] **QUAL-01**: ESLint 9 and Prettier 3 are configured with npm scripts (`npm run lint`, `npm run format`)
- [ ] **QUAL-02**: Codebase passes ESLint and Prettier with zero errors/warnings
- [ ] **QUAL-03**: Duplicated CSS patterns extracted into shared styles where beneficial
- [ ] **QUAL-04**: Dead code and unused variables removed
- [ ] **QUAL-05**: Intentional vulnerabilities (12 SCA findings) and SQL pattern-matching DB adapter are preserved unchanged

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
- **I18N-02**: Other lab modules (DAST, Pentest, VM) translated to French

## Out of Scope

| Feature | Reason |
|---------|--------|
| Live code editor in findings | High complexity, students should review not edit |
| Auto-grading / correct answer comparison | SCA triage is subjective; formative exercise |
| Student-visible solutions | Answer key is instructor-only by design |
| Comprehensive JSDoc/TypeScript migration | 11,800 LOC rewrite for zero classroom benefit |
| CSS framework adoption | Inline styles are the established convention |
| highlight.js | No native line-highlight support; Prism.js is superior |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SNIP-01 | Phase 6 | Pending |
| SNIP-02 | Phase 6 | Pending |
| SNIP-03 | Phase 6 | Pending |
| SNIP-04 | Phase 6 | Pending |
| SNIP-05 | Phase 6 | Pending |
| AKEY-01 | Phase 7 | Pending |
| AKEY-02 | Phase 7 | Pending |
| AKEY-03 | Phase 7 | Pending |
| AKEY-04 | Phase 7 | Pending |
| AKEY-05 | Phase 7 | Pending |
| AKEY-06 | Phase 7 | Pending |
| DOCS-01 | Phase 8 | Pending |
| DOCS-02 | Phase 8 | Pending |
| QUAL-01 | Phase 9 | Pending |
| QUAL-02 | Phase 9 | Pending |
| QUAL-03 | Phase 9 | Pending |
| QUAL-04 | Phase 9 | Pending |
| QUAL-05 | Phase 9 | Pending |

**Coverage:**
- v1.1 requirements: 18 total
- Mapped to phases: 18
- Unmapped: 0

---
*Requirements defined: 2026-03-12*
*Last updated: 2026-03-12 after roadmap creation*
