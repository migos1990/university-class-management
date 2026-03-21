
# Roadmap: HEC Montreal Application Security Platform

## Milestones

- ✅ **v1.0 MVP** -- Phases 1-5 (shipped 2026-03-12)
- 🚧 **v1.1 Polish & Pedagogy** -- Phases 6-16 (in progress)

## Phases

<details>
<summary>✅ v1.0 HEC Montreal SCA Lab Production Release (Phases 1-5) -- SHIPPED 2026-03-12</summary>

- [x] Phase 1: Translation Foundation (1/1 plans) -- completed 2026-03-12
- [x] Phase 2: Shared UI Translation (1/1 plans) -- completed 2026-03-12
- [x] Phase 3: SCA Student Experience (2/2 plans) -- completed 2026-03-12
- [x] Phase 4: SCA Instructor Experience (2/2 plans) -- completed 2026-03-12
- [x] Phase 5: Deployment Verification (2/2 plans) -- completed 2026-03-12

Full details: [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md)

</details>

### 🚧 v1.1 Polish & Pedagogy (In Progress)

**Milestone Goal:** Expand the platform with quick wins, full French localization across all labs, instructor tooling, integration tests, and a CTF pentest lab — building on the SCA lab foundation.

**Wave order (from product review):** Quick Wins → Tests → Security Docs → DAST French → Instructor Tools → Answer Key → Documentation → Code Quality → CSS Extraction → CTF Pentest Lab

- [x] **Phase 6: Inline Code Snippets** - Syntax-highlighted multi-line code with vulnerable-line callout in finding views
- [ ] **Phase 7: Quick Wins** - Security status bar French, SCA completion celebration, finding prev/next nav, API auth hardening
- [ ] **Phase 8: Testing** - Integration tests for SCA review submission, answer key role-gating, internal API auth
- [ ] **Phase 9: Security Boundary Documentation** - SECURITY-BOUNDARY.md documenting all 12 intentional vulnerabilities vs. real bugs
- [ ] **Phase 10: DAST French Translation** - Translate all 6 DAST scenarios + views using the established localize() pattern
- [ ] **Phase 11: Instructor Tools** - Student activity tracking (last_active_at, current finding) and progress summary on dashboard
- [ ] **Phase 12: Instructor Answer Key** - Role-gated answer key with classifications, reasoning, and discussion prompts in French
- [ ] **Phase 13: Documentation** - README and instructor docs reflecting the v1.1 feature set
- [x] **Phase 14: Code Quality** - ESLint/Prettier tooling, dead code removal (preserving intentional vulnerabilities) (completed 2026-03-21)
- [x] **Phase 15: CSS Extraction** - Move shared severity/badge/card CSS from inline styles into public/styles.css (completed 2026-03-21)
- [ ] **Phase 16: CTF Pentest Lab** - CTF-style challenge board replacing the pentest form-filling module with 12 exploit challenges

## Phase Details

### Phase 6: Inline Code Snippets
**Goal**: Students see real source code context for each SCA finding, with the vulnerable line visually called out, making code review analysis concrete rather than abstract
**Depends on**: Phase 5 (v1.0 complete)
**Requirements**: SNIP-01, SNIP-02, SNIP-03, SNIP-04, SNIP-05
**Success Criteria** (what must be TRUE):
  1. Student viewing a finding detail page sees 5-10 lines of actual source code with line numbers matching the real file
  2. The vulnerable line within the code snippet is visually distinct (highlighted background and left border) so students know exactly which line to analyze
  3. Code snippet has syntax coloring (keywords, strings, comments in different colors) making the code readable
  4. Student-lab overview page shows a compact one-line code preview per finding, giving a quick sense of what each finding involves without overwhelming the card layout
  5. All code snippets render correctly without XSS -- angle brackets in source code display as text, not HTML
**Plans:** 2 plans

Plans:
- [x] 06-01-PLAN.md -- Seed data expansion, Prism.js vendoring, and syntax-highlighted finding detail view
- [x] 06-02-PLAN.md -- Student-lab card code preview and visual verification

### Phase 7: Quick Wins
**Goal**: Fix the most impactful small issues identified in the product review — complete French experience on every page, celebrate student completion, improve SCA navigation, and close unauthenticated API endpoints
**Depends on**: Phase 6
**Requirements**: QWIN-01, QWIN-02, QWIN-03, QWIN-04
**Success Criteria** (what must be TRUE):
  1. Security status bar badges display in French on every page (currently English)
  2. Students who submit all 12 SCA findings see a celebration banner ("Bravo!") confirming completion
  3. Finding detail page has prev/next navigation arrows so students don't have to go back to the list after each finding
  4. POST /api/instructor-message and GET /api/summary require authentication (currently unauthenticated)
**Plans:** 1 plan

Plans:
- [ ] 07-01-PLAN.md -- French security badges, SCA celebration banner, prev/next finding nav, API auth hardening

### Phase 8: Testing
**Goal**: Core user actions and security-critical paths have integration test coverage, catching regressions before they reach the classroom
**Depends on**: Phase 7
**Requirements**: TEST-01, TEST-02, TEST-03
**Success Criteria** (what must be TRUE):
  1. Integration tests verify SCA review submission workflow (student submits classification, data persists)
  2. Integration tests verify answer key role-gating (student denied, instructor allowed)
  3. Integration tests verify /api/instructor-message and /api/summary require auth
**Plans**: TBD

Plans:
- [ ] 08-01: TBD

### Phase 9: Security Boundary Documentation
**Goal**: A clear reference document distinguishes the 12 intentional teaching vulnerabilities from real security bugs, so anyone reviewing the codebase understands what is deliberate
**Depends on**: Phase 8
**Requirements**: SDOC-01
**Success Criteria** (what must be TRUE):
  1. SECURITY-BOUNDARY.md exists at the project root, listing all 12 intentional vulnerabilities with their purpose, and separately listing any real security findings with their status
**Plans**: TBD

Plans:
- [ ] 09-01: TBD

### Phase 10: DAST French Translation
**Goal**: DAST lab has the same full-French experience as the SCA lab, so students work entirely in their native language across both labs
**Depends on**: Phase 9
**Requirements**: DAST-01, DAST-02
**Success Criteria** (what must be TRUE):
  1. All 6 DAST scenario descriptions, instructions, and results display in Quebec French using the localize() pattern
  2. All DAST views (scenario list, scenario detail, results) display in Quebec French
**Plans**: TBD

Plans:
- [ ] 10-01: TBD

### Phase 11: Instructor Tools
**Goal**: Instructor can see at a glance which students are active, what they're working on, and their overall progress — enabling timely intervention during class
**Depends on**: Phase 10
**Requirements**: INST-01, INST-02
**Success Criteria** (what must be TRUE):
  1. Instructor dashboard shows each student's last_active_at timestamp and current finding being analyzed
  2. Instructor dashboard includes a progress summary card showing per-student completion across labs
**Plans**: TBD

Plans:
- [ ] 11-01: TBD

### Phase 12: Instructor Answer Key
**Goal**: Instructor has a French-language reference showing expected classifications, reasoning, and discussion prompts for all 12 findings, enabling confident in-class facilitation
**Depends on**: Phase 11
**Requirements**: AKEY-01, AKEY-02, AKEY-03, AKEY-04, AKEY-05, AKEY-06
**Success Criteria** (what must be TRUE):
  1. Instructor navigating to the answer key page sees all 12 findings with their expected classification (vrai positif, faux positif, etc.), reasoning, and discussion prompts -- entirely in Quebec French
  2. A student attempting to access the answer key page is denied (redirect or 403) -- the route is role-gated at the handler level, not just hidden in the UI
  3. Instructor viewing a specific finding detail page sees a collapsible inline section with the expected answer, invisible to students even in page source
  4. Answer key page is linked from the instructor dashboard so it is discoverable without memorizing a URL
**Plans:** 2 plans

Plans:
- [ ] 12-01-PLAN.md -- i18n answer key content, standalone answer key page, dashboard link, and role-gating with RBAC-bypass hardening
- [ ] 12-02-PLAN.md -- Inline collapsible answer on finding detail page and smoke test extensions

### Phase 13: Documentation
**Goal**: README and instructor-facing docs accurately describe the v1.1 feature set so a new instructor (or future Julie) can understand and use the platform without tribal knowledge
**Depends on**: Phase 12
**Requirements**: DOCS-01, DOCS-02
**Success Criteria** (what must be TRUE):
  1. README describes current features (inline code snippets, answer key, DAST French, CTF lab, code quality tooling), setup instructions, and usage -- reflecting the actual shipped v1.1 state
  2. Instructor documentation explains how to access and use the answer key, what the code snippets show students, and any new classroom workflow considerations
**Plans**: TBD

Plans:
- [ ] 13-01: TBD

### Phase 14: Code Quality
**Goal**: Codebase has consistent formatting and linting enforced by tooling, with dead code removed -- without touching the 12 intentional SCA vulnerabilities
**Depends on**: Phase 13
**Requirements**: QUAL-01, QUAL-02, QUAL-03, QUAL-04
**Success Criteria** (what must be TRUE):
  1. Running `npm run lint` executes ESLint 9 and reports zero errors/warnings across the codebase
  2. Running `npm run format` executes Prettier 3 and the codebase is already formatted (no changes needed after a fresh format pass)
  3. No dead code or unused variables remain in the codebase (verified by ESLint rules)
  4. All 12 intentional SCA vulnerabilities and the SQL pattern-matching DB adapter are preserved exactly as-is -- `npm test` smoke test passes before and after every code quality change
**Plans:** 2/2 plans complete

Plans:
- [ ] 14-01-PLAN.md -- Install ESLint 9 + Prettier 3 devDependencies, create config files, add npm scripts
- [ ] 14-02-PLAN.md -- Fix all lint errors, format codebase, remove dead code, verify vulnerability preservation

### Phase 15: CSS Extraction
**Goal**: Shared visual patterns (severity badges, cards, status indicators) are defined once in a shared stylesheet instead of duplicated across 8+ inline style blocks
**Depends on**: Phase 14
**Requirements**: CSS-01
**Success Criteria** (what must be TRUE):
  1. Common CSS patterns (severity badges, card layouts, status indicators) are in public/styles.css and referenced from templates instead of inline `<style>` blocks
**Plans:** 2/2 plans complete

Plans:
- [ ] 15-01-PLAN.md -- Create public/styles.css with all shared and page-specific CSS, update header.ejs, clean SCA and DAST templates
- [ ] 15-02-PLAN.md -- Clean VM, Pentest, and Admin templates, final codebase-wide verification

### Phase 16: CTF Pentest Lab
**Goal**: Students exploit the same 12 vulnerabilities they analyzed in SCA -- but now as attackers capturing hidden flags -- completing the pedagogical loop from analyst to attacker to class discussion
**Depends on**: Phase 15
**Requirements**: CTF-01, CTF-02, CTF-03, CTF-04, CTF-05, CTF-06, CTF-07, CTF-08, CTF-09
**Success Criteria** (what must be TRUE):
  1. 12 CTF challenges are available, each corresponding to an SCA finding, with flags planted in the codebase (source code, cookies, hidden endpoints, backup files)
  2. Progressive unlock works: all 4 Easy available at start, solving 2 Easy unlocks 3 Medium, solving 2 Medium unlocks 5 Advanced
  3. Scoring system awards Easy=100, Medium=200, Advanced=300 points; hints deduct 10/20 points; max score is 2,500
  4. Instructor sees a ranked leaderboard with per-student progress and challenge heatmap
  5. Successful flag capture triggers a celebration animation (radial pulse + counter tick-up) with tier unlock banner
  6. Sticky hunt reminder bar appears on all pages showing active challenge while student explores the app
  7. Hint system uses two-click inline confirmation to prevent accidental point loss
  8. All CTF content (challenge descriptions, hints, UI) is in Quebec French
  9. Old pentest form-filling module is replaced (old routes/views/tables removed)
**Plans**: TBD

Plans:
- [ ] 16-01: TBD
- [ ] 16-02: TBD
- [ ] 16-03: TBD

**Full spec:** `docs/superpowers/specs/2026-03-19-ctf-pentest-lab-design.md`

## Progress

**Execution Order:**
Phases execute in numeric order: 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12 -> 13 -> 14 -> 15 -> 16

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Translation Foundation | v1.0 | 1/1 | Complete | 2026-03-12 |
| 2. Shared UI Translation | v1.0 | 1/1 | Complete | 2026-03-12 |
| 3. SCA Student Experience | v1.0 | 2/2 | Complete | 2026-03-12 |
| 4. SCA Instructor Experience | v1.0 | 2/2 | Complete | 2026-03-12 |
| 5. Deployment Verification | v1.0 | 2/2 | Complete | 2026-03-12 |
| 6. Inline Code Snippets | v1.1 | 2/2 | Complete | 2026-03-12 |
| 7. Quick Wins | v1.1 | 0/1 | Planned | - |
| 8. Testing | v1.1 | 0/? | Not started | - |
| 9. Security Boundary Doc | v1.1 | 0/? | Not started | - |
| 10. DAST French | v1.1 | 0/? | Not started | - |
| 11. Instructor Tools | v1.1 | 0/? | Not started | - |
| 12. Instructor Answer Key | v1.1 | 0/2 | Planned | - |
| 13. Documentation | v1.1 | 0/? | Not started | - |
| 14. Code Quality | 2/2 | Complete    | 2026-03-21 | - |
| 15. CSS Extraction | 2/2 | Complete   | 2026-03-21 | - |
| 16. CTF Pentest Lab | v1.1 | 0/? | Not started | - |
