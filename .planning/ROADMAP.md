# Roadmap: HEC Montreal SCA Lab

## Milestones

- ✅ **v1.0 MVP** -- Phases 1-5 (shipped 2026-03-12)
- 🚧 **v1.1 Polish & Pedagogy** -- Phases 6-9 (in progress)

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

**Milestone Goal:** Improve the learning experience with inline code snippets, instructor answer key, updated documentation, and code quality optimization.

- [x] **Phase 6: Inline Code Snippets** - Syntax-highlighted multi-line code with vulnerable-line callout in finding views
- [ ] **Phase 7: Instructor Answer Key** - Role-gated answer key with classifications, reasoning, and discussion prompts in French
- [ ] **Phase 8: Documentation** - README and instructor docs reflecting the v1.1 feature set
- [ ] **Phase 9: Code Quality** - ESLint/Prettier tooling, dead code removal, and CSS deduplication (preserving intentional vulnerabilities)

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

### Phase 7: Instructor Answer Key
**Goal**: Instructor has a French-language reference showing expected classifications, reasoning, and discussion prompts for all 12 findings, enabling confident in-class facilitation
**Depends on**: Phase 6
**Requirements**: AKEY-01, AKEY-02, AKEY-03, AKEY-04, AKEY-05, AKEY-06
**Success Criteria** (what must be TRUE):
  1. Instructor navigating to the answer key page sees all 12 findings with their expected classification (vrai positif, faux positif, etc.), reasoning, and discussion prompts -- entirely in Quebec French
  2. A student attempting to access the answer key page is denied (redirect or 403) -- the route is role-gated at the handler level, not just hidden in the UI
  3. Instructor viewing a specific finding detail page sees a collapsible inline section with the expected answer, invisible to students even in page source
  4. Answer key page is linked from the instructor dashboard so it is discoverable without memorizing a URL
**Plans**: TBD

Plans:
- [ ] 07-01: TBD
- [ ] 07-02: TBD

### Phase 8: Documentation
**Goal**: README and instructor-facing docs accurately describe the v1.1 feature set so a new instructor (or future Julie) can understand and use the platform without tribal knowledge
**Depends on**: Phase 7
**Requirements**: DOCS-01, DOCS-02
**Success Criteria** (what must be TRUE):
  1. README describes current features (inline code snippets, answer key, code quality tooling), setup instructions, and usage -- reflecting the actual shipped v1.1 state
  2. Instructor documentation explains how to access and use the answer key, what the code snippets show students, and any new classroom workflow considerations
**Plans**: TBD

Plans:
- [ ] 08-01: TBD

### Phase 9: Code Quality
**Goal**: Codebase has consistent formatting and linting enforced by tooling, with dead code removed and duplicated CSS consolidated -- without touching the 12 intentional SCA vulnerabilities
**Depends on**: Phase 8
**Requirements**: QUAL-01, QUAL-02, QUAL-03, QUAL-04, QUAL-05
**Success Criteria** (what must be TRUE):
  1. Running `npm run lint` executes ESLint 9 and reports zero errors/warnings across the codebase
  2. Running `npm run format` executes Prettier 3 and the codebase is already formatted (no changes needed after a fresh format pass)
  3. Duplicated CSS patterns (if any are worth extracting) are consolidated into shared styles, reducing copy-paste across templates
  4. No dead code or unused variables remain in the codebase (verified by ESLint rules)
  5. All 12 intentional SCA vulnerabilities and the SQL pattern-matching DB adapter are preserved exactly as-is -- `npm test` smoke test passes before and after every code quality change
**Plans**: TBD

Plans:
- [ ] 09-01: TBD
- [ ] 09-02: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 6 -> 7 -> 8 -> 9

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Translation Foundation | v1.0 | 1/1 | Complete | 2026-03-12 |
| 2. Shared UI Translation | v1.0 | 1/1 | Complete | 2026-03-12 |
| 3. SCA Student Experience | v1.0 | 2/2 | Complete | 2026-03-12 |
| 4. SCA Instructor Experience | v1.0 | 2/2 | Complete | 2026-03-12 |
| 5. Deployment Verification | v1.0 | 2/2 | Complete | 2026-03-12 |
| 6. Inline Code Snippets | v1.1 | 2/2 | Complete | 2026-03-12 |
| 7. Instructor Answer Key | v1.1 | 0/? | Not started | - |
| 8. Documentation | v1.1 | 0/? | Not started | - |
| 9. Code Quality | v1.1 | 0/? | Not started | - |
