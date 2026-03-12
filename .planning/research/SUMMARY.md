# Project Research Summary

**Project:** HEC Montreal SCA Lab -- v1.1 Polish & Pedagogy
**Domain:** Incremental feature additions (inline code snippets, instructor answer key, code quality) to an educational SCA lab platform
**Researched:** 2026-03-12
**Confidence:** HIGH

## Executive Summary

The v1.1 milestone adds four capabilities to an already-shipped educational SCA lab: (1) multi-line inline code snippets with vulnerable-line highlighting in the finding detail view, (2) an instructor answer key for in-class discussion, (3) updated documentation, and (4) code quality optimization via ESLint/Prettier. The existing Express 4.18 / EJS 3.1 / Node.js 22 stack is proven and stable after v1.0. The research across all four areas converges on a single theme: this is enrichment work on a working system, not structural change. Every feature integrates into existing patterns -- seed data enrichment, route-level data injection, role-gated views, and the i18n translation system.

The recommended approach uses Prism.js via CDN (zero npm dependencies) for syntax-highlighted code blocks with its native `data-line` attribute mapping directly to the existing `finding.line_number` field. The instructor answer key follows the established `DIFFICULTY_MAP` pattern: static data keyed by finding ID, merged at route time, gated behind `requireRole(['admin', 'professor'])`. ESLint 9 and Prettier 3 are added as devDependencies only, completing the already-configured VS Code extensions in devcontainer.json. The STACK and ARCHITECTURE research are in tension on one point -- whether to use Prism.js CDN or CSS-only rendering for code snippets -- but STACK's recommendation of Prism.js is the stronger choice because its `data-line` plugin eliminates custom vulnerable-line highlighting code entirely.

The critical risks are: (1) introducing XSS by switching to unescaped EJS output for code snippets in a security education platform -- ironic and reputation-damaging; (2) destroying student data by modifying the destructive `seedDatabase()` function; and (3) leaking the answer key to students through template-level rather than route-level role gating. All three are avoidable through architectural discipline: keep `<%= %>` escaping (or let Prism.js handle rendering), store new snippet data outside the seed function using the `DIFFICULTY_MAP` route-enrichment pattern, and gate answer key data in the route handler before it reaches the template.

## Key Findings

### Recommended Stack

No new production dependencies. Two additions: Prism.js loaded from CDN for browser-side syntax highlighting, and ESLint 9 + Prettier 3 as devDependencies for code quality tooling. See [STACK.md](STACK.md) for full rationale.

**Core technologies:**
- **Prism.js 1.29.0 via CDN:** Syntax highlighting with native `data-line` vulnerable-line callout, `data-start` for real line numbers, okaidia dark theme matching existing `#282c34` code blocks -- ~15 KB total, zero npm impact
- **ESLint 9 + eslint-config-prettier 10:** Flat config format (project uses CommonJS), rules tuned to existing patterns (`no-console: off`, `eqeqeq: error`), completes the already-declared VS Code extensions
- **Prettier 3.4:** `singleQuote: true`, `printWidth: 120` (matching existing code conventions), `semi: true` -- config based on actual codebase analysis

**Explicitly rejected:** highlight.js (no native line-highlight), CodeMirror/Monaco (editor libraries, not display), Shiki (requires Node.js runtime), TypeScript (11,800 LOC rewrite for zero classroom benefit), husky/lint-staged (solo instructor project), any CSS framework (inline styles are the convention).

### Expected Features

See [FEATURES.md](FEATURES.md) for the full landscape including dependency graph.

**Must have (P0 -- defines the v1.1 milestone):**
- Multi-line code snippets (5-10 lines) replacing single-line snippets in finding detail
- Vulnerable line visually called out within the snippet (background highlight + left border)
- Line numbers in code snippets corresponding to actual file line numbers
- Instructor answer key view (role-gated, French, with expected classification + reasoning + discussion prompts for all 12 findings)
- Updated README reflecting v1.1 features

**Should have (P1 -- high value, low risk):**
- Syntax coloring via Prism.js (keywords, strings, comments differentiated)
- Answer key inline within finding-detail view (collapsible instructor-only section)
- Answer key comparison badges on student review (green check / red X vs expected)

**Defer (v2+):**
- Live code editor, auto-grading, student-visible solutions, comprehensive JSDoc/TypeScript migration, CSS framework adoption

### Architecture Approach

The architecture is additive-only with two independent work streams that can execute in parallel. See [ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries, data flows, and anti-patterns.

**Major components:**
1. **Seed data enrichment (`utils/seedData.js`)** -- Expand `code_snippet` to multi-line, add `code_snippet_start_line` and `code_snippet_vuln_line` fields to the 12 findings
2. **Enhanced code block rendering (`views/sca/finding-detail.ejs`)** -- Replace plain `<pre>` with Prism.js `<pre class="line-numbers" data-line="...">` or CSS-based line-numbered block with vulnerable-line highlighting
3. **Static answer key data (`data/sca-answer-key.json` + i18n keys)** -- 12 expected classifications in JSON, rich text (reasoning, discussion points) in `fr.json` under `sca.answerKey.*`
4. **Answer key route and view (`GET /sca/answer-key`)** -- Role-gated route, new EJS template reusing existing card/badge patterns, linked from instructor dashboard
5. **Code quality tooling (`eslint.config.js` + `.prettierrc`)** -- Config files + npm scripts, run after all features complete

**Key architectural decisions:**
- Answer key data gated at route level (never passed to template for student role), not template level
- Code snippets stay escaped (`<%= %>`) when using CSS-only approach; or use Prism.js which handles its own rendering safely
- Student-lab cards show only the vulnerable line (1 line), not the full multi-line snippet -- prevents layout bloat
- `localize()` function left unchanged; code snippets are source code and must NOT be translated

### Critical Pitfalls

See [PITFALLS.md](PITFALLS.md) for the complete set including recovery strategies and "looks done but isn't" checklist.

1. **XSS via unescaped code snippet output** -- Switching from `<%= %>` to `<%- %>` for multi-line rendering creates injection risk in a security education platform. Prevention: use Prism.js (handles its own escaping) or keep `<%= %>` with CSS-only styling. Test with a snippet containing `<script>alert(1)</script>`.
2. **Seed data destruction on reseed** -- `seedDatabase()` runs `DELETE FROM` on all tables before re-inserting. Modifying it to add new fields risks destroying student reviews on active Codespaces instances. Prevention: use route-level enrichment (the `DIFFICULTY_MAP` pattern) or accept that seed changes only apply to fresh instances.
3. **Answer key leaked to students** -- Passing answer key data unconditionally in `res.render()` exposes it in page source even when the template conditionally hides it. Prevention: role check in the route handler, never in the template alone.
4. **Card layout broken by multi-line snippets** -- 12 cards each with 10-line snippets makes student-lab unusably long. Prevention: show only the vulnerable line in card view; full snippet on finding-detail only.
5. **Missing French translations** -- New UI elements added in English break the French-first experience. Prevention: add ALL new i18n keys before writing any template code, following the v1.0 pattern.

## Implications for Roadmap

Based on research, the work divides into 4 phases. Two feature streams (snippets and answer key) are independent and could theoretically parallelize, but they share template files and should be sequenced to avoid merge conflicts. Code quality must come last.

### Phase 1: i18n Keys + Inline Code Snippets
**Rationale:** Multi-line snippets are the headline v1.1 feature and a prerequisite for syntax highlighting. i18n keys must be added before any template work (v1.0 lesson learned). Combining these ensures the data and translation layers are ready before any rendering changes.
**Delivers:** All new French translation keys in `fr.json`/`en.json`; expanded multi-line `code_snippet` data with `code_snippet_start_line` and `code_snippet_vuln_line` fields; Prism.js CDN tags in header/footer; line-numbered syntax-highlighted code block in finding-detail with vulnerable-line callout; compact vulnerable-line preview in student-lab cards.
**Addresses:** P0 features (multi-line snippets, vulnerable line highlight, line numbers) + P1 feature (syntax coloring via Prism.js)
**Avoids:** Pitfall 1 (XSS -- Prism.js handles escaping), Pitfall 2 (seed data destruction -- use route-level enrichment OR accept fresh-instance-only seeding), Pitfall 4 (card layout -- show only vulnerable line in cards), Pitfall 5 (missing French -- keys added first)

### Phase 2: Instructor Answer Key
**Rationale:** Independent of snippet work but benefits from Phase 1's enhanced code display in the answer key view. The answer key data structure and role-gating pattern must be established before any template work to prevent student exposure.
**Delivers:** `data/sca-answer-key.json` with 12 classifications; ~40 i18n keys for answer key content (reasoning, discussion points, common mistakes); `GET /sca/answer-key` route with role gating; `answer-key.ejs` template; link from instructor dashboard; optional inline answer section in finding-detail for instructor role.
**Addresses:** P0 feature (instructor answer key) + P1 features (inline answer key in finding-detail, comparison badges)
**Avoids:** Pitfall 3 (answer key exposure -- route-level gating, not template-level)

### Phase 3: Documentation and README
**Rationale:** Must follow feature work so documentation reflects the actual shipped state. Low complexity but depends on knowing the final feature set.
**Delivers:** Updated README reflecting v1.1 features (inline snippets, answer key, code quality tooling); architecture decision records if desired.
**Addresses:** P0 feature (updated README) + P2 (architecture decision records)
**Avoids:** No critical pitfalls, but must accurately describe the final state.

### Phase 4: Code Quality Optimization
**Rationale:** Must be the absolute last phase. Refactoring in parallel with feature work creates merge conflicts and makes regression tracking impossible. The JSON database adapter uses SQL string pattern matching -- restructuring queries can silently break it. Intentional vulnerabilities in the codebase must NOT be "fixed" during code quality work.
**Delivers:** ESLint 9 + Prettier 3 configured and running; `npm run lint` and `npm run format` scripts; linting/formatting pass across codebase; duplicated CSS extraction; dead code removal; consistent error handling patterns.
**Addresses:** P2 feature (code quality optimization)
**Avoids:** Pitfall 6 (smoke test regression -- run `npm test` before and after every commit), security mistake (accidentally fixing intentional vulnerabilities used as teaching examples)

### Phase Ordering Rationale

- Phase 1 first because multi-line snippets are the core deliverable and i18n keys are a prerequisite for all template work.
- Phase 2 after Phase 1 because the answer key view reuses the enhanced code block rendering.
- Phase 3 after Phases 1-2 because documentation must describe the final feature set.
- Phase 4 strictly last because refactoring after feature-complete avoids merge conflicts and ensures the smoke test baseline is stable.
- Phases 1 and 2 could theoretically parallelize (they modify different routes/views) but share `finding-detail.ejs` -- sequential is safer.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 1 (Snippets):** The Prism.js CDN integration is straightforward but the seed data expansion for 12 findings requires reading each actual source file to extract accurate 5-10 line snippets with correct line numbers. This is content authoring work, not engineering research. The STACK and ARCHITECTURE files disagree on whether to use Prism.js CDN or CSS-only -- resolve during phase planning (recommendation: Prism.js CDN, per STACK.md reasoning).
- **Phase 2 (Answer Key):** The 12 answer key entries (reasoning, discussion points, common mistakes) require pedagogical domain expertise in French. Content must be derived from the existing SOLUTION-GUIDE.md but rewritten as concise French instructor notes.

Phases with standard patterns (skip research-phase):
- **Phase 3 (Documentation):** README update is a writing task with no technical research needed.
- **Phase 4 (Code Quality):** ESLint 9 flat config and Prettier 3 setup are well-documented. The STACK.md already provides complete config files ready to use.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All recommendations verified against codebase analysis. Prism.js CDN availability confirmed. ESLint/Prettier versions compatible with Node 22. No speculative technology choices. |
| Features | HIGH | Feature landscape grounded in existing codebase capabilities and SOLUTION-GUIDE.md content. Clear P0/P1/P2 prioritization with explicit anti-features. Dependency graph verified. |
| Architecture | HIGH | Architecture is additive-only on a proven v1.0 system. All integration points verified against actual source code. Data flows traced through the middleware chain. New files estimated at 2-3, modified files at 7. |
| Pitfalls | HIGH | 6 critical pitfalls identified, all verified by direct code evidence. Recovery strategies provided. "Looks done but isn't" checklist covers edge cases (HTML angle brackets in snippets, first/last line vulnerability highlight, student view-source for answer key). |

**Overall confidence:** HIGH

All four research streams converge: this is well-scoped enrichment of a working system. Every pattern needed (seed data enrichment, route-level data injection, role-gated views, i18n keys, CSS styling) already exists in the codebase. The risk profile is low because changes are additive and patterns are proven.

### Gaps to Address

- **STACK vs ARCHITECTURE disagreement on syntax highlighting approach:** STACK.md recommends Prism.js via CDN. ARCHITECTURE.md recommends CSS-only (no Prism.js). FEATURES.md lists Prism.js as an anti-feature. Resolution needed during Phase 1 planning. Recommendation: go with Prism.js CDN per STACK.md -- the `data-line` attribute alone justifies it, and CDN loading is not a "dependency" in the npm sense.
- **Seed data modification strategy:** PITFALLS.md warns against modifying `seedDatabase()` (destructive reseed). ARCHITECTURE.md proposes modifying it with new fields. Resolution: if v1.1 is deployed to fresh Codespaces instances (not upgrading mid-class), seed data modification is safe. If upgrading existing instances, use the route-level enrichment pattern instead. Clarify deployment model during Phase 1 planning.
- **Content authoring for 12 findings:** Both the multi-line code snippets and the French answer key content require manual authoring work. This is not a technical gap but a time/effort gap. Each finding needs: (a) 5-10 lines of accurate source code extracted from the actual file, (b) French reasoning explaining the vulnerability, (c) French discussion prompts, (d) common student mistakes. Budget this as significant effort.
- **Prism.js theme compatibility:** The okaidia theme should match the existing `#282c34` dark background, but this needs visual verification. If the theme clashes with existing inline styles, custom CSS overrides may be needed.

## Sources

### Primary (HIGH confidence)
- Direct codebase analysis of all modified/new files: `utils/seedData.js`, `routes/sca.js`, `views/sca/finding-detail.ejs`, `views/sca/student-lab.ejs`, `views/sca/instructor.ejs`, `config/database.js`, `config/translations/fr.json`, `utils/i18n.js`, `.devcontainer/devcontainer.json`, `package.json`
- Prism.js official documentation -- https://prismjs.com/ (line-highlight plugin, line-numbers plugin, CDN availability)
- ESLint 9 flat config documentation -- https://eslint.org/docs/latest/use/configure/configuration-files
- Prettier 3 options documentation -- https://prettier.io/docs/en/options.html
- Existing SOLUTION-GUIDE.md in repository (expected classifications, teaching flow, grading rubric)

### Secondary (MEDIUM confidence)
- OWASP Security Shepherd -- classroom-mode security training patterns
- OWASP Secure Coding Dojo Code Review 101 -- structured code review with inline display
- Snyk Code SAST tool UX -- highlighted affected code lines with context
- SAST tools feature comparison (guru99.com) -- standard UI patterns for code review tools
- highlight.js vs Prism.js comparison -- https://github.com/highlightjs/highlight.js/issues/3625
- CSS-only syntax highlighting approaches (ft-syntax-highlight) -- validation of pre-rendered approach
- Server-side code highlighting performance analysis (remysharp.com)

### Tertiary (LOW confidence)
- yeswehack/vulnerable-code-snippets -- pattern reference for presenting vulnerable code with highlighted sections

---
*Research completed: 2026-03-12*
*Ready for roadmap: yes*
