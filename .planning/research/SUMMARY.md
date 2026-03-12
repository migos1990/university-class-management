# Project Research Summary

**Project:** HEC Montreal SCA Lab Production Release
**Domain:** Educational SCA (Static Code Analysis) lab for university application security course
**Researched:** 2026-03-12
**Confidence:** HIGH

## Executive Summary

This project is a production-readiness push for a server-rendered Express/EJS classroom platform that runs 12 team instances inside a single GitHub Codespace. The platform already has a complete SCA workflow -- 12 pre-seeded findings mapped to real CWE vulnerabilities in the codebase itself, a student triage workflow (classify, annotate, submit), an instructor review matrix, and orchestrated multi-instance deployment. The core gap is straightforward but pervasive: the entire interface is in English (zero EJS templates call the existing `t()` translation function), the default language is English, and the SCA seed data content is English-only. This must be fixed for 30+ French-speaking HEC Montreal students tonight.

The recommended approach is strictly additive: no new dependencies, no architectural changes, no restructuring. The i18n infrastructure is already solid (custom `utils/i18n.js` with nested dot-notation keys, parameter interpolation, and English fallback). The work is (1) adding ~100 French translation keys to `fr.json`, (2) replacing hardcoded English strings in ~8 EJS templates with `t()` calls, (3) flipping the default language from `'en'` to `'fr'`, (4) enriching SCA seed data with French fields, and (5) enhancing the instructor dashboard with polling-based class progress stats. Every pattern needed already exists in the codebase -- this is extension work, not invention.

The primary risks are Codespaces port visibility (ports default to private, blocking student access entirely) and the sheer volume of string replacements across templates (a typo in a translation key shows the raw key instead of French text). Both are mitigable: port visibility requires a single CLI command before class, and translation key errors are cosmetic rather than functional. The session cookie + Codespaces proxy interaction is a secondary risk avoided by not enabling HTTPS in the security panel.

## Key Findings

### Recommended Stack

No new dependencies. The entire implementation uses the existing Express 4.18 / EJS 3.1 / Node.js 22 stack with the custom `utils/i18n.js` module. The i18n system already supports nested dot-notation keys (`sca.lab.title`), `{param}` interpolation, and automatic English fallback. Real-time dashboard updates use the existing `setInterval + fetch` polling pattern already proven in the classroom-manager dashboard and instructor broadcast system.

**Core technologies (all existing, no changes):**
- **Express 4.18 + EJS 3.1:** Server-rendered monolith with `t()` translation helper injected into all views via `res.locals`
- **Custom i18n module (`utils/i18n.js`):** Loads JSON translation files at startup, supports nested keys and parameter interpolation
- **HTTP polling (setInterval + fetch):** Dashboard updates every 20-60s, matching two existing patterns in the codebase
- **Codespaces devcontainer:** Port forwarding for 13 ports, `postCreateCommand` for npm install + setup, `postStartCommand` for auto-start

**Critical version requirements:** None. Everything is locked by the existing devcontainer image.

### Expected Features

**Must have (P0 -- class fails without these):**
- Full French translation of 4 SCA views (~80 strings) and 3 shared views (~45 strings)
- Default language flipped to French (one-line change in `utils/i18n.js`)
- Classification labels in French ("Vrai positif", "Faux positif", "Necessite une investigation")
- French AJAX feedback messages in save/submit flow
- French error messages on SCA routes
- Codespaces first-boot reliability verification (seeding, port forwarding, team isolation)

**Should have (P1 -- makes the class impactful):**
- Enriched SCA seed data with French descriptions, business-impact framing, educational context
- Guided workflow intro banner explaining the task in French
- Live class progress stats on instructor dashboard (aggregate completion, students started/completed)
- Class consensus indicators per finding (distribution of student classifications for discussion)

**Defer (P2 -- future sessions):**
- Contextual hints per finding (requires enriched seed data first)
- Finding difficulty indicators
- Instructor broadcast message form
- Severity distribution visuals
- Grading/scoring (tonight is formative, not summative)
- WebSocket real-time updates (polling is sufficient for 30 students)
- Language toggle UI (all students speak French)
- Mobile responsive design (students are on laptops)

### Architecture Approach

The architecture is an additive-only modification strategy across three independent layers: (1) Translation Data (JSON files + seed data), (2) View Integration (EJS templates call `t()`), and (3) Dashboard Enhancement (new API fields + client-side polling). These layers have clear dependencies -- Layer 2 requires Layer 1 to exist, Layer 3 is independent -- but the modified files are distinct across layers, enabling parallel work on shared UI translation and SCA-specific translation.

**Major components:**
1. **Translation JSON (`config/translations/fr.json`)** -- Store all French UI strings under `sca.*` and `nav.*` namespaces; purely additive to existing 290-key file
2. **SCA view templates (`views/sca/*.ejs`)** -- Replace ~80 hardcoded English strings with `<%= t('sca.xxx') %>` calls
3. **Shared UI templates (`views/partials/header.ejs`, `views/login.ejs`)** -- Replace ~45 hardcoded English strings; login.ejs is standalone (no partials) and needs separate treatment
4. **SCA seed data (`utils/seedData.js`)** -- Add `fr_title`, `fr_description`, `fr_remediation` fields to 12 findings; views use `localize()` helper
5. **Enhanced `/api/summary` endpoint** -- Add `consensus`, `draft_count`, `class_stats` fields to existing JSON response for instructor dashboard polling
6. **Classroom dashboard SCA section** -- New `renderSCADetail()` function following established pattern in `classroom-manager.js`

### Critical Pitfalls

1. **Templates never call `t()` (CRITICAL)** -- Zero EJS templates use the translation function. Adding keys to `fr.json` alone changes nothing. Every hardcoded English string in every template must be replaced with a `t()` call. This is the single largest workstream.
2. **Codespaces port visibility defaults to private (CRITICAL)** -- Students on other machines cannot access team ports unless the professor manually sets them to public. Must run `gh codespace ports visibility 3000:public ... 3012:public -c $CODESPACE_NAME` before class.
3. **Language defaults to English (CRITICAL)** -- `utils/i18n.js` line 75 defaults to `'en'`. Even after template translation, all students see English on first load. One-line fix but easy to forget.
4. **SCA seed data is English-only (HIGH)** -- Students spend 90% of their time reading finding content (titles, descriptions, remediation), not UI chrome. A French UI wrapper around English security content creates a jarring bilingual experience.
5. **Session cookies may fail in Codespaces (MEDIUM)** -- If HTTPS is enabled in the security panel, the `secure` cookie flag + Codespaces proxy causes silent login failures. Prevention: do not enable HTTPS in security settings.
6. **`autoResetOnStart` is false (MEDIUM)** -- Stale data from test runs persists across restarts. Set to `true` in `classroom.config.json` before deploying.

## Implications for Roadmap

Based on research, the work divides into 5 phases with clear dependency ordering.

### Phase 1: Translation Foundation
**Rationale:** All subsequent translation work depends on (a) French being the default language and (b) translation keys existing in the JSON files. This phase is invisible to users but unlocks everything.
**Delivers:** i18n infrastructure ready for template integration -- default language flipped, ~100 translation keys added, `localize()` helper for seed data, `<html lang>` fix
**Addresses:** Default language switch (P0), translation key creation, `localize()` helper, `<html lang="en">` fix
**Avoids:** Pitfall 2 (English default), Pitfall 3 (`<html lang="en">`), and ensures Pitfall 1 can be resolved in subsequent phases

### Phase 2: Shared UI Translation (Login + Navigation)
**Rationale:** Login is the first thing students see; sidebar navigation is visible on every page. These create the French-first impression. Also, header.ejs is included by every authenticated page -- validating this integration point early catches breakage before SCA-specific work begins.
**Delivers:** French login page, French sidebar navigation, French error page, French student/professor dashboards
**Addresses:** Login page translation (P0), header sidebar translation (P0), error page translation (P0), dashboard translation
**Avoids:** Pitfall 7 (standalone login page), Pitfall 10 (sidebar English), Pitfall 14 (header subtitle), Pitfall 15 (demo account instructions)

### Phase 3: SCA Student Experience
**Rationale:** This is where students spend 90% of their time. The student lab view and finding detail view are the core learning interface. Seed data enrichment belongs here because students read finding content more than UI chrome.
**Delivers:** Fully French SCA student workflow (lab listing, finding detail, review form, save/submit feedback), enriched seed data with French fields, guided workflow intro banner
**Addresses:** SCA view translation (P0), classification labels in French (P0), AJAX feedback messages (P0), French error messages (P0), seed data enrichment (P1), guided workflow banner (P1)
**Avoids:** Pitfall 1 (templates not using `t()`), Pitfall 6 (English seed data), Pitfall 9 (JS alert/confirm strings)

### Phase 4: SCA Instructor Experience
**Rationale:** Less urgent than student-facing pages but needed for class monitoring. Depends on Phase 3 because instructor views display the same translation keys and seed data. Dashboard enhancement follows the existing polling pattern exactly.
**Delivers:** French instructor dashboard, class progress stats, consensus indicators, enhanced classroom-manager SCA section
**Addresses:** Instructor.ejs translation (P0), student-detail.ejs translation, live class progress stats (P1), class consensus indicators (P1), enhanced `/api/summary` endpoint
**Avoids:** Pitfall 12 (stale data -- set `autoResetOnStart: true`)

### Phase 5: Codespaces Verification and Polish
**Rationale:** Must be done last because it tests the full integrated experience. Includes deployment verification, error path testing, and minor polish. This is the "does it actually work in the real classroom?" gate.
**Delivers:** Verified Codespaces deployment, public port access, end-to-end French workflow confirmation, date formatting, security status bar translation
**Addresses:** Port visibility verification (P0), session cookie testing, first-boot seeding, pre-class checklist, minor polish (date locale, security badges)
**Avoids:** Pitfall 4 (private ports), Pitfall 5 (session cookies), Pitfall 11 (slow boot), Pitfall 12 (stale data)

### Phase Ordering Rationale

- Phase 1 must precede all others: translation keys and default language are prerequisites for every template change. Without them, `t()` calls resolve to raw key strings.
- Phase 2 before Phase 3: students encounter login and navigation before the SCA lab. Also, header.ejs is included by every authenticated page -- a syntax error there breaks everything. Better to validate early.
- Phase 3 before Phase 4: instructor views reference the same translation namespace and seed data as student views. Building student views first establishes the keys and patterns that instructor views reuse.
- Phases 2 and 3 can partially overlap: they modify different files (shared UI vs. SCA views), so parallel work is safe.
- Phase 5 must be last: it tests the integrated result of all prior phases.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3 (SCA Student Experience):** The seed data French field integration needs care -- the JSON database is schema-free so new fields store automatically, but the INSERT statements in `seedData.js` must align parameters correctly. The `localize()` helper pattern needs validation against the actual finding object structure. Also, writing pedagogically effective French security descriptions requires domain expertise.
- **Phase 5 (Codespaces Verification):** Port visibility behavior must be tested in the actual Codespace. The `gh codespace ports visibility` command may need to run from outside the Codespace. Test with an incognito browser to confirm public access.

Phases with standard patterns (skip research-phase):
- **Phase 1 (Translation Foundation):** One-line default change, additive JSON edits, simple middleware helper. Fully documented patterns.
- **Phase 2 (Shared UI Translation):** Repetitive `t()` call replacements. Pattern is identical across all templates. The STACK.md research provides the complete translation key structure.
- **Phase 4 (Instructor Experience):** Follows established polling and dashboard rendering patterns already proven in `classroom-manager.js`.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All recommendations based on direct codebase analysis. No new dependencies. Every technology already exists and works. |
| Features | HIGH | Feature landscape grounded in codebase capabilities, educational research on non-technical student engagement, and competitor analysis. Clear P0/P1/P2 prioritization. |
| Architecture | HIGH | Architecture is additive-only on a working monolith. All integration points verified against source code. Data flows traced through actual middleware chain. |
| Pitfalls | HIGH | 16 pitfalls identified, all verified by direct code evidence or official documentation. Priority ranking aligned with class-night time pressure. |

**Overall confidence:** HIGH

All four research streams converge on the same conclusion: this is a well-architected platform that needs surface-level translation and minor enhancement, not structural changes. The risk profile is low because every change is additive and every pattern is already proven in the codebase.

### Gaps to Address

- **Codespaces port visibility in practice:** The `devcontainer.json` cannot pre-set port visibility to "public." The `gh codespace ports visibility` CLI command is documented but must be tested in the actual Codespace before class. Consider adding this to a `postStartCommand` script if the CLI is available inside the container.
- **Seed data French content quality:** The French translations for 12 SCA finding descriptions need domain expertise in both application security and Quebec French technical terminology. Machine-translated security content may use incorrect terms. The existing `fr.json` uses appropriate Quebec French ("Televerser", "courriel") which is a good reference.
- **`express-session` + Codespaces proxy interaction:** The analysis suggests avoiding HTTPS in security settings, but the exact behavior of `secure` cookies behind the Codespaces reverse proxy should be tested empirically. Adding `app.set('trust proxy', 1)` is a safe defensive measure.
- **12-instance memory footprint:** The default 4-core/16GB Codespace should handle 13 Node.js processes, but this has not been load-tested with 30 concurrent students. If memory is tight, reducing `TEAM_COUNT` to 6 is the fallback.
- **Instructor classroom-manager dashboard:** This dashboard is entirely English HTML with no i18n -- deprioritized since only the professor sees it, but noted for completeness.

## Sources

### Primary (HIGH confidence)
- Direct codebase analysis -- all critical files read and verified: `utils/i18n.js`, `config/translations/fr.json`, `views/sca/*.ejs`, `views/partials/header.ejs`, `views/login.ejs`, `scripts/classroom-manager.js`, `.devcontainer/devcontainer.json`, `server.js`, `routes/sca.js`, `utils/seedData.js`, `config/database.js`, `classroom.config.json`, `package.json`
- GitHub Codespaces port forwarding documentation -- https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace
- GitHub Codespaces port visibility restrictions -- https://docs.github.com/en/codespaces/managing-codespaces-for-your-organization/restricting-the-visibility-of-forwarded-ports
- Express-session secure cookie behavior -- https://github.com/expressjs/session/issues/983

### Secondary (MEDIUM confidence)
- OWASP Application Security Curriculum -- educational framework for security training
- OWASP Security Shepherd -- classroom-mode security training with user-specific solution keys
- PentesterLab Code Review Exercise -- guided code review training with progressive difficulty
- Secure Code Warrior -- developer security training platform patterns
- ACM study on gamification in university cybersecurity courses -- real-world problem-solving tasks preferred over leaderboards
- Real-time student progress monitoring best practices -- instructor dashboard patterns
- Vulnerability triage best practices -- false positive vs true positive classification industry approach

### Tertiary (LOW confidence)
- Codespaces port visibility first-boot community discussion -- https://github.com/orgs/community/discussions/156546
- GitHub Classroom Codespaces FAQ -- https://github.com/orgs/community/discussions/145312

---
*Research completed: 2026-03-12*
*Ready for roadmap: yes*
