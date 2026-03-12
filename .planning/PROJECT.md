# HEC Montreal — SCA Lab Production Release

## What This Is

A production-ready Static Code Analysis (SCA) hands-on lab for a 30+ student application security class at HEC Montreal. The platform already exists — an Express.js/EJS security education app with 12 pre-seeded SCA findings, team-based Codespaces deployment, and an instructor dashboard. Tonight's class focuses on the SCA module: students classify real code vulnerabilities, write analysis notes, and submit findings while the instructor monitors progress live. The entire experience needs to be in French (Quebec) and bulletproof for non-technical students with no TA support.

## Core Value

The SCA lab must work flawlessly end-to-end in French — from Codespace boot to student submission to instructor review — with zero friction for non-technical students.

## Requirements

### Validated

- ✓ 12 SCA findings seeded with real CWEs mapped to actual codebase — existing
- ✓ Student review workflow (classify, notes, remediation, save draft, submit) — existing
- ✓ Instructor dashboard with review matrix and VM import — existing
- ✓ Classroom manager with 12 team instances on Codespaces — existing
- ✓ i18n infrastructure (utils/i18n.js, en.json, fr.json, language middleware) — existing
- ✓ Role-based access (student, professor, admin) — existing
- ✓ Health checks and instance monitoring — existing

### Active

- [ ] Full French translation of all SCA views (student-lab, instructor, finding-detail, student-detail)
- [ ] French translation of shared UI (header, footer, login, dashboards, navigation)
- [ ] Default language set to French for all users
- [ ] Enhanced SCA seed data — richer descriptions, better code snippets, varied severity distribution
- [ ] Live class stats on instructor SCA dashboard — real-time student progress, class consensus indicators
- [ ] Guided workflow — contextual hints/tips in French to help students understand what good analysis looks like
- [ ] Codespaces setup verification — clean first-time boot, team isolation, port visibility, data seeding
- [ ] End-to-end polish — no dead ends, clear error messages in French, smooth save/submit flow
- [ ] Robust error handling for non-technical users — friendly French error messages, graceful recovery

### Out of Scope

- Other lab modules (DAST, Pentest, VM) — not the focus of tonight's class
- English/French language toggle UI — defaulting to French is simpler and sufficient
- Mobile responsiveness — students use laptops in class
- Real-time WebSocket updates — polling-based updates are sufficient for the instructor dashboard
- Grading features — not needed for tonight's SCA lab
- New security features or toggles — existing 9 features are sufficient

## Context

- **Environment:** GitHub Codespaces with devcontainer (Node.js 22, Express 4.18, EJS 3.1)
- **Deployment:** Classroom manager spawns 12 team instances (ports 3001-3012) + instructor dashboard (port 3000)
- **Database:** JSON file-based with SQL-like interface, per-team isolation via DATA_DIR env var
- **Audience:** 30+ non-technical students at HEC Montreal, Quebec — French-speaking
- **No TA:** Professor manages the entire class alone; the app must be self-explanatory
- **Time pressure:** Class is tonight (2026-03-12) — changes must be focused and reliable
- **Existing i18n:** Infrastructure exists but SCA views have zero French translations; all strings hardcoded in English
- **SCA findings:** 12 findings already seeded in utils/seedData.js, mapped to real code vulnerabilities

## Constraints

- **Timeline**: Must be ready for tonight's class — no experimental changes
- **Stability**: Every change must be safe; cannot break existing functionality
- **Language**: Quebec French — not European French (use local terminology where relevant)
- **Tech stack**: No new dependencies — work within Express/EJS/vanilla JS
- **Codespaces**: Must work in GitHub Codespaces environment; no local-only assumptions

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Default to French, no toggle | Simplest approach for tonight; all students are French-speaking | — Pending |
| Focus on SCA module only | Tonight's class is SCA; other modules can wait | — Pending |
| Enhance existing seed data | 12 findings exist but descriptions can be richer for learning impact | — Pending |
| No new dependencies | Time pressure + stability requirement = work with what's there | — Pending |

---
*Last updated: 2026-03-12 after initialization*
