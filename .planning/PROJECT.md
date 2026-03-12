# HEC Montreal — SCA Lab Production Release

## What This Is

A production-ready Static Code Analysis (SCA) hands-on lab for a 30+ student application security class at HEC Montreal. The Express.js/EJS platform delivers 12 pre-seeded SCA findings in French (Quebec), with team-based Codespaces deployment (12 instances + instructor dashboard), difficulty-graded findings with guided hints, and live class progress monitoring. The entire experience — from Codespace boot to student submission to instructor review — works end-to-end in French with zero manual intervention.

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
- ✓ App defaults to French for all new sessions — v1.0
- ✓ Full French translation of all SCA views (student-lab, finding-detail, instructor, student-detail) — v1.0
- ✓ French translation of shared UI (header, login, error pages, navigation) — v1.0
- ✓ Enhanced SCA seed data with enriched descriptions and business impact context — v1.0
- ✓ Live class stats on instructor SCA dashboard (students started, avg completion, pace) — v1.0
- ✓ Guided workflow with contextual hints and difficulty indicators — v1.0
- ✓ Codespaces setup verification (clean first-boot, port visibility, data seeding) — v1.0
- ✓ End-to-end French student journey verified by comprehensive smoke test — v1.0

### Active

- [ ] Class consensus indicators per finding (% confirmed vs FP vs needs investigation)
- [ ] Severity distribution visual card on instructor dashboard
- [ ] Instructor broadcast message form on SCA dashboard
- [ ] Per-finding time tracking (how long students spend analyzing each finding)
- [ ] EN/FR language toggle UI for bilingual flexibility
- [ ] Other lab modules (DAST, Pentest, VM) translated to French

### Out of Scope

- Real-time WebSocket updates — polling at 30s intervals is sufficient
- Grading/scoring system — formative exercise, not summative
- Auto-grading or "correct answer" comparison — SCA triage is subjective
- Mobile responsive design — students use laptops in class
- Solution guide visible to students — instructor references SOLUTION-GUIDE.md during discussion

## Context

Shipped v1.0 with ~11,800 LOC (6,870 JS + 4,928 EJS).
Tech stack: Express.js 4.18, EJS 3.1, Node.js 22, JSON file-based DB.
Deployment: GitHub Codespaces with devcontainer, 12 team instances (ports 3001-3012) + instructor (port 3000).
~136 i18n translation keys in Quebec French, localize() helper for SCA finding data.
Smoke test (`npm test`) validates all 13 ports, French content, and authenticated student journey.
4 minor tech debt items tracked in audit (no blockers for classroom use).

## Constraints

- **Language**: Quebec French — not European French
- **Tech stack**: No new dependencies — Express/EJS/vanilla JS
- **Codespaces**: Must work in GitHub Codespaces environment
- **Audience**: Non-technical students, no TA support

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Default to French, no toggle | Simplest approach; all students are French-speaking | ✓ Good |
| Focus on SCA module only | Tonight's class is SCA; other modules can wait | ✓ Good |
| Enhance existing seed data | 12 findings exist but descriptions richer for learning impact | ✓ Good |
| No new dependencies | Time pressure + stability requirement | ✓ Good |
| localize() overlays title/description/remediation only | Category and severity stay English (industry terms) | ✓ Good |
| All ~136 keys added upfront in Phase 1 | Phases 2-4 only wire templates, never add keys | ✓ Good — zero key-addition work in later phases |
| DIFFICULTY_MAP as route-level constant | Simple lookup, no DB changes needed | ✓ Good |
| EJS-embedded JS constants for AJAX feedback | Avoids runtime i18n in client-side JS | ✓ Good |
| Stats endpoint with 30s polling | Sufficient for classroom; avoids WebSocket complexity | ✓ Good |
| HTTPS toggle disabled at API+UI level | Prevents Codespaces proxy conflicts | ✓ Good |
| Port visibility via gh CLI in postAttachCommand | Automatic, no manual step for professor | ✓ Good |
| Deep test one instance, health-check all 13 | Balances thoroughness with test speed | ✓ Good |

---
*Last updated: 2026-03-12 after v1.0 milestone*
