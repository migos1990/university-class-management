# Milestones

## v1.0 HEC Montreal SCA Lab Production Release (Shipped: 2026-03-12)

**Phases:** 5 | **Plans:** 8 | **Tasks:** 16
**Files:** 50 changed (+6,798 / -655) | **LOC:** ~11,800 (JS + EJS)
**Timeline:** 2026-03-12 (single day) | **Git range:** `824e4ee..2d8744b`

**Key accomplishments:**
1. Complete French i18n infrastructure with ~136 SCA translation keys and localize() helper
2. Full Quebec French student experience: login, navigation, error pages, 12 SCA findings with difficulty badges and guided hints
3. French instructor dashboard with live class progress stats (30s polling) and student-detail review
4. Codespaces deployment hardening: safe defaults, HTTPS disabled, auto-reset, port visibility automation
5. Comprehensive 13-port smoke test (`npm test`) verifying French content and end-to-end student journey

**Delivered:** Transformed English-only SCA lab into a fully French, classroom-ready experience for 30+ HEC Montreal students with zero-friction deployment on GitHub Codespaces.

**Requirements:** 18/18 satisfied (TRAN-01..10, SCAC-01..04, INST-01, DEPL-01..03)
**Audit:** Tech debt only — 4 minor items, no blockers (see milestones/v1.0-MILESTONE-AUDIT.md)

**Archives:**
- [milestones/v1.0-ROADMAP.md](milestones/v1.0-ROADMAP.md)
- [milestones/v1.0-REQUIREMENTS.md](milestones/v1.0-REQUIREMENTS.md)
- [milestones/v1.0-MILESTONE-AUDIT.md](milestones/v1.0-MILESTONE-AUDIT.md)

---

