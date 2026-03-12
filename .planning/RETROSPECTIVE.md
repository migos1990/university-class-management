# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — HEC Montreal SCA Lab Production Release

**Shipped:** 2026-03-12
**Phases:** 5 | **Plans:** 8 | **Tasks:** 16

### What Was Built
- Complete French i18n infrastructure (~136 keys) with localize() helper for SCA finding data
- Full Quebec French student experience: login, navigation, 12 SCA findings with difficulty badges, guided hints, and AJAX feedback
- French instructor dashboard with live class progress stats (30s polling), student-detail review
- Codespaces deployment hardening: safe defaults, HTTPS disabled, auto-reset, port visibility automation
- Comprehensive 13-port smoke test validating French content and end-to-end student journey

### What Worked
- **Upfront key strategy:** Adding all ~136 translation keys in Phase 1 meant Phases 2-5 only wired templates — zero key-addition work later
- **Additive-only approach:** No existing functionality broken; all changes layered on top
- **Phase dependency chain:** Linear 1→2→3→4→5 meant no merge conflicts or integration surprises
- **Single-day execution:** All 8 plans completed in ~30 minutes total execution time across 5 phases
- **Atomic commits:** Each task committed separately with clear feat() prefixes — clean git history

### What Was Inefficient
- **ROADMAP.md checkbox drift:** Phase 2-5 checkboxes were never marked complete in ROADMAP.md during execution (only Phase 1 was checked), requiring manual fixup — executor should update roadmap after each phase
- **Summary one-liner extraction:** gsd-tools `summary-extract --fields one_liner` returned None for all summaries — manual extraction needed

### Patterns Established
- `localize(finding, lang)` pattern for overlaying French translations onto seed data objects
- `DIFFICULTY_MAP` as route-level constant for finding-to-difficulty lookup
- EJS-embedded `MSG_*` constants for translated client-side AJAX feedback
- `localStorage` dismissal pattern for one-time pedagogical banners
- Status-code-based error translation maps in EJS templates
- `postAttachCommand` lifecycle hook for Codespaces port visibility automation

### Key Lessons
1. **Front-load translation keys:** Adding all i18n keys in a single phase dramatically simplifies template wiring in subsequent phases
2. **Additive-only is safer under time pressure:** Never modifying existing logic, only adding French translations on top, eliminated regression risk
3. **Smoke test as final gate:** A single `npm test` command that validates all 13 ports + French content + authenticated journey gives high confidence before class

### Cost Observations
- Model mix: 100% opus (quality profile)
- Execution time: ~30 minutes total for 8 plans (avg 3-4 min/plan)
- Notable: Fastest milestone execution — simple, well-scoped translation work with clear patterns

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.0 | 5 | 8 | First milestone — established translation and deployment patterns |

### Top Lessons (Verified Across Milestones)

1. Front-load infrastructure (keys, helpers) so later phases focus on wiring
2. Additive-only changes under time pressure — never break what works
