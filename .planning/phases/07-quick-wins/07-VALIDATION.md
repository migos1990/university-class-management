---
phase: 7
slug: quick-wins
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-19
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Custom smoke test (scripts/smoke-test.js) |
| **Config file** | scripts/smoke-test.js |
| **Quick run command** | `npm test` |
| **Full suite command** | `npm test` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm test`
- **After every plan wave:** Run `npm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 7-01-01 | 01 | 1 | QWIN-01 | manual | Visual check: load any page, verify status bar badges are French | N/A | ⬜ pending |
| 7-01-02 | 01 | 1 | QWIN-02 | manual | Log in as student, submit all 12 findings, verify banner appears | N/A | ⬜ pending |
| 7-01-03 | 01 | 1 | QWIN-03 | manual | Navigate to /sca/findings/1, verify prev/next arrows work | N/A | ⬜ pending |
| 7-01-04 | 01 | 1 | QWIN-04 | smoke | `curl -s http://localhost:3000/api/summary` should return redirect/401 | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers most phase requirements. Only QWIN-04 benefits from a smoke-level verification:

- [ ] Verify `curl -s http://localhost:3000/api/summary` returns 302/401 after auth middleware applied
- [ ] Verify `curl -s http://localhost:3000/api/instructor-message` returns 302/401 for unauthenticated requests

*QWIN-01 through QWIN-03 are visual/UI behaviors — automated verification requires a browser testing framework which is out of scope for Phase 7. Phase 8 (TEST-03) will add integration tests.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Security badges render in French | QWIN-01 | Visual text rendering in EJS templates | Load any page while logged in, inspect security status bar — all badges should show French text (ACTIVE/DESACTIVE, Chiffré/Clair, etc.) |
| Celebration banner on completion | QWIN-02 | Requires 12 finding submissions | Log in as student, submit all 12 SCA findings, verify "Bravo !" banner appears on student-lab page |
| Prev/next arrows on finding detail | QWIN-03 | Navigation flow between pages | Navigate to /sca/findings/1, verify prev/next arrows are present and link to correct findings in difficulty order |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
