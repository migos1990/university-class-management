---
phase: 15
slug: css-extraction
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-21
---

# Phase 15 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | node:test (built-in Node.js native) |
| **Config file** | none — tests run via `node --test test/*.test.js` |
| **Quick run command** | `npm test` |
| **Full suite command** | `npm run test:integration` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm test`
- **After every plan wave:** Run `npm run test:integration`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 15-01-01 | 01 | 1 | CSS-01 | smoke | `npm test` | Yes | pending |
| 15-01-02 | 01 | 1 | CSS-01 | smoke | `npm test` | Yes | pending |
| 15-01-03 | 01 | 1 | CSS-01 | smoke | `npm test` | Yes | pending |
| 15-01-04 | 01 | 1 | CSS-01 | manual | Visual parity check | N/A | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test files needed — CSS extraction is a visual refactor verified by existing smoke tests (server boot + page rendering) and visual inspection.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Visual parity after CSS extraction | CSS-01 | CSS refactoring is verified by visual comparison; automated CSS testing would be over-engineering | 1. Start server 2. Visit SCA student-lab page 3. Verify severity badges render correctly 4. Spot-check DAST and VM pages |
| No leftover empty style blocks | CSS-01 | Grep verification sufficient | Run `grep -r '<style>' views/` and verify only expected blocks remain (standalone pages + Prism conditional) |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
