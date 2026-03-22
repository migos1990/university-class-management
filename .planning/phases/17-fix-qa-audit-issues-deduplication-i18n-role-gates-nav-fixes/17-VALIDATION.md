---
phase: 17
slug: fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-22
---

# Phase 17 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Node.js built-in test runner (node:test) |
| **Config file** | none — uses `node --test test/*.test.js` |
| **Quick run command** | `node --test test/qa-fixes.test.js` |
| **Full suite command** | `node --test test/*.test.js` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `node --test test/qa-fixes.test.js`
- **After every plan wave:** Run `node --test test/*.test.js`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 17-01-01 | 01 | 1 | ISSUE-001 | integration | `node --test test/qa-fixes.test.js` | ❌ W0 | ⬜ pending |
| 17-02-01 | 02 | 1 | ISSUE-002 | integration | `node --test test/qa-fixes.test.js` | ❌ W0 | ⬜ pending |
| 17-03-01 | 03 | 2 | ISSUE-003 | integration | `node --test test/qa-fixes.test.js` | ❌ W0 | ⬜ pending |
| 17-03-02 | 03 | 2 | ISSUE-004 | integration | `node --test test/qa-fixes.test.js` | ❌ W0 | ⬜ pending |
| 17-03-03 | 03 | 2 | ISSUE-005 | integration | `node --test test/qa-fixes.test.js` | ❌ W0 | ⬜ pending |
| 17-03-04 | 03 | 2 | ISSUE-006 | manual-only | Visual inspection | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `test/qa-fixes.test.js` — integration tests for ISSUE-001 through ISSUE-005
- [ ] Delete `database/data.json` before test runs to ensure clean seed

*Existing test infrastructure (node:test) covers framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| "Mes inscriptions" href changed | ISSUE-006 | DOM inspection needed | Check sidebar HTML for updated href on /dashboard/student |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
