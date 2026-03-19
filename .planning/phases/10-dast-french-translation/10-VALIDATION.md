---
phase: 10
slug: dast-french-translation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-19
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | node:test (built-in) |
| **Config file** | none (uses node --test glob) |
| **Quick run command** | `node --test test/*.test.js` |
| **Full suite command** | `node --test test/*.test.js` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `node --test test/*.test.js`
- **After every plan wave:** Run `node --test test/*.test.js` + manual visual check of /dast views
- **Before `/gsd:verify-work`:** Full suite must be green + visual confirmation all 3 DAST views render in French
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 1 | DAST-01 | manual-only | Visual: /dast and /dast/scenarios/{1-6} in French | N/A | ⬜ pending |
| 10-01-02 | 01 | 1 | DAST-02 | manual-only | Visual: all 3 DAST views display in French | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. Translation content is validated manually.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 6 DAST scenarios display in French | DAST-01 | Translation content correctness requires human review | Login, navigate /dast and /dast/scenarios/{1-6}, verify French text |
| All DAST views display in French | DAST-02 | UI text correctness requires human review | Login, check student-lab, scenario-detail, instructor views for French |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: regression tests run on every commit
- [x] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [x] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
