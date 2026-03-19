---
phase: 8
slug: testing
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-19
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | node:test (built-in, Node.js v20.20.0) |
| **Config file** | None needed — uses CLI flags |
| **Quick run command** | `node --test test/*.test.js` |
| **Full suite command** | `npm run test:integration` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `node --test test/*.test.js`
- **After every plan wave:** Run `npm run test:integration`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 08-01-01 | 01 | 1 | TEST-01 | integration | `node --test --test-name-pattern="SCA Review" test/sca-review.test.js` | ❌ W0 | ⬜ pending |
| 08-01-02 | 01 | 1 | TEST-02 | integration | `node --test --test-name-pattern="Answer Key" test/answer-key-gating.test.js` | ❌ W0 | ⬜ pending |
| 08-01-03 | 01 | 1 | TEST-03 | integration | `node --test --test-name-pattern="API.*Auth" test/api-auth.test.js` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `test/helpers.js` — shared HTTP helpers (request, getSessionCookie, loginAs)
- [ ] `test/sca-review.test.js` — stubs for TEST-01
- [ ] `test/answer-key-gating.test.js` — stubs for TEST-02
- [ ] `test/api-auth.test.js` — stubs for TEST-03
- [ ] `routes/sca.js` modification — add GET /sca/answer-key stub route
- [ ] `package.json` modification — add test:integration script
- [ ] No framework install needed (node:test is built-in)

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
