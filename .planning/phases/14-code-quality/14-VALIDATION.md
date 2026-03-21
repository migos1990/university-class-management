---
phase: 14
slug: code-quality
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-21
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Node.js built-in test runner (node:test) + custom smoke test |
| **Config file** | None (no config file needed for node:test) |
| **Quick run command** | `npm test` |
| **Full suite command** | `npm run lint && npm run format:check && npm test && npm run test:integration` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `npm run lint && npm run format:check && npm test`
- **After every plan wave:** Run `npm run lint && npm run format:check && npm test && npm run test:integration`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 01 | 1 | QUAL-01 | smoke | `npm run lint && npm run format:check` | N/A — scripts ARE the test | ⬜ pending |
| 14-01-02 | 01 | 1 | QUAL-02 | smoke | `npm run lint && npm run format:check` | N/A — clean output IS the test | ⬜ pending |
| 14-02-01 | 02 | 1 | QUAL-03 | smoke | `npm run lint` (no-unused-vars rule) | N/A — lint clean IS the test | ⬜ pending |
| 14-02-02 | 02 | 1 | QUAL-04 | integration | `npm test` | Yes — scripts/smoke-test.js | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. The lint/format scripts are created by the phase implementation itself — no separate Wave 0 setup needed.

- `npm test` (smoke test) already exists and validates QUAL-04
- `npm run test:integration` already exists
- `npm run lint` and `npm run format` will be created as part of QUAL-01 implementation

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| 12 intentional vulnerabilities unchanged | QUAL-04 | Must visually confirm eslint-disable comments target correct lines | Diff vulnerability lines against SECURITY-BOUNDARY.md inventory |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
