---
phase: 18
slug: security-environment-hardening-session-secret-csrf-protection-npm-cves-helmet-headers-env-setup-health-check-endpoint
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-22
---

# Phase 18 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Node.js built-in test runner (node:test + node:assert) |
| **Config file** | None (uses node --test) |
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
| 18-01-01 | 01 | 1 | SEC-M01 | smoke | `test -f .env.example && grep PORT .env.example` | N/A | pending |
| 18-01-02 | 01 | 1 | DEP-C01 | smoke | `grep -q '.env' .gitignore` | N/A | pending |
| 18-01-03 | 01 | 1 | SEC-H01 | smoke | `npm audit --audit-level=high` | N/A | pending |
| 18-01-04 | 01 | 1 | VULN-PRESERVE | integration | `npm run test:integration` | Existing | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Requirements

*Existing infrastructure covers all phase requirements.* Smoke tests and integration tests already exist. No new test files needed for Wave 0 -- verification uses CLI checks and existing test suite.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SCA findings 1,7,8,9,11 code snippets still match source | VULN-PRESERVE | Code snippet content depends on source line numbers | Visually verify finding detail pages show correct code after bcrypt upgrade |

---

## Validation Sign-Off

- [ ] All tasks have automated verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
