---
phase: 11
slug: instructor-tools
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-19
---

# Phase 11 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | node:test (built-in, Node 20+) |
| **Config file** | none — uses --test flag |
| **Quick run command** | `node --test test/instructor-tools.test.js` |
| **Full suite command** | `npm run test:integration` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `node --test test/instructor-tools.test.js`
- **After every plan wave:** Run `npm run test:integration`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 11-01-01 | 01 | 0 | INST-01, INST-02 | integration | `node --test test/instructor-tools.test.js` | ❌ W0 | ⬜ pending |
| 11-01-02 | 01 | 1 | INST-01 | integration | `node --test test/instructor-tools.test.js` | ❌ W0 | ⬜ pending |
| 11-01-03 | 01 | 1 | INST-01, INST-02 | integration | `node --test test/instructor-tools.test.js` | ❌ W0 | ⬜ pending |
| 11-01-04 | 01 | 1 | INST-01, INST-02 | integration | `node --test test/instructor-tools.test.js` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `test/instructor-tools.test.js` — integration tests for INST-01, INST-02 (stats endpoint returns students array with activity tracking and per-student completion)
- Existing `test/helpers.js` with `loginAs`, `request`, `BASE_URL` covers shared fixtures
- Framework (node:test) already available — no install needed

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Student progress table renders with correct layout and badges | INST-01, INST-02 | Visual rendering in EJS template with inline styles | 1. Login as instructor 2. Navigate to /sca 3. Verify table shows between stats cards and findings overview 4. Check badge colors match spec (green/amber/gray) |
| Time-ago displays in French | INST-01 | Client-side JS rendering from ISO timestamps | 1. Login as student, visit /sca/findings/:id 2. Login as instructor, check "Dernière act." column shows "il y a X min" |
| 30s polling updates table without page reload | INST-01, INST-02 | Real-time polling behavior | 1. Open instructor view 2. In another tab, login as student and navigate SCA 3. Wait 30s, verify instructor table updates |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
