---
phase: 7
slug: instructor-answer-key
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
| **Framework** | Custom smoke test (`scripts/smoke-test.js`) |
| **Config file** | `scripts/smoke-test.js` |
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
| 7-01-01 | 01 | 1 | AKEY-01 | smoke | `npm test` (answer-key page check) | ❌ W0 | ⬜ pending |
| 7-01-02 | 01 | 1 | AKEY-02 | manual | Visual verification | N/A | ⬜ pending |
| 7-01-03 | 01 | 1 | AKEY-03 | manual | Visual verification | N/A | ⬜ pending |
| 7-01-04 | 01 | 1 | AKEY-04 | smoke | `npm test` (role-gate denial check) | ❌ W0 | ⬜ pending |
| 7-02-01 | 02 | 1 | AKEY-05 | manual | Inspect page source as student | N/A | ⬜ pending |
| 7-02-02 | 02 | 1 | AKEY-06 | manual | Visual verification | N/A | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Add answer key page accessibility check to `scripts/smoke-test.js` — covers AKEY-01
- [ ] Add role-gate denial check (student accessing `/sca/answer-key` gets redirect/403) — covers AKEY-04

*These checks extend the existing smoke test file.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Reasoning text visible on answer key page | AKEY-02 | Content quality check — requires French text verification | Navigate to `/sca/answer-key` as instructor, verify each finding has reasoning text in Quebec French |
| Discussion prompts visible | AKEY-03 | Content quality check | Navigate to `/sca/answer-key` as instructor, verify each finding has a discussion prompt |
| Inline answer absent from student page source | AKEY-05 | Must verify HTML source, not just visibility | Log in as student, view `/sca/findings/1`, View Source, confirm no answer key HTML emitted |
| All text in Quebec French | AKEY-06 | Language/content quality check | Browse answer key page and inline answers, verify all text is French |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
