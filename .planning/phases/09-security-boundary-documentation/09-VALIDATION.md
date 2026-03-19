---
phase: 9
slug: security-boundary-documentation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-19
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | node:test (built-in) |
| **Config file** | none |
| **Quick run command** | `node --test test/sca-review.test.js` |
| **Full suite command** | `node --test test/*.test.js` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `node --test test/sca-review.test.js`
- **After every plan wave:** Run `node --test test/*.test.js`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 09-01-01 | 01 | 1 | SDOC-01 | smoke | `node -e "const fs=require('fs'); const c=fs.readFileSync('SECURITY-BOUNDARY.md','utf8'); [1,2,3,4,5,6,7,8,9,10,11,12].forEach(i=>{if(!c.includes('#'+i))throw new Error('Missing finding '+i)}); if(!c.includes('Real'))throw new Error('Missing real findings'); console.log('PASS')"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Existing test suite (`test/*.test.js`) should pass unchanged since no code is modified
- [ ] No new test file needed — this is a documentation phase; verification is content review + automated existence check

*Existing infrastructure covers all phase requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| All 12 findings have correct CWE, severity, difficulty, and file:line | SDOC-01 | Content accuracy requires human review against seedData.js | Cross-reference each entry's fields against `utils/seedData.js` lines 195-394 |
| Learning objectives are meaningful | SDOC-01 | Editorial quality judgment | Read each learning objective and verify it connects CWE to a teachable concept |
| README.md links to SECURITY-BOUNDARY.md | SDOC-01 | Trivial to check | Open README.md, search for "SECURITY-BOUNDARY" |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 5s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
