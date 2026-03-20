---
phase: 11-instructor-tools
verified: 2026-03-19T00:00:00Z
status: passed
score: 6/6 must-haves verified
re_verification: false
---

# Phase 11: Instructor Tools Verification Report

**Phase Goal:** Instructor can see at a glance which students are active, what they're working on, and their overall progress — enabling timely intervention during class
**Verified:** 2026-03-19
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Instructor dashboard shows each student's last activity timestamp as relative time-ago in French | VERIFIED | `timeAgo()` in instructor.ejs (line 201–208) outputs "il y a X s/min/h/j"; `renderStudentTable()` (line 252) passes ISO string to timeAgo and renders in `<td>` |
| 2 | Instructor dashboard shows which finding each student is currently analyzing | VERIFIED | `currentFindingTitle` field returned by `/sca/stats` (routes/sca.js line 172–174); rendered as 4th column in renderStudentTable (line 253) |
| 3 | Instructor dashboard shows per-student SCA submission progress as X/12 with progress bar | VERIFIED | `submitted` count in studentsData (routes/sca.js line 162–164); progress bar rendered with `.progress-bar-fill` width (instructor.ejs line 249–250) |
| 4 | Student progress table updates every 30 seconds via the same polling call as stats cards | VERIFIED | `refreshStats()` calls `renderStudentTable(data.students, data.totalFindings)` (instructor.ejs line 271); `setInterval(refreshStats, 30000)` (line 277); no extra fetch added |
| 5 | Activity is tracked when a student views the SCA lab page, views a finding detail, or submits a review | VERIFIED | `trackActivity(user.id)` called on GET /sca/ (routes/sca.js line 70, inside student role guard); `trackActivity(user.id, finding.id)` on GET /sca/findings/:id (line 194, inside student role guard); `trackActivity(studentId)` on POST /sca/findings/:id/review (line 239) |
| 6 | Students with no SCA activity show "Pas commence" badge and dash instead of time-ago | VERIFIED | Three-state badge logic in renderStudentTable: when `s.submitted === 0 && !s.lastActiveAt`, statusClass = 'status-notstarted', statusLabel = 'Pas commencé' (instructor.ejs lines 235–237); dash rendered via `(ago \|\| '\u2014')` (line 252) |

**Score:** 6/6 truths verified

---

### Required Artifacts

| Artifact | Provided | Status | Details |
|----------|----------|--------|---------|
| `routes/sca.js` | `activityTracker` object, `trackActivity()`, extended `/sca/stats` with `students` array | VERIFIED | `activityTracker = {}` at line 10; `function trackActivity(...)` at line 12; `studentsData` built and returned in `/sca/stats` (lines 161–181); 306 lines, substantive |
| `views/sca/instructor.ejs` | Student progress table, `renderStudentTable()`, `timeAgo()` | VERIFIED | Table HTML with `student-progress-tbody` at lines 48–70; `timeAgo()` at lines 201–208; `renderStudentTable()` at lines 211–257; 281 lines, substantive |
| `config/translations/fr.json` | French i18n keys under `sca.instructor.progress.*` | VERIFIED | 12 keys present: heading, activeCount, colStudent, colProgress, colLastActive, colCurrentFinding, colStatus, submitted, statusActive, statusInactive, statusNotStarted, noStudents |
| `config/translations/en.json` | English i18n keys under `sca.instructor.progress.*` | VERIFIED | Same 12 keys present in English |
| `test/instructor-tools.test.js` | 6 integration tests tagged INST-01/INST-02 | VERIFIED | 143 lines; covers stats response (INST-01), activity tracking on finding view (INST-01), lab page activity (INST-01), per-student submitted count (INST-02), sort order (INST-02), unauthenticated regression |

**All 5 artifacts: exist, substantive, wired.**

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `routes/sca.js` GET /sca/ | `activityTracker` | `trackActivity(user.id)` for student role | WIRED | Line 70, inside `if (user.role === 'student')` block |
| `routes/sca.js` GET /sca/findings/:id | `activityTracker` | `trackActivity(user.id, finding.id)` for student role | WIRED | Line 194, inside `if (user.role === 'student')` block |
| `routes/sca.js` POST /sca/findings/:id/review | `activityTracker` | `trackActivity(studentId)` call | WIRED | Line 239, immediately after studentId assignment |
| `routes/sca.js` GET /sca/stats | `activityTracker` | `activityTracker[s.id] \|\| {}` to build students array | WIRED | Line 165 in map over allStudents |
| `views/sca/instructor.ejs` `refreshStats()` | `/sca/stats` | `renderStudentTable(data.students, data.totalFindings)` | WIRED | Line 271 inside refreshStats; setInterval at line 277 fires every 30s |

**All 5 key links: WIRED.**

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| INST-01 | 11-01-PLAN.md | Instructor dashboard shows each student's last_active_at and current finding being analyzed | SATISFIED | `lastActiveAt` and `currentFindingId`/`currentFindingTitle` in `/sca/stats` students array; rendered in progress table with timeAgo and finding title columns |
| INST-02 | 11-01-PLAN.md | Instructor dashboard includes a progress summary card showing per-student completion | SATISFIED | Per-student `submitted` count + progress bar in student progress table card; sorted by completion descending |

**No orphaned requirements.** REQUIREMENTS.md maps both INST-01 and INST-02 to Phase 11 (lines 139–140) and both are marked Complete. Both are claimed in 11-01-PLAN.md frontmatter and verified in the codebase.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `routes/sca.js` | 301–303 | `placeholder: true` — answer-key stub | Info | Pre-existing stub from before Phase 11 (not introduced in commits 61f7384 or 3404f3e); scoped to Phase 12; no impact on Phase 11 goal |

No blockers or warnings. The one info-level item predates this phase.

---

### Human Verification Required

#### 1. Live polling in browser

**Test:** Log in as instructor, navigate to `/sca`, open browser DevTools Network tab. Wait 30 seconds.
**Expected:** A GET request to `/sca/stats` fires every 30 seconds and the student progress table rows update.
**Why human:** Cannot verify real-time DOM updates or timing behavior programmatically without a running browser.

#### 2. Three-state badge rendering

**Test:** Log in as a student who has never visited SCA. Open instructor dashboard. Observe that student's row shows "Pas commence" badge (gray) and dashes for time and finding columns.
**Expected:** Gray badge with label "Pas commencé", em-dash characters in last-active and current-finding columns.
**Why human:** Status badge logic depends on runtime state (zero submissions + no tracker entry) that varies by test data.

#### 3. French time-ago display

**Test:** Log in as a student, visit any SCA finding, then check instructor dashboard within 60 seconds.
**Expected:** Student's "Derniere act." column shows "il y a X s" (seconds) or "il y a X min" (minutes), not a raw ISO timestamp.
**Why human:** Requires a running browser with timing; cannot validate rendered DOM text programmatically.

---

### Commits Verified

| Commit | Status | Contents |
|--------|--------|----------|
| `61f7384` | EXISTS | routes/sca.js (+78 lines), config/translations/fr.json (+16), config/translations/en.json (+16), test/instructor-tools.test.js (+143); dated 2026-03-19 |
| `3404f3e` | EXISTS | views/sca/instructor.ejs (+87 lines); dated 2026-03-19 |

Both commits are present in `git log`. Both predate the HEAD docs commit (`5bd8929`).

---

## Summary

Phase 11 goal is **fully achieved**. All six observable truths are satisfied by substantive, wired implementations:

- The in-memory `activityTracker` object captures student activity at all three trigger points (lab page, finding detail, review submission), with correct student-role guards.
- The `/sca/stats` endpoint builds a complete `students` array from live tracker state and DB-aggregated submission counts, sorted by completion descending — all in JS to avoid DB adapter limitations.
- The instructor dashboard renders a 5-column progress table between stats cards and the Findings Overview, updated every 30 seconds through the existing polling mechanism with no additional fetch calls.
- Both `fr.json` and `en.json` have all 12 `sca.instructor.progress.*` keys.
- 6 integration tests cover INST-01 and INST-02 scenarios including the regression check.
- INST-01 and INST-02 are both satisfied. No orphaned requirements.

The only flag is a pre-existing `answer-key` stub in `routes/sca.js` (Phase 12 scope) — not introduced by Phase 11 and not blocking the goal.

---

_Verified: 2026-03-19_
_Verifier: Claude (gsd-verifier)_
