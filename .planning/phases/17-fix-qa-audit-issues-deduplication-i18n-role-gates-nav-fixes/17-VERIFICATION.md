---
phase: 17-fix-qa-audit-issues-deduplication-i18n-role-gates-nav-fixes
verified: 2026-03-26T00:00:00Z
status: passed
score: 11/11 must-haves verified
re_verification: false
---

# Phase 17: Fix QA Audit Issues Verification Report

**Phase Goal:** Fix all 6 QA audit issues: 5x finding deduplication in seedData.js (CRITICAL), untranslated English strings on dashboards and VM pages (HIGH), dashboard role gates (MEDIUM), /classes 404 (MEDIUM), locked CTF JSON error (LOW), and "Mes inscriptions" nav loop (LOW)
**Verified:** 2026-03-26
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | SCA/DAST/VM pages show correct finding counts with no duplication | VERIFIED | `utils/seedData.js` lines 9-23: 15 DELETE statements (6 core + 9 curriculum). All 9 curriculum table DELETEs present. Matching bulk DELETE handlers confirmed in `config/database.js` lines 1077-1097. |
| 2 | Student dashboard displays all text in Quebec French | VERIFIED | `views/student/dashboard.ejs`: 13 t() calls confirmed. Zero hardcoded English strings found. All keys resolve in fr.json (dashboard.student.* namespace verified). |
| 3 | Professor dashboard displays all text in Quebec French | VERIFIED | `views/professor/dashboard.ejs`: 11 t() calls confirmed. Zero hardcoded English strings found. All keys in fr.json dashboard.professor.* namespace. |
| 4 | Admin dashboard displays all text in Quebec French | VERIFIED | `views/admin/dashboard.ejs`: 16 t() calls confirmed. Zero hardcoded English strings found. All keys in fr.json dashboard.admin.* namespace. |
| 5 | VM student-lab page displays UI chrome in Quebec French | VERIFIED | `views/vm/student-lab.ejs`: 17 t() calls confirmed. All stat labels, filter labels, table headers use vm.* keys. |
| 6 | VM instructor page displays UI chrome in Quebec French | VERIFIED | `views/vm/instructor.ejs`: 31 t() calls confirmed. Headings, buttons, modal form labels, filter controls, table headers all use vm.* keys. |
| 7 | Instructor accessing /dashboard/student gets 403 (when RBAC enabled) | VERIFIED | `routes/dashboard.js` line 31: `requireRole(['student'])`. Line 71: `requireRole(['professor', 'admin'])`. Line 96: `requireRole(['admin'])`. requireRole imported from `middleware/rbac.js` at line 4. Middleware enforces 403 when RBAC enabled and role mismatch. |
| 8 | Clicking 'Cours' nav link renders a page (not 404) | VERIFIED | `routes/classes.js` lines 12-14: `router.get('/', requireAuth, (req, res) => { res.redirect('/dashboard'); })` placed before /:id handler. |
| 9 | Accessing a locked CTF challenge page renders HTML error (not raw JSON) | VERIFIED | `routes/pentest.js` lines 250-255: GET /challenges/:id locked check uses `res.status(403).render('error', { message: 'Challenge verrouillé', error: { status: 403, details: '...' } })`. No JSON response on this GET route. |
| 10 | "Mes inscriptions" sidebar link points to /classes | VERIFIED | `views/partials/header.ejs` line 114: `<a href="/classes" class="nav-link">` for the student nav.myEnrollments entry. Confirmed distinct from the /dashboard link at line 69. |
| 11 | fr.json and en.json contain all required vm.* and dashboard.* translation keys | VERIFIED | fr.json: vm.* namespace (lines 876-921) and dashboard.* sub-namespaces (lines 123-181) fully populated. en.json: matching vm.* and dashboard.* keys confirmed present. JSON structure is valid. |

**Score:** 11/11 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `utils/seedData.js` | DELETE statements for all curriculum collections | VERIFIED | Lines 9-23: 15 total DELETEs including all 9 curriculum tables (sca_findings, sca_student_reviews, dast_scenarios, dast_student_findings, vulnerabilities, vm_status_history, vm_comments, ctf_challenges, ctf_submissions) |
| `config/translations/fr.json` | New dashboard.student.*, dashboard.professor.*, dashboard.admin.*, vm.* keys | VERIFIED | Contains dashboard.student (lines 165-181), dashboard.professor (lines 147-163), dashboard.admin (lines 124-145), vm.* namespace (lines 876-921) |
| `config/translations/en.json` | Matching English keys for all new fr.json entries | VERIFIED | Confirmed vm.* namespace and dashboard.* sub-namespaces present with English translations |
| `views/student/dashboard.ejs` | All strings use t('dashboard.student.*') calls | VERIFIED | 13 t() calls; zero hardcoded English visible text |
| `views/professor/dashboard.ejs` | All strings use t('dashboard.professor.*') calls | VERIFIED | 11 t() calls; zero hardcoded English visible text |
| `views/admin/dashboard.ejs` | All strings use t('dashboard.admin.*') calls | VERIFIED | 16 t() calls; zero hardcoded English visible text |
| `views/vm/student-lab.ejs` | UI chrome strings use t('vm.*') calls | VERIFIED | 17 t() calls covering heading, subtitle, stat labels, filter controls, table headers |
| `views/vm/instructor.ejs` | UI chrome and modal strings use t('vm.*') calls | VERIFIED | 31 t() calls covering heading, subtitle line, button, stat labels, filter controls, table headers, modal form labels |
| `routes/dashboard.js` | requireRole middleware on student/professor/admin sub-routes | VERIFIED | Lines 31, 71, 96: requireRole(['student']), requireRole(['professor','admin']), requireRole(['admin']) after requireAuth |
| `routes/classes.js` | GET / handler for classes list page | VERIFIED | Lines 12-14: redirect handler present before /:id route |
| `routes/pentest.js` | Rendered error page for locked CTF challenge GET | VERIFIED | Lines 251-254: res.status(403).render('error', ...) with French message |
| `views/partials/header.ejs` | Corrected Mes inscriptions link to /classes | VERIFIED | Line 114: href="/classes" for the student myEnrollments nav link |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `utils/seedData.js` | JSON DB adapter | DELETE-before-INSERT clears all collections | VERIFIED | seedData.js DELETEs trigger bulk-DELETE handlers in config/database.js (lines 1077-1097). All 9 curriculum collections cleared. |
| `routes/dashboard.js` | `middleware/rbac.js` | requireRole import and middleware usage | VERIFIED | Line 4 imports requireRole; lines 31, 71, 96 apply it with correct role arrays |
| `views/partials/header.ejs` | `routes/classes.js` | sidebar nav link to /classes | VERIFIED | href="/classes" at header line 114 resolves to classes.js GET / handler which redirects to /dashboard |
| `routes/pentest.js` | `views/error.ejs` | res.render('error') for locked challenge | VERIFIED | Lines 251-254 render the error template with 403 status and French message for locked GET requests |
| `views/student/dashboard.ejs` | `config/translations/fr.json` | t() function calls | VERIFIED | Pattern `t('dashboard.student.` present 13 times; all keys exist in fr.json |
| `views/admin/dashboard.ejs` | `config/translations/fr.json` | t() function calls | VERIFIED | Pattern `t('dashboard.admin.` present 16 times; all keys exist in fr.json |
| `views/vm/student-lab.ejs` | `config/translations/fr.json` | t() function calls | VERIFIED | Pattern `t('vm.` present 17 times; vm.* namespace fully populated in fr.json |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| ISSUE-001 | 17-01-PLAN.md | SCA/DAST/VM pages show correct finding counts with no duplication (12/6/12) | SATISFIED | 9 curriculum DELETE statements in seedData.js lines 15-23; matching handlers in database.js |
| ISSUE-002 | 17-02-PLAN.md | Student/professor/admin dashboards and VM pages display all text in Quebec French | SATISFIED | 5 EJS templates fully translated; 60+ keys in fr.json and en.json vm.* and dashboard.* namespaces |
| ISSUE-003 | 17-03-PLAN.md | Instructor accessing /dashboard/student gets 403 when RBAC is enabled | SATISFIED | requireRole(['student']) on /dashboard/student; requireRole(['professor','admin']) on /dashboard/professor; requireRole(['admin']) on /dashboard/admin |
| ISSUE-004 | 17-03-PLAN.md | Clicking "Cours" nav link renders a page (not 404) | SATISFIED | GET / handler in classes.js redirects to /dashboard |
| ISSUE-005 | 17-03-PLAN.md | Locked CTF challenge renders HTML error page (not raw JSON) | SATISFIED | GET /challenges/:id locked check uses res.render('error', ...) at pentest.js lines 251-254 |
| ISSUE-006 | 17-03-PLAN.md | "Mes inscriptions" sidebar link points to /classes (not /dashboard) | SATISFIED | header.ejs line 114: href="/classes" for student myEnrollments link |

All 6 ISSUE-* requirements are mapped in REQUIREMENTS.md (lines 173-178) and marked Complete. No orphaned requirements found for Phase 17.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `routes/pentest.js` | 323 | `res.status(403).json({ success: false, error: 'Challenge verrouille' })` | Info | This is the POST /challenges/:id/submit API endpoint (not a page render). The PLAN targeted the GET handler at line 251, which was correctly fixed. This POST endpoint returning JSON is appropriate since flag submission is an AJAX call, not a page navigation. Not a gap. |

No blocker or warning anti-patterns found. The one info-level note confirms scope was correctly bounded.

---

### Human Verification Required

#### 1. Role-gate 403 behavior when RBAC is disabled

**Test:** Log in as instructor, toggle RBAC OFF in the security panel, navigate to /dashboard/student.
**Expected:** Should be accessible (RBAC bypass) — access is allowed when RBAC is disabled, which is intentional for the DAST lab.
**Why human:** Runtime behavior depends on the securitySettings toggle; cannot verify programmatically without running the server.

#### 2. Visual French rendering on dashboards

**Test:** Log in as each role (student, professor, admin) and visually inspect all text on their respective dashboards.
**Expected:** All labels, headings, table headers, button text, and empty-state messages display in Quebec French. No raw translation keys (dot-notation strings) visible.
**Why human:** EJS render with t() fallback behavior (returns key if missing) cannot be confirmed without actually loading the page.

#### 3. VM pages display correct non-duplicated vulnerability counts

**Test:** After a fresh server start, navigate to /vm as student and as instructor.
**Expected:** The Total stat shows 12, matching the seed count; no duplicates across successive restarts.
**Why human:** Requires actually running the server to trigger the seed + verify counts in the UI.

#### 4. "Mes inscriptions" redirect experience

**Test:** Log in as student, click "Mes inscriptions" in the sidebar.
**Expected:** Navigates to dashboard content (via /classes redirect to /dashboard). No 404, no infinite redirect loop.
**Why human:** Browser redirect chain behavior cannot be fully verified by static analysis.

---

### Gaps Summary

No gaps found. All 11 observable truths verified. All 12 artifacts verified as existing, substantive, and wired. All 6 ISSUE-* requirements satisfied with implementation evidence. No blocker anti-patterns. Four items flagged for human verification are behavioral/runtime checks that require a running server but do not indicate missing implementation.

---

_Verified: 2026-03-26_
_Verifier: Claude (gsd-verifier)_
