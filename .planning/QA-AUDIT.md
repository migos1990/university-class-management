# QA Audit Report -- HEC Montreal Application Security Platform

**Date:** 2026-03-22
**Tester:** Automated QA (Claude Code)
**Target:** http://localhost:3000
**Duration:** ~15 minutes
**Pages visited:** 14
**Screenshots captured:** 16
**Framework:** Node.js/Express + EJS templates + SQLite

---

## Health Score: 52/100

| Category      | Weight | Score | Deductions                                          |
|---------------|--------|-------|------------------------------------------------------|
| Console       | 15%    | 100   | 0 JS errors across all pages                        |
| Links         | 10%    | 85    | /classes returns 404 from Cours nav link             |
| Visual        | 10%    | 75    | 5x duplication bug across SCA/DAST/VM pages          |
| Functional    | 20%    | 65    | Duplication is functional blocker; role gate bypass   |
| UX            | 15%    | 70    | Locked challenge returns raw JSON 403                |
| Performance   | 10%    | 70    | Pages render 5x more DOM than needed                 |
| Content       | 5%     | 20    | Extensive untranslated English strings               |
| Accessibility | 15%    | 80    | Forms properly labeled; semantic nav present          |

**Weighted score:** (15x100 + 10x85 + 10x75 + 20x65 + 15x70 + 10x70 + 5x20 + 15x80) / 100 = **73.0** adjusted to **52** for severity of critical duplication bug affecting 3 core lab pages.

---

## Top 3 Things to Fix

1. **CRITICAL -- 5x Finding Duplication on SCA, DAST, and VM Pages** (ISSUE-001)
2. **HIGH -- Extensive Untranslated English Strings Across Multiple Pages** (ISSUE-002)
3. **MEDIUM -- Instructor Can Access Student Dashboard** (ISSUE-003)

---

## Issues

### ISSUE-001: 5x Finding Duplication on SCA, DAST, VM, and SCA Instructor Pages

**Severity:** CRITICAL
**Category:** Functional / Visual
**Pages affected:** /sca, /dast, /vm, /sca (instructor view)

**Description:**
Every page that lists findings renders the complete list 5 times. On the SCA student page, 12 unique findings appear as 60 DOM elements. All 5 copies are `display: block` (visible). The duplicated elements have identical IDs (e.g., five `#finding-1` elements), which also breaks HTML validity.

**Evidence:**
- SCA page: 60 `.finding-card` elements, 12 unique titles
- DAST page: same pattern with 5x duplicated findings
- VM page: each vulnerability name repeated 5 times (e.g., 5x "Plaintext Password Comparison")
- SCA instructor dashboard: 5x duplicated findings table

**Repro steps:**
1. Login as alice_student / student123
2. Navigate to /sca
3. Count finding cards -- expect 12, see 60
4. Same for /dast and /vm

**Screenshots:**
- `.gstack/qa-reports/screenshots/sca-findings-list.png`
- `.gstack/qa-reports/screenshots/dast-page.png`
- `.gstack/qa-reports/screenshots/vm-page.png`
- `.gstack/qa-reports/screenshots/sca-instructor-dashboard.png`

**Impact:** Students see each finding 5 times, making the lab confusing and unusable for its educational purpose. Also causes unnecessary DOM bloat.

---

### ISSUE-002: Extensive Untranslated English Strings

**Severity:** HIGH
**Category:** Content (i18n)
**Pages affected:** Student dashboard, Instructor dashboard, Admin dashboard, VM page

**Description:**
While the sidebar navigation, login page, SCA finding details, and CTF lab are properly translated to Quebec French, several pages contain significant English text that was never localized.

**Untranslated strings found:**

| Page | English Strings |
|------|----------------|
| Student dashboard (/dashboard/student) | "My Classes", "View your enrolled classes and grades", "Enrolled Classes", "View Details" (x15), "About This Platform", full English paragraph |
| Instructor dashboard (/dashboard/professor) | "My Classes", "Manage your classes and student enrollments", "All Classes", "View Details" (x3) |
| Admin dashboard (/dashboard/admin) | "Admin Dashboard", "System overview and quick actions", "Total Users", "Professors", "Classes", "Quick Actions", "Security Settings", "View Audit Logs", "Configure MFA", "Database Backups", "Recent Logins", "USER", "ROLE", "LAST LOGIN" |
| VM page (/vm) | "Vulnerability Manager -- Registry", "Search...", "All severities", "All statuses", all vulnerability titles (e.g., "Plaintext Password Comparison"), column headers |

**Screenshots:**
- `.gstack/qa-reports/screenshots/student-dashboard.png`
- `.gstack/qa-reports/screenshots/instructor-dashboard.png`
- `.gstack/qa-reports/screenshots/admin-dashboard.png`
- `.gstack/qa-reports/screenshots/vm-page.png`

**Impact:** The platform is intended for Quebec French-speaking students. Mixing English content throughout breaks the educational immersion and is inconsistent with the localized lab pages.

---

### ISSUE-003: Instructor Can Access Student Dashboard

**Severity:** MEDIUM
**Category:** Functional (Authorization)

**Description:**
When logged in as an instructor (prof_jones), navigating directly to `/dashboard/student` returns HTTP 200 and renders the full student dashboard view with enrollment data, rather than blocking access or redirecting.

**Repro steps:**
1. Login as prof_jones / prof123
2. Navigate to http://localhost:3000/dashboard/student
3. Observe: full student dashboard renders (HTTP 200)

**Screenshot:** `.gstack/qa-reports/screenshots/role-gate-test.png`

**Impact:** While not a direct security vulnerability (the data shown belongs to the professor's own enrollment records), it is an authorization inconsistency. An instructor should see the instructor dashboard or be redirected, not the student view.

---

### ISSUE-004: "Cours" Nav Link Returns 404

**Severity:** MEDIUM
**Category:** Functional (Navigation)

**Description:**
The sidebar "Cours" link navigates to `/classes`, which returns a 404 error page. The 404 page itself is properly translated ("Page introuvable").

**Repro steps:**
1. Login as any user
2. Click "Cours" in sidebar
3. See 404 error

**Impact:** A primary navigation item leads to a dead page.

---

### ISSUE-005: Locked CTF Challenge Returns Raw JSON Error

**Severity:** LOW
**Category:** UX

**Description:**
When a student tries to access a locked CTF challenge directly (e.g., `/pentest/challenges/5`), the server returns HTTP 403 with a raw JSON response: `{"error":"Challenge verrouille"}` instead of rendering a user-friendly error page.

**Repro steps:**
1. Login as alice_student / student123
2. Navigate to http://localhost:3000/pentest/challenges/5
3. See raw JSON instead of styled error page

**Impact:** Minor -- students would typically navigate through the board, but direct URL access produces a poor experience compared to the polished 403 page shown for other role-gated routes (e.g., /sca/answer-key has a beautiful styled 403).

---

### ISSUE-006: "Mes inscriptions" Link Loops to Same Page

**Severity:** LOW
**Category:** UX (Navigation)

**Description:**
The "Mes inscriptions" sidebar link for students navigates to `/dashboard/student` -- the exact same page the user is already on. It does not provide a distinct enrollments view.

**Repro steps:**
1. Login as alice_student
2. Click "Mes inscriptions" in sidebar
3. Page reloads to /dashboard/student (no change)

**Impact:** Misleading navigation -- suggests a separate enrollments page exists.

---

## What Works Well

| Feature | Status | Notes |
|---------|--------|-------|
| Login / Logout | PASS | French UI, proper error messages, session management |
| Invalid login error | PASS | "Echec de connexion" -- properly translated |
| Unauthenticated access protection | PASS | 302 redirect to login for all protected routes |
| SCA finding detail page | PASS | Excellent: code snippet, classification, hints, prev/next nav |
| SCA classification submission | PASS | Save draft & submit work correctly, timestamps update |
| SCA hint system | PASS | "Pistes d'analyse" revealed in French with guiding questions |
| CTF challenge board | PASS | Progress bar, scoring, rank display, all in French |
| CTF progressive unlock | PASS | "Verrouille -- 2 defis faciles" correctly gates medium/advanced |
| CTF flag submission | PASS | Wrong flag: "Flag incorrect. Pas de penalite. Reessayez." |
| CTF sticky reminder bar | PASS | Fixed position "Defi en cours" bar with continue/dismiss |
| CTF instructor dashboard | PASS | Leaderboard + heatmap fully functional and in French |
| CTF student reset | PASS | "Reinitialiser" buttons present for each student |
| Answer key role-gating | PASS | Students get styled 403 "Acces refuse" in French |
| API auth (/api/instructor-message) | PASS | 302 redirect when unauthenticated |
| API auth (/api/summary) | PASS | 302 redirect when unauthenticated |
| Sidebar navigation (all roles) | PASS | Fully translated, role-appropriate sections |
| Security status bar | PASS | French labels: AMF, RBAC, Mots de passe, etc. |
| Console errors | PASS | Zero JS errors across all tested pages |

---

## Console Health Summary

**JS Errors:** 0 across 14 pages tested
**Network Errors:** None observed
**Deprecation Warnings:** None observed

---

## Test Coverage Summary

| Flow | Tested | Result |
|------|--------|--------|
| Student login | Yes | PASS |
| Instructor login | Yes | PASS |
| Admin login | Yes | PASS |
| Invalid login | Yes | PASS |
| Unauthenticated access | Yes | PASS (redirects to login) |
| Role-gate bypass (instructor to student) | Yes | FAIL (ISSUE-003) |
| SCA finding list | Yes | FAIL (5x duplication -- ISSUE-001) |
| SCA finding detail | Yes | PASS |
| SCA classification submit | Yes | PASS |
| SCA hints | Yes | PASS |
| SCA prev/next nav | Yes | PASS |
| CTF challenge board | Yes | PASS |
| CTF challenge detail | Yes | PASS |
| CTF flag submission (wrong) | Yes | PASS |
| CTF hint system | Yes | PASS (two-click confirm UX) |
| CTF progressive unlock | Yes | PASS |
| CTF locked challenge direct access | Yes | FAIL (raw JSON -- ISSUE-005) |
| CTF sticky reminder bar | Yes | PASS |
| CTF instructor leaderboard | Yes | PASS |
| CTF instructor heatmap | Yes | PASS |
| SCA instructor dashboard | Yes | FAIL (5x duplication -- ISSUE-001) |
| SCA answer key (instructor) | Yes | PASS |
| SCA answer key (student blocked) | Yes | PASS |
| DAST finding list | Yes | FAIL (5x duplication -- ISSUE-001) |
| VM page | Yes | FAIL (5x duplication + untranslated -- ISSUE-001, ISSUE-002) |
| French translations | Yes | FAIL (ISSUE-002) |
| API /api/instructor-message auth | Yes | PASS |
| API /api/summary auth | Yes | PASS |
| Cours nav link | Yes | FAIL (404 -- ISSUE-004) |

---

## Severity Summary

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 1     |
| Medium   | 2     |
| Low      | 2     |
| **Total**| **6** |

---

## Notes

- No test framework detected in the project (no test config, no test directories with unit tests). The existing `scripts/smoke-test.js` is a basic HTTP-level smoke test only. Run `/qa` to bootstrap a proper test framework and enable regression test generation.
- The 5x duplication bug is systemic -- it affects SCA (student), SCA (instructor), DAST, and VM pages. The root cause is likely in a shared EJS template or layout partial that iterates the findings multiple times.
- The CTF lab (Phase 16) is the most polished section -- fully translated, well-designed UX, proper error handling.
- The SCA finding detail pages are also excellent -- good code snippets, classification workflow, hint system.
- The dashboard pages (student, instructor, admin) and VM page are the weakest in terms of localization.
