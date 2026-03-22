# Phase 17: Fix QA Audit Issues — Research

**Researched:** 2026-03-22
**Domain:** EJS templates, Express routing, i18n, JSON database adapter, role-based access control
**Confidence:** HIGH

## Summary

Phase 17 addresses 6 QA audit issues found during automated testing of the HEC Montreal Application Security Platform. The root cause investigation reveals that the most critical bug (5x finding duplication) is a **data layer problem, not a template problem** -- the JSON database file contains 5 copies of every SCA finding, DAST scenario, and vulnerability record because `seedDatabase()` never clears those collections before re-seeding.

The remaining 5 issues are straightforward: untranslated English strings on 4 pages (dashboards + VM), a missing role gate on the student dashboard route, a missing `/classes` list route, a raw JSON error response for locked CTF challenges, and a misleading sidebar link that loops to the same page.

**Primary recommendation:** Fix the seed data deduplication first (it affects 3 pages and the data layer), then address i18n, then routing/role fixes. The seed fix is a one-line addition to `seedData.js` plus deleting and re-seeding the database file; the i18n fix requires adding ~80 new translation keys to `fr.json` and converting 4 EJS templates to use `t()` calls.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ISSUE-001 | CRITICAL: 5x finding duplication on SCA, DAST, VM pages | Root cause found: `seedData.js` missing DELETE statements for sca_findings, dast_scenarios, vulnerabilities, ctf_challenges. Database has 60 SCA records instead of 12, 30 DAST records instead of 6, 60 vulnerability records instead of 12. |
| ISSUE-002 | HIGH: Untranslated English strings on student/instructor/admin dashboards and VM page | Four templates confirmed hardcoded English: `views/student/dashboard.ejs`, `views/professor/dashboard.ejs`, `views/admin/dashboard.ejs`, `views/vm/student-lab.ejs`, `views/vm/instructor.ejs`. No dashboard or VM i18n keys exist in `fr.json`. |
| ISSUE-003 | MEDIUM: Instructor can access student dashboard | Route `GET /dashboard/student` in `routes/dashboard.js` uses only `requireAuth` -- no `requireRole` check. All 3 dashboard routes lack role gates. |
| ISSUE-004 | MEDIUM: "Cours" nav link returns 404 | `routes/classes.js` has no `GET /` handler. Only `GET /:id` exists. Sidebar links to `/classes` via `t('nav.classes')`. |
| ISSUE-005 | LOW: Locked CTF challenge returns raw JSON | `routes/pentest.js` line 251: `res.status(403).json({ error: 'Challenge verrouille' })`. Should render `error.ejs` like other 403s. |
| ISSUE-006 | LOW: "Mes inscriptions" loops to same page | `views/partials/header.ejs` line 114: student "Mes inscriptions" links to `/dashboard` (same as dashboard). Should either link to a distinct view or be removed/changed. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express | existing | Web framework | Already in use |
| EJS | existing | Template engine | Already in use |
| Node.js built-in test | existing | Integration tests | Already used in test/*.test.js |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| utils/i18n.js | custom | Translation function `t()` | All template localization |
| config/translations/fr.json | custom | French translation keys | Adding new dashboard/VM keys |
| middleware/rbac.js | custom | `requireRole()` middleware | Adding role gates to dashboard routes |

**Installation:** No new dependencies needed. All fixes use existing project infrastructure.

## Architecture Patterns

### Recommended Project Structure
```
config/translations/
  fr.json           # Add ~80 new keys for dashboards + VM
  en.json           # Add matching English keys
utils/
  seedData.js       # Add DELETE statements for curriculum collections
routes/
  dashboard.js      # Add requireRole to each sub-route
  classes.js        # Add GET / handler (classes list)
  pentest.js        # Change JSON 403 to rendered error page
views/
  student/dashboard.ejs    # Convert English strings to t() calls
  professor/dashboard.ejs  # Convert English strings to t() calls
  admin/dashboard.ejs      # Convert English strings to t() calls
  vm/student-lab.ejs       # Convert English strings to t() calls
  vm/instructor.ejs        # Convert English strings to t() calls
  partials/header.ejs      # Fix "Mes inscriptions" link
```

### Pattern 1: i18n Key Naming Convention
**What:** The project uses dot-notation namespaced keys
**When to use:** All new translation keys
**Example:**
```javascript
// Existing pattern (from SCA, DAST):
t('sca.studentLab.title')
t('dast.instructor.subtitle', { scenarioCount: scenarios.length })

// New keys should follow same pattern:
t('dashboard.student.title')     // "Mes cours"
t('dashboard.admin.totalUsers')  // "Total utilisateurs"
t('vm.studentLab.title')         // "Gestionnaire de vulnerabilites — Registre"
```

### Pattern 2: Role Gate Middleware
**What:** Use `requireRole()` from `middleware/rbac.js` to restrict route access
**When to use:** Dashboard sub-routes that should be role-specific
**Example:**
```javascript
// Current (no role gate):
router.get('/student', requireAuth, (req, res) => { ... });

// Fixed:
const { requireRole } = require('../middleware/rbac');
router.get('/student', requireAuth, requireRole(['student']), (req, res) => { ... });
router.get('/professor', requireAuth, requireRole(['professor', 'admin']), (req, res) => { ... });
router.get('/admin', requireAuth, requireRole(['admin']), (req, res) => { ... });
```

### Pattern 3: Rendered Error Pages
**What:** Use `res.status(403).render('error', {...})` instead of `res.json()`
**When to use:** User-facing error responses
**Example:**
```javascript
// Current (raw JSON):
return res.status(403).json({ error: 'Challenge verrouille' });

// Fixed (rendered error page matching existing pattern):
return res.status(403).render('error', {
  message: 'Challenge verrouille',
  error: { status: 403, details: t(lang, 'pentest.ctf.challengeLocked') }
});
```

### Anti-Patterns to Avoid
- **Hardcoded English in EJS templates:** Every user-visible string MUST use `t()`. The dashboards and VM are the last holdouts.
- **Missing collection cleanup in seeder:** Every INSERT loop in `seedData.js` must have a corresponding DELETE at the top of the function.
- **Using `requireAuth` without `requireRole` on role-specific routes:** If a page is only for students, enforce it.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation system | Custom i18n library | Existing `utils/i18n.js` + `t()` | Already works, well-tested across SCA/DAST/CTF |
| Role-based access | Custom role check in route handler | `requireRole()` middleware | Consistent with rest of codebase, handles RBAC toggle |
| Error rendering | Custom error HTML | `views/error.ejs` template | Already handles 403/404/429/500 with French text |

## Common Pitfalls

### Pitfall 1: Deleting database file without re-seeding
**What goes wrong:** Deleting `database/data.json` to fix duplicates but not re-starting the server to trigger re-seed.
**Why it happens:** The fix requires both clearing the data AND ensuring clean seed runs.
**How to avoid:** After adding DELETE statements to `seedData.js`, delete `database/data.json`, restart server. The `isDatabaseSeeded()` check (which looks at `db.users.length > 0`) will trigger a fresh seed.
**Warning signs:** Record counts are not exact multiples (12, 6) after fix.

### Pitfall 2: RBAC toggle bypasses role gates
**What goes wrong:** `requireRole()` skips enforcement when `rbac_enabled` is false (line 13 of middleware/rbac.js: `if (!req.securitySettings.rbac_enabled) { return next(); }`).
**Why it happens:** This is intentional for the DAST lab (students need to demonstrate RBAC bypass).
**How to avoid:** For the dashboard role gate, this is acceptable behavior -- when RBAC is off, all users can access all dashboards. This is consistent with the security lab's educational purpose. Do NOT add secondary role checks like the answer key has.
**Warning signs:** During QA, if RBAC is disabled, the "instructor can access student dashboard" issue will still reproduce. Test with RBAC enabled.

### Pitfall 3: Missing t() key fallback
**What goes wrong:** If a translation key is missing, `t()` returns the key string (e.g., "dashboard.student.title" appears literally in the UI).
**Why it happens:** The i18n module logs a warning but returns the key as fallback.
**How to avoid:** Add EVERY new key to BOTH fr.json and en.json. Test by visually inspecting pages for raw dot-notation strings.
**Warning signs:** Console shows "Translation missing: fr.dashboard.student.title" warnings.

### Pitfall 4: Route order matters for /classes/:id vs /classes
**What goes wrong:** Adding `GET /` to classes router could conflict with `GET /:id` if placed after.
**Why it happens:** Express matches routes in order; `:id` would match empty string only if `GET /` is not defined first.
**How to avoid:** In this case, `GET /` and `GET /:id` don't conflict because `/` won't match `/:id` (`:id` requires a segment). So order doesn't matter. But for clarity, place `GET /` before `GET /:id`.

### Pitfall 5: VM page has no i18n infrastructure at all
**What goes wrong:** Both `views/vm/student-lab.ejs` and `views/vm/instructor.ejs` have zero `t()` calls. The route handlers (`routes/vm.js`) also pass hardcoded English titles.
**Why it happens:** The VM module was built before the French localization push.
**How to avoid:** Must update BOTH the route handler (to pass French titles via `t()`) AND the templates (to use `t()` for labels). The DAST module is the best pattern to follow.

## Code Examples

### Fix 1: Seed Data Deduplication (Root Cause)

**File: `utils/seedData.js`**
```javascript
// At the top of seedDatabase(), after existing DELETE statements, add:
db.prepare('DELETE FROM sca_findings').run();
db.prepare('DELETE FROM sca_student_reviews').run();
db.prepare('DELETE FROM dast_scenarios').run();
db.prepare('DELETE FROM dast_student_findings').run();
db.prepare('DELETE FROM vulnerabilities').run();
db.prepare('DELETE FROM vm_status_history').run();
db.prepare('DELETE FROM vm_comments').run();
db.prepare('DELETE FROM ctf_challenges').run();
db.prepare('DELETE FROM ctf_submissions').run();
```

Then delete `database/data.json` so the next startup triggers a clean re-seed.

### Fix 2: Dashboard Role Gates

**File: `routes/dashboard.js`**
```javascript
const { requireRole } = require('../middleware/rbac');

router.get('/student', requireAuth, requireRole(['student']), (req, res) => { ... });
router.get('/professor', requireAuth, requireRole(['professor', 'admin']), (req, res) => { ... });
router.get('/admin', requireAuth, requireRole(['admin']), (req, res) => { ... });
```

### Fix 3: Classes List Route

**File: `routes/classes.js`**
```javascript
// Add before the /:id route
router.get('/', requireAuth, (req, res) => {
  const classes = db.prepare(`
    SELECT c.*, COUNT(DISTINCT e.student_id) as enrolled_count
    FROM classes c
    LEFT JOIN enrollments e ON c.id = e.class_id
    GROUP BY c.id
    ORDER BY c.code
  `).all();

  res.render('student/dashboard', { enrollments: classes });
  // OR create a new view views/classes/list.ejs
});
```

**Note:** The simplest approach is to redirect `/classes` to `/dashboard` since the dashboard already shows classes. Alternatively, create a proper classes list view. The planner should decide.

### Fix 4: Locked CTF Challenge Error Page

**File: `routes/pentest.js` line 251**
```javascript
// Before:
return res.status(403).json({ error: 'Challenge verrouille' });

// After:
return res.status(403).render('error', {
  message: 'Challenge verrouille',
  error: { status: 403 }
});
```

### Fix 5: Mes inscriptions Link

**File: `views/partials/header.ejs` line 113-118**

Options:
1. Remove the "Mes inscriptions" link entirely (it duplicates the dashboard link)
2. Point it to `/classes` (once the classes list route is added)
3. Keep it but change it to `/classes` so it shows the class list

Recommended: change href to `/classes` since that's the intuitive meaning.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in templates | `t()` function with fr.json keys | Phase 7+ | SCA, DAST, CTF fully localized; dashboards + VM still English |
| No role gates on dashboard routes | Only `requireAuth` used | Original code | ISSUE-003: instructors can access student dashboard |
| Seed only clears core collections | Should clear ALL collections | Phase 17 fix | Prevents data duplication on re-seed |

**Deprecated/outdated:**
- None. All patterns are current.

## Open Questions

1. **Classes list view design**
   - What we know: The `/classes` route needs a GET / handler. The professor dashboard already shows a class list.
   - What's unclear: Should we create a brand new classes list view, or redirect `/classes` to `/dashboard`?
   - Recommendation: Create a simple classes list view (like professor/dashboard but read-only for all roles) OR redirect to dashboard. The simplest fix is a redirect, but a proper list view is more correct.

2. **"Mes inscriptions" link destination**
   - What we know: Currently points to `/dashboard` (same page student is already on).
   - What's unclear: Should it go to `/classes`, be removed, or point somewhere else?
   - Recommendation: Change href to `/classes` (which will show the classes list once ISSUE-004 is fixed).

3. **VM page i18n depth**
   - What we know: VM templates and routes have zero i18n. Vulnerability titles come from the database (English seed data).
   - What's unclear: Should vulnerability titles/descriptions be translated (like SCA findings are via `localize()`), or just the UI chrome?
   - Recommendation: Translate only UI chrome (headings, labels, placeholders, column headers). Vulnerability titles/descriptions remain in English since they originate from SCA imports and the localize() function already handles SCA finding titles. Per REQUIREMENTS.md, I18N-02 "VM lab translated to French" is deferred to v2+, so minimal UI chrome translation is appropriate.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Node.js built-in test runner (node:test) |
| Config file | none -- uses `node --test test/*.test.js` |
| Quick run command | `node --test test/*.test.js` |
| Full suite command | `node --test test/*.test.js` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ISSUE-001 | SCA findings count = 12, DAST = 6, VM = 12 | integration | `node --test test/qa-fixes.test.js` | Wave 0 |
| ISSUE-002 | Dashboard pages contain French text, no raw English | integration | `node --test test/qa-fixes.test.js` | Wave 0 |
| ISSUE-003 | Instructor GET /dashboard/student returns 403 (RBAC on) | integration | `node --test test/qa-fixes.test.js` | Wave 0 |
| ISSUE-004 | GET /classes returns 200 (not 404) | integration | `node --test test/qa-fixes.test.js` | Wave 0 |
| ISSUE-005 | GET /pentest/challenges/5 (locked) returns HTML, not JSON | integration | `node --test test/qa-fixes.test.js` | Wave 0 |
| ISSUE-006 | "Mes inscriptions" href is not /dashboard | manual-only | Visual inspection of sidebar HTML | N/A |

### Sampling Rate
- **Per task commit:** `node --test test/qa-fixes.test.js`
- **Per wave merge:** `node --test test/*.test.js`
- **Phase gate:** Full suite green before verify

### Wave 0 Gaps
- [ ] `test/qa-fixes.test.js` -- covers ISSUE-001 through ISSUE-005
- [ ] Delete `database/data.json` before running server to get clean seed

## Sources

### Primary (HIGH confidence)
- Direct codebase investigation:
  - `database/data.json` -- confirmed 60 SCA findings, 30 DAST scenarios, 60 vulnerabilities (5x duplication)
  - `utils/seedData.js` lines 6-14 -- missing DELETE for sca_findings, dast_scenarios, vulnerabilities, ctf_challenges
  - `routes/dashboard.js` lines 30, 70, 95 -- no `requireRole` on any dashboard sub-route
  - `routes/classes.js` -- no `GET /` handler exists
  - `routes/pentest.js` line 251 -- `res.status(403).json()` for locked challenge
  - `views/partials/header.ejs` line 114 -- "Mes inscriptions" links to `/dashboard`
  - `views/student/dashboard.ejs` -- all English, zero `t()` calls
  - `views/professor/dashboard.ejs` -- all English, zero `t()` calls
  - `views/admin/dashboard.ejs` -- all English, zero `t()` calls
  - `views/vm/student-lab.ejs` -- all English, zero `t()` calls
  - `views/vm/instructor.ejs` -- all English, zero `t()` calls
  - `config/translations/fr.json` -- no dashboard.* or vm.* keys exist

### Secondary (MEDIUM confidence)
- QA-AUDIT.md -- detailed issue descriptions with repro steps and screenshots

## Metadata

**Confidence breakdown:**
- Root cause of duplication: HIGH -- verified by inspecting database/data.json (60 records instead of 12)
- i18n gaps: HIGH -- confirmed no `t()` calls in 5 templates, no keys in fr.json
- Role gate fix: HIGH -- confirmed no `requireRole` in dashboard.js
- Route fix: HIGH -- confirmed no GET / handler in classes.js
- CTF error fix: HIGH -- confirmed JSON response at pentest.js line 251
- Nav link fix: HIGH -- confirmed href="/dashboard" in header.ejs line 114

**Research date:** 2026-03-22
**Valid until:** Indefinite (codebase-specific findings, not library-dependent)
