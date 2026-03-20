# Phase 11: Instructor Tools - Research

**Researched:** 2026-03-19
**Domain:** Express.js server-rendered dashboard with polling-based live updates
**Confidence:** HIGH

## Summary

Phase 11 adds a student progress summary table to the existing SCA instructor dashboard, plus activity tracking (last_active_at, current_finding) on SCA routes. The implementation extends an existing, well-understood codebase: the instructor.ejs template already has stats polling (30s), progress bar CSS, classification badge CSS, and a student progress matrix. The new section slots between the stats cards and the findings overview table.

The most important technical finding is that the JSON database adapter uses SQL-pattern-matching (string includes) rather than real SQL parsing. Complex SQL queries with COUNT(DISTINCT), GROUP BY, or compound WHERE clauses that don't match existing patterns will silently return wrong results. All data aggregation for the new students array MUST be done in JavaScript from raw arrays fetched via simple queries. The existing GET /sca/stats endpoint already suffers from this (its COUNT(DISTINCT) query doesn't have a matching adapter pattern), making the JavaScript-aggregation approach both necessary and consistent.

**Primary recommendation:** Use a simple in-memory tracking object in routes/sca.js for last_active_at and current_finding, aggregate per-student stats in JavaScript inside the /sca/stats handler, and extend the existing refreshStats() client-side function to render the new table on each 30s poll cycle.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Summary table format: one row per student, sorted by completion % descending (most progress at top)
- Fixed sort order -- no click-to-sort column headers
- Five columns: Etudiant (linked to /sca/student/:id), Progression (progress bar + "X/12 soumis"), Derniere act. (relative time-ago), Analyse en cours (finding title or "--"), Statut (badge)
- Always visible -- not collapsible
- Section heading includes active count: "Suivi des etudiants -- 5 actifs / 8 etudiants"
- Table wrapped in overflow-x:auto for narrow screens (same pattern as existing matrix)
- Track last_active_at on any SCA action: GET /sca/findings/:id (viewing), POST /sca/findings/:id/review (save/submit), GET /sca/ (student lab page)
- Non-SCA actions (dashboard, DAST, VM, login) are NOT tracked
- "Current finding" = last finding detail page the student viewed (recorded on GET /sca/findings/:id)
- Current finding persists even when student navigates away from finding detail
- Three-state status badges: Actif (green #d4edda), Inactif (amber #fff3cd), Pas commence (gray #e9ecef)
- Last active displayed as relative time-ago in French: "il y a 2 min", "il y a 15 min", "il y a 1 h"
- Students with no activity show "Pas commence" instead of a time-ago value
- Progress tracks SCA submissions only (X/12 findings submitted), only status='submitted' counts
- DAST and other labs excluded from this progress view
- New section positioned between the 3 stats cards and the Findings Overview table
- Extend existing GET /sca/stats response with a "students" array
- Each student object: id, username, submitted count, lastActiveAt, currentFinding (id), currentFindingTitle
- Single AJAX call updates both stats cards and student table on 30s polling interval

### Claude's Discretion
- In-memory storage mechanism for last_active_at and current_finding (database adapter updates vs. separate tracking object)
- Exact i18n key names and French translations for new UI elements
- Progress bar styling (reuse existing .progress-bar-wrap/fill or new variant)
- Time-ago calculation logic (client-side vs. server-side)
- How to extract display name from username (e.g., strip "_student" suffix)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| INST-01 | Instructor dashboard shows each student's last_active_at and current finding being analyzed | Activity tracking via in-memory object in routes/sca.js; extended /sca/stats JSON response; client-side time-ago rendering; student progress table section in instructor.ejs |
| INST-02 | Instructor dashboard includes a progress summary card showing per-student completion | JavaScript aggregation of sca_student_reviews per student; progress bar reusing existing .progress-bar-wrap/.progress-bar-fill CSS; sorted table rows by completion % descending |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express | ^4.18.2 | HTTP server + routing | Already in use, all routes follow this pattern |
| EJS | ^3.1.9 | Server-side view templates | All views use EJS; instructor.ejs is the target file |
| express-session | ^1.17.3 | Session management (req.session.user) | Session provides user identity for tracking |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| utils/i18n.js (t function) | project-internal | Translation key lookup with {param} interpolation | All new French strings in the student progress table |
| config/database.js (db interface) | project-internal | SQL-pattern-matching JSON adapter | Reading sca_student_reviews, sca_findings, users |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| In-memory tracking object | Database fields on users table | DB adapter UPDATE for users is tightly scoped; adding new fields requires adapter changes; in-memory is simpler and sufficient for classroom use |
| Client-side time-ago | Server-side time-ago in stats JSON | Client-side avoids clock drift between server response time and display time; simpler since client already has Date.now() |

## Architecture Patterns

### Recommended Project Structure
```
routes/
  sca.js              # Add tracking middleware + extend /sca/stats
views/sca/
  instructor.ejs      # Add student progress table section + JS rendering
config/translations/
  fr.json             # Add sca.instructor.progress.* keys
  en.json             # Add parallel English keys
```

### Pattern 1: In-Memory Activity Tracking Object
**What:** A module-level plain object in routes/sca.js that maps student IDs to their last_active_at timestamp and current_finding_id.
**When to use:** When you need transient per-request state that doesn't need to survive server restarts (classroom session lasts hours, server restart resets activity which is acceptable).
**Example:**
```javascript
// Source: Pattern derived from existing codebase conventions
// Module-level tracking state (top of routes/sca.js)
const activityTracker = {};
// { [studentId]: { lastActiveAt: ISO string, currentFindingId: number|null } }

// Helper to record activity
function trackActivity(studentId, findingId) {
  if (!activityTracker[studentId]) {
    activityTracker[studentId] = { lastActiveAt: null, currentFindingId: null };
  }
  activityTracker[studentId].lastActiveAt = new Date().toISOString();
  if (findingId !== undefined) {
    activityTracker[studentId].currentFindingId = findingId;
  }
}
```

### Pattern 2: JavaScript Aggregation for Stats
**What:** Fetch raw arrays from the database adapter using simple queries, then aggregate in JS.
**When to use:** Always when building the /sca/stats response -- the SQL-pattern-matching adapter cannot handle GROUP BY, COUNT(DISTINCT), or compound WHERE reliably.
**Example:**
```javascript
// Source: Existing routes/sca.js pattern (adapted)
// Fetch all students and all submitted reviews
const students = db.prepare('SELECT * FROM users WHERE role = ?').all('student');
const allReviews = db.prepare('SELECT * FROM sca_student_reviews').all();

// Aggregate per-student submitted counts in JS
const studentsData = students.map(s => {
  const submitted = allReviews.filter(
    r => r.student_id === s.id && r.status === 'submitted'
  ).length;
  const activity = activityTracker[s.id] || {};
  return {
    id: s.id,
    username: s.username,
    submitted,
    lastActiveAt: activity.lastActiveAt || null,
    currentFindingId: activity.currentFindingId || null,
    currentFindingTitle: null // resolved below
  };
});
```

### Pattern 3: Extend refreshStats() for Client-Side Table Rendering
**What:** The existing refreshStats() function fetches /sca/stats every 30s and updates DOM elements. Extend it to also rebuild the student progress table.
**When to use:** Mandatory -- the user locked the single AJAX call approach.
**Example:**
```javascript
// Source: Existing views/sca/instructor.ejs:173-190 pattern
async function refreshStats() {
  try {
    const res = await fetch('/sca/stats');
    const data = await res.json();
    // Update existing stats cards (unchanged)
    document.getElementById('stat-started').textContent = ...;
    // Update student progress table (new)
    renderStudentTable(data.students, data.totalFindings);
  } catch (e) { /* silent fail */ }
}
```

### Pattern 4: EJS Inline Styles + Badge CSS
**What:** All styling uses inline styles or existing CSS classes in the template's `<style>` block. No external CSS files.
**When to use:** Mandated by project convention -- inline styles throughout templates.
**Example:**
```html
<!-- Reuse existing badge pattern from instructor.ejs -->
<span class="badge-sm" style="background:#d4edda; color:#155724;">Actif</span>
<span class="badge-sm" style="background:#fff3cd; color:#856404;">Inactif</span>
<span class="badge-sm" style="background:#e9ecef; color:#6c757d;">Pas commenc&eacute;</span>
```

### Anti-Patterns to Avoid
- **Complex SQL queries in the adapter:** The database.js adapter matches SQL by string inclusion. Do NOT add GROUP BY, COUNT(DISTINCT), JOINs, or subqueries. Fetch raw arrays and aggregate in JS.
- **Database writes for activity tracking:** Adding columns to the users table would require modifying the database adapter's UPDATE handler. Use an in-memory object instead.
- **WebSocket for real-time updates:** Explicitly out of scope (REQUIREMENTS.md). 30s polling is the established pattern.
- **External time-ago libraries:** Zero new npm dependencies is the project constraint (from Phase 8 decision). Implement a small time-ago function inline.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Progress bar rendering | Custom SVG/canvas progress | Existing `.progress-bar-wrap` + `.progress-bar-fill` CSS | Already styled with #002855 fill, 6px height, border-radius -- exact match |
| Badge styling | New badge CSS classes | Existing `.badge-sm` + `.cls-confirmed` / `.cls-needs` / `.cls-none` pattern | Colors and sizing already defined and consistent across the dashboard |
| Username display | Custom name parser | `s.username.replace('_student','')` | Exact pattern already used in instructor.ejs:109 for the matrix |
| i18n | Custom translation layer | Existing `t()` function with {param} interpolation | Handles nested keys, French fallback, parameter substitution |
| Session cookie/auth | Custom auth check | `requireAuth` + `requireRole(['admin','professor'])` | Exact middleware already on /sca/stats |

## Common Pitfalls

### Pitfall 1: Database Adapter SQL Pattern Mismatch
**What goes wrong:** Writing SQL like `SELECT COUNT(DISTINCT student_id) FROM sca_student_reviews` expecting it to return `{ count: N }`, but the adapter has no matching pattern and returns the full array instead.
**Why it happens:** The database.js adapter uses `sql.includes()` string matching, not SQL parsing. Only explicitly coded patterns work.
**How to avoid:** Fetch full arrays with simple `SELECT * FROM table WHERE column = ?` queries and aggregate in JavaScript.
**Warning signs:** `.get().count` returning `undefined`; `.all()` returning un-grouped results.

### Pitfall 2: Student ID Type Mismatch
**What goes wrong:** Comparing student IDs as strings vs. numbers. The database adapter uses `params[0]` directly for some queries and `parseInt(params[0])` for others.
**Why it happens:** Session user IDs come from `req.session.user.id` which may be a number, while database queries sometimes parse to int and sometimes don't.
**How to avoid:** In the activityTracker, always use the student ID as-is from `req.session.user.id`. In filter comparisons, use strict equality (`===`) and ensure both sides are the same type.
**Warning signs:** Activity data not matching students; empty results from filter operations.

### Pitfall 3: Race Condition on Activity Timestamps
**What goes wrong:** Two concurrent requests from the same student could interleave, with a GET /sca/ overwriting a more recent GET /sca/findings/:id timestamp.
**Why it happens:** Node.js is single-threaded but Express middleware executes asynchronously.
**How to avoid:** Not a real concern in practice -- Node is single-threaded so `activityTracker[id].lastActiveAt = new Date().toISOString()` is atomic. Just always write the timestamp unconditionally.
**Warning signs:** None expected -- this is a non-issue in Node.js.

### Pitfall 4: Findings Title Resolution for Current Finding
**What goes wrong:** The currentFindingId stored in the tracker needs to be resolved to a title for display, but fetching each finding individually in a loop is wasteful.
**Why it happens:** The finding title is needed in the stats response but only the ID is tracked.
**How to avoid:** Fetch all findings once with `db.prepare('SELECT * FROM sca_findings').all()` and build a lookup map `{ [id]: title }`. Use it to resolve currentFindingTitle in the students array.
**Warning signs:** N+1 query pattern; slow stats endpoint response.

### Pitfall 5: Stale Activity After Server Restart
**What goes wrong:** In-memory tracker is empty after server restart, so all students show "Pas commence" even if they were active before.
**Why it happens:** In-memory state doesn't survive process restart.
**How to avoid:** This is acceptable for classroom use -- the instructor starts the server at beginning of class. Document it as a known limitation. The progress (submitted count) is persistent since it comes from the database.
**Warning signs:** All students showing "Pas commence" after restart. Expected behavior.

## Code Examples

### Activity Tracking Integration Points
```javascript
// Source: routes/sca.js - existing route at line 51
// GET /sca/ - Student lab page
router.get('/', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role === 'student') {
    trackActivity(user.id);  // <-- ADD THIS LINE
    // ... existing student code ...
  }
  // ... existing instructor code ...
});

// Source: routes/sca.js - existing route at line 139
// GET /sca/findings/:id - Finding detail
router.get('/findings/:id', requireAuth, (req, res) => {
  const finding = db.prepare('SELECT * FROM sca_findings WHERE id = ?').get(parseInt(req.params.id));
  // ... existing code ...
  const user = req.session.user;
  if (user.role === 'student') {
    trackActivity(user.id, finding.id);  // <-- ADD THIS LINE (tracks both activity + current finding)
  }
  // ... existing code ...
});

// Source: routes/sca.js - existing route at line 189
// POST /sca/findings/:id/review - Student submit review
router.post('/findings/:id/review', requireAuth, requireRole(['student']), (req, res) => {
  const studentId = req.session.user.id;
  trackActivity(studentId);  // <-- ADD THIS LINE
  // ... existing code ...
});
```

### Extended Stats Endpoint Response Shape
```javascript
// Source: routes/sca.js - extending existing /sca/stats handler
res.json({
  // Existing fields (unchanged)
  studentsStarted,
  totalStudents,
  avgCompletion,
  pace,
  // New field
  totalFindings,  // needed by client for progress bar calculation
  students: [
    {
      id: 3,
      username: "alice_student",
      submitted: 8,
      lastActiveAt: "2026-03-19T14:32:00.000Z",  // ISO string or null
      currentFindingId: 5,                          // number or null
      currentFindingTitle: "Journalisation d'audit desactivee par defaut"  // string or null
    }
  ]
});
```

### Client-Side Time-Ago in French
```javascript
// Source: Custom implementation (no library allowed per project constraint)
function timeAgo(isoString) {
  if (!isoString) return null;
  const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (diff < 60) return 'il y a ' + diff + ' s';
  if (diff < 3600) return 'il y a ' + Math.floor(diff / 60) + ' min';
  if (diff < 86400) return 'il y a ' + Math.floor(diff / 3600) + ' h';
  return 'il y a ' + Math.floor(diff / 86400) + ' j';
}
```

### Client-Side Table Rendering
```javascript
// Source: Pattern from existing refreshStats() in instructor.ejs
function renderStudentTable(students, totalFindings) {
  if (!students) return;
  const tbody = document.getElementById('student-progress-tbody');
  const activeCount = students.filter(s => {
    if (!s.lastActiveAt) return false;
    return (Date.now() - new Date(s.lastActiveAt).getTime()) < 5 * 60 * 1000;
  }).length;

  document.getElementById('student-active-count').textContent =
    activeCount + ' actifs / ' + students.length + ' \u00e9tudiants';

  // Sort by completion descending
  students.sort((a, b) => b.submitted - a.submitted);

  tbody.innerHTML = students.map(s => {
    const pct = totalFindings ? Math.round(s.submitted / totalFindings * 100) : 0;
    const name = s.username.replace('_student', '');
    const status = getStatus(s.lastActiveAt, s.submitted);
    const ago = timeAgo(s.lastActiveAt);
    return `<tr>
      <td><a href="/sca/student/${s.id}" style="color:#002855;font-weight:600;">${name}</a></td>
      <td style="min-width:140px;">
        <div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:${pct}%"></div></div>
        <div style="font-size:0.8rem;color:#666;margin-top:2px;">${s.submitted}/${totalFindings} soumis</div>
      </td>
      <td style="font-size:0.85rem;color:#666;">${ago || '\u2014'}</td>
      <td style="font-size:0.85rem;">${s.currentFindingTitle || '\u2014'}</td>
      <td>${status}</td>
    </tr>`;
  }).join('');
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Server-side full page reload | 30s AJAX polling + DOM update | Already in place (Phase 4) | Student table follows same pattern |
| Complex SQL in adapter | JS aggregation from raw arrays | Learned from adapter limitations | Must aggregate per-student counts in JS |

**Deprecated/outdated:**
- None relevant to this phase. All patterns are current and actively used.

## Open Questions

1. **Activity tracker reset behavior**
   - What we know: In-memory tracker clears on server restart. Progress (submitted counts) is persistent.
   - What's unclear: Whether the instructor needs a "reset activity" button between class sessions.
   - Recommendation: Not needed for v1.1 -- server restart between classes naturally resets activity. Can be added later if needed.

2. **Localization of finding titles in stats response**
   - What we know: Finding titles are stored in English in the database. French translations exist in fr.json via `sca.findings.{id}.title`.
   - What's unclear: Whether to localize in the stats endpoint (server-side) or client-side.
   - Recommendation: Localize server-side in the /sca/stats handler using the existing `localize()` or `t()` function with the session language. The client rendering code then uses titles as-is.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, Node 20+) |
| Config file | none (uses --test flag) |
| Quick run command | `node --test test/sca-review.test.js` |
| Full suite command | `npm run test:integration` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| INST-01 | /sca/stats returns students array with lastActiveAt and currentFindingId after student activity | integration | `node --test test/instructor-tools.test.js` | No -- Wave 0 |
| INST-01 | Activity tracked on GET /sca/findings/:id (student role only) | integration | `node --test test/instructor-tools.test.js` | No -- Wave 0 |
| INST-02 | /sca/stats students array includes per-student submitted count | integration | `node --test test/instructor-tools.test.js` | No -- Wave 0 |
| INST-02 | Students sorted by completion descending in response | integration | `node --test test/instructor-tools.test.js` | No -- Wave 0 |

### Sampling Rate
- **Per task commit:** `node --test test/instructor-tools.test.js`
- **Per wave merge:** `npm run test:integration`
- **Phase gate:** Full suite green before /gsd:verify-work

### Wave 0 Gaps
- [ ] `test/instructor-tools.test.js` -- covers INST-01, INST-02 (stats endpoint integration tests)
- Existing test infrastructure (`test/helpers.js` with `loginAs`, `request`, `BASE_URL`) is sufficient -- no new shared fixtures needed
- Framework (node:test) already available -- no install needed

## Sources

### Primary (HIGH confidence)
- `routes/sca.js` -- existing /sca/stats endpoint, GET /sca/, GET /sca/findings/:id, POST review routes (direct code review)
- `views/sca/instructor.ejs` -- existing stats polling, progress bar CSS, badge CSS, matrix table pattern (direct code review)
- `config/database.js` -- SQL-pattern-matching adapter behavior, executeSQL function, known pattern limitations (direct code review)
- `config/translations/fr.json` -- existing sca.instructor.* keys, translation structure (direct code review)
- `utils/i18n.js` -- t() function signature, localize() behavior, parameter interpolation (direct code review)

### Secondary (MEDIUM confidence)
- `test/helpers.js` -- testing patterns, loginAs helper, BASE_URL convention (direct code review)

### Tertiary (LOW confidence)
- None. All findings are from direct codebase analysis.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- direct codebase analysis, no external dependencies needed
- Architecture: HIGH -- extending existing proven patterns (polling, EJS templates, in-memory state)
- Pitfalls: HIGH -- database adapter limitations verified by reading executeSQL source; type mismatches observed in existing code
- Activity tracking approach: HIGH -- in-memory object is simplest approach; database adapter would require changes for new user fields

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- no external dependency changes expected)
