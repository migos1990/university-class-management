# Phase 7: Quick Wins - Research

**Researched:** 2026-03-19
**Domain:** EJS templating, Express.js routing, i18n translation, API authentication
**Confidence:** HIGH

## Summary

Phase 7 addresses four independent "quick wins" identified during the product review: (1) translating hardcoded English security status bar badges into French, (2) adding a celebration banner when students complete all 12 SCA findings, (3) adding prev/next navigation arrows on the SCA finding detail page, and (4) adding authentication guards to two currently-unauthenticated API endpoints.

All four tasks operate on the existing Express/EJS codebase with no new dependencies. The i18n system (`utils/i18n.js`, `config/translations/fr.json`) is already mature and handles all other pages. The auth middleware (`middleware/auth.js`) already exists and is used throughout the app. The SCA routes (`routes/sca.js`) already track submission counts. These are purely wiring tasks -- connecting existing infrastructure to overlooked spots.

**Primary recommendation:** Implement each requirement as an independent, small change -- all four can be planned as tasks in a single plan since they touch different files and have zero inter-dependencies.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| QWIN-01 | Security status bar badges display in French on every page | Badges in `views/partials/header.ejs` lines 558-582 use hardcoded English strings ("ON", "OFF", "Encrypted", "Plaintext", "HTTPS", "HTTP"). French translations already exist in `fr.json` under `security.status.*`. Wire `t()` calls to replace hardcoded text. |
| QWIN-02 | SCA completion celebration banner shown when student submits all 12 findings | `views/sca/student-lab.ejs` already computes `submitted` and `total` variables. Add conditional banner when `submitted === total && total > 0`. Add French translation key for celebration message. |
| QWIN-03 | Finding detail page has prev/next navigation arrows between findings | `routes/sca.js` GET `/sca/findings/:id` currently loads a single finding. Needs to pass ordered finding IDs list (or prev/next IDs) to the view. `views/sca/finding-detail.ejs` needs nav arrows added to page header. |
| QWIN-04 | POST /api/instructor-message and GET /api/summary require authentication | Both endpoints defined in `server.js` lines 115-224 with zero middleware. Import and apply `requireAuth` middleware. Note: GET /api/instructor-message is polled by the header banner script -- must remain accessible to authenticated users (students, professors, admins). |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| express | ^4.18.2 | Web framework | Already in use, all routes use Express router |
| ejs | ^3.1.9 | Template engine | All views use EJS, no alternatives needed |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| utils/i18n.js | project | Translation function `t()` | All French text rendering |
| middleware/auth.js | project | `requireAuth` middleware | Protecting API endpoints |
| middleware/rbac.js | project | `requireRole` middleware | If role-gating needed beyond auth |

### Alternatives Considered
None. All four tasks use existing project infrastructure. No new dependencies required.

## Architecture Patterns

### Relevant Project Structure
```
config/translations/
  en.json                # English translations (reference)
  fr.json                # French translations (active language)
middleware/
  auth.js                # requireAuth (session check)
  rbac.js                # requireRole (role-based access)
views/partials/
  header.ejs             # Security status bar (QWIN-01), broadcast banner
views/sca/
  student-lab.ejs        # Student SCA list page (QWIN-02 celebration)
  finding-detail.ejs     # Finding detail page (QWIN-03 nav arrows)
routes/
  sca.js                 # SCA routes, finding detail handler
server.js                # API endpoints (QWIN-04)
```

### Pattern 1: Translation via t() Function
**What:** All user-visible strings use `t('key.path')` which resolves from session language (defaults to `'fr'`)
**When to use:** Any hardcoded English text that should be French
**Example:**
```ejs
<!-- Current (hardcoded English): -->
MFA: <%= securitySettings.mfa_enabled ? 'ON' : 'OFF' %>

<!-- Fixed (translated): -->
MFA: <%= securitySettings.mfa_enabled ? t('security.status.on') : t('security.status.off') %>
```
**Source:** `utils/i18n.js` lines 73-84, existing `fr.json` already has `security.status.on` = "ACTIVE" and `security.status.off` = "DESACTIVE"

### Pattern 2: Conditional Banner Display
**What:** Show/hide a banner based on server-side condition in EJS
**When to use:** Celebration banner on SCA completion
**Example:**
```ejs
<% if (submitted === total && total > 0) { %>
<div class="alert alert-success" style="...">
  <strong><%= t('sca.studentLab.completionTitle') %></strong>
  <p><%= t('sca.studentLab.completionMessage') %></p>
</div>
<% } %>
```
**Source:** Same pattern as existing intro banner in `student-lab.ejs` lines 26-33

### Pattern 3: Express Auth Middleware Application
**What:** Apply `requireAuth` to route handlers to require session
**When to use:** Any endpoint that should reject unauthenticated requests
**Example:**
```javascript
// Current (no auth):
app.get('/api/instructor-message', (req, res) => { ... });

// Fixed (auth required):
const { requireAuth } = require('./middleware/auth');
app.get('/api/instructor-message', requireAuth, (req, res) => { ... });
```
**Source:** `middleware/auth.js`, used extensively in `routes/sca.js` line 51

### Pattern 4: Prev/Next Navigation in Detail Views
**What:** Pass ordered list of item IDs to template, compute prev/next links
**When to use:** QWIN-03 finding detail navigation
**Example:**
```javascript
// In route handler, after loading finding:
const allFindings = db.prepare('SELECT id FROM sca_findings').all();
const enriched = allFindings.map(f => ({ ...f, difficulty: DIFFICULTY_MAP[f.id] || 'medium' }));
enriched.sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty]);
const ids = enriched.map(f => f.id);
const currentIndex = ids.indexOf(parseInt(req.params.id));
const prevId = currentIndex > 0 ? ids[currentIndex - 1] : null;
const nextId = currentIndex < ids.length - 1 ? ids[currentIndex + 1] : null;

res.render('sca/finding-detail', {
  // ... existing params
  prevId,
  nextId
});
```

### Anti-Patterns to Avoid
- **Hardcoding French strings in EJS:** Always use `t()` -- never write raw French text in templates. New strings must go into both `en.json` and `fr.json`.
- **Adding auth to GET /api/instructor-message without considering the banner script:** The banner in `header.ejs` (line 432) calls `fetch('/api/instructor-message')` with no credentials mode set. Since the fetch is same-origin and sessions are cookie-based, `requireAuth` will work -- but the banner must handle 401 gracefully (it already has `.catch(() => {})` on line 444).
- **Sorting findings inconsistently between list and detail:** The student-lab sorts by difficulty order. The prev/next navigation must use the same sort order, otherwise arrows will feel random. Use the same `DIFFICULTY_ORDER` mapping from `routes/sca.js`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Translation | Custom string interpolation | `t()` from `utils/i18n.js` | Already handles fallback, interpolation, nested keys |
| Auth check | Inline `if (!req.session.user)` | `requireAuth` middleware | Consistent redirect behavior, DRY |
| Role check | Inline role comparison | `requireRole` middleware | Already handles RBAC disabled mode |

**Key insight:** Every piece of infrastructure needed for these 4 tasks already exists. The work is purely wiring -- no new systems, libraries, or patterns to create.

## Common Pitfalls

### Pitfall 1: Forgetting to Handle Auth Error in Banner Poll
**What goes wrong:** After adding `requireAuth` to `/api/instructor-message`, unauthenticated users' banner script gets a 302 redirect to login page instead of JSON, causing silent errors.
**Why it happens:** The redirect response is HTML, not JSON, so `.json()` will throw.
**How to avoid:** The existing `catch(() => {})` in header.ejs already swallows errors, so this is handled. But verify the banner does not show broken state for logged-out users (login page does not include header.ejs so banner script does not run -- confirmed safe).
**Warning signs:** Console errors in browser on login page.

### Pitfall 2: Missing Translation Keys in en.json
**What goes wrong:** Adding new keys to `fr.json` but forgetting `en.json`, causing the fallback to return the raw key path.
**Why it happens:** French is the primary language, so testers may not notice.
**How to avoid:** Always add new keys to both `en.json` and `fr.json` simultaneously.
**Warning signs:** Strings like "sca.studentLab.completionTitle" appearing in the UI.

### Pitfall 3: Inconsistent Finding Sort Order for Prev/Next
**What goes wrong:** The prev/next arrows follow database ID order while the student-lab list follows difficulty order, confusing students.
**Why it happens:** Developer uses `SELECT * FROM sca_findings` which returns by ID, but the student-lab sorts by difficulty.
**How to avoid:** Use the same `DIFFICULTY_MAP` and `DIFFICULTY_ORDER` from `routes/sca.js` when computing prev/next IDs.
**Warning signs:** Clicking "next" on an Easy finding jumps to an Advanced finding.

### Pitfall 4: Security Status Bar Translation Incomplete
**What goes wrong:** Some badges translated but others missed, resulting in mixed English/French.
**Why it happens:** There are 7 badges and each has different text patterns -- some say "ON/OFF", others say "Encrypted/Plaintext" or "HTTPS/HTTP".
**How to avoid:** Systematically go through all 7 badge spans in header.ejs lines 561-581. Each one needs its own translation treatment. The existing `security.status.on/off/enabled/disabled` keys cover most cases, but "Encrypted"/"Plaintext" and "HTTPS"/"HTTP" need additional keys.
**Warning signs:** The word "Encrypted" or "Plaintext" appearing in the status bar.

### Pitfall 5: POST /api/instructor-message Needs requireAuth but Also Role-Gating
**What goes wrong:** Adding only `requireAuth` allows any logged-in student to broadcast messages.
**Why it happens:** The requirement says "require authentication" but the original code comment says it is "called by classroom-manager broadcast fan-out" -- meaning it is meant to be called by the classroom manager process, not by end users.
**How to avoid:** Apply `requireAuth` (minimum per requirement). Consider whether `requireRole(['admin', 'professor'])` is also appropriate -- but note the classroom-manager calls this endpoint programmatically from the server-side, not through a browser session. Adding auth may break the classroom-manager fan-out. Need to check if classroom-manager sends a session cookie.
**Warning signs:** Classroom broadcast feature stops working after adding auth.

## Code Examples

### QWIN-01: Translating Security Status Bar Badges

Current header.ejs badges (lines 561-581) use hardcoded English:
```ejs
<!-- CURRENT (English hardcoded) -->
<span class="badge ...">MFA: <%= securitySettings.mfa_enabled ? 'ON' : 'OFF' %></span>
<span class="badge ...">RBAC: <%= securitySettings.rbac_enabled ? 'ON' : 'OFF' %></span>
<span class="badge ...">Passwords: <%= securitySettings.encryption_at_rest ? 'Encrypted' : 'Plaintext' %></span>
<span class="badge ...">Data: <%= securitySettings.field_encryption ? 'Encrypted' : 'Plaintext' %></span>
<span class="badge ..."><%= securitySettings.https_enabled ? 'HTTPS' : 'HTTP' %></span>
<span class="badge ...">Logging: <%= securitySettings.audit_logging ? 'ON' : 'OFF' %></span>
<span class="badge ...">Rate Limit: <%= securitySettings.rate_limiting ? 'ON' : 'OFF' %></span>
```

Existing French translations available in `fr.json`:
- `security.status.on` = "ACTIVE"
- `security.status.off` = "DESACTIVE"
- `security.status.enabled` = "Active"
- `security.status.disabled` = "Desactive"

**Missing translations needed** (add to both en.json and fr.json):
- Badge labels: "MFA", "RBAC", "Passwords"/"Mots de passe", "Data"/"Donnees", "Logging"/"Journalisation", "Rate Limit"/"Limitation de debit"
- Badge values: "Encrypted"/"Chiffre", "Plaintext"/"Clair", "HTTPS", "HTTP"

### QWIN-02: Celebration Banner

Add after the progress card in `views/sca/student-lab.ejs` (after line 50):
```ejs
<% if (submitted === total && total > 0) { %>
<div class="card" style="background: #d4edda; border: 1px solid #c3e6cb; text-align: center; padding: 2rem;">
  <div style="font-size: 2rem; margin-bottom: 0.5rem;">...</div>
  <h2 style="color: #155724; margin-bottom: 0.5rem;"><%= t('sca.studentLab.completionTitle') %></h2>
  <p style="color: #155724;"><%= t('sca.studentLab.completionMessage') %></p>
</div>
<% } %>
```

New translation keys:
- `sca.studentLab.completionTitle`: EN "Congratulations!" / FR "Bravo !"
- `sca.studentLab.completionMessage`: EN "You have submitted all 12 findings. Well done!" / FR "Vous avez soumis les 12 constats. Excellent travail !"

### QWIN-03: Prev/Next Navigation

Route change in `routes/sca.js` GET `/sca/findings/:id` -- add prev/next computation:
```javascript
// After loading the finding, compute nav links
const allFindings = db.prepare('SELECT id FROM sca_findings').all();
const enriched = allFindings.map(f => ({ ...f, difficulty: DIFFICULTY_MAP[f.id] || 'medium' }));
enriched.sort((a, b) => DIFFICULTY_ORDER[a.difficulty] - DIFFICULTY_ORDER[b.difficulty]);
const ids = enriched.map(f => f.id);
const currentIndex = ids.indexOf(finding.id);
const prevId = currentIndex > 0 ? ids[currentIndex - 1] : null;
const nextId = currentIndex < ids.length - 1 ? ids[currentIndex + 1] : null;
```

View change in `views/sca/finding-detail.ejs` -- add nav arrows in page header:
```ejs
<div style="display:flex; align-items:center; gap:1rem;">
  <% if (prevId) { %>
    <a href="/sca/findings/<%= prevId %>" style="..." title="<%= t('common.previous') %>">&larr;</a>
  <% } %>
  <a href="/sca" style="..."><%= t('sca.findingDetail.backToLab') %></a>
  <h1 class="page-title" style="margin:0;flex:1;"><%= finding.title %></h1>
  <% if (nextId) { %>
    <a href="/sca/findings/<%= nextId %>" style="..." title="<%= t('common.next') %>">&rarr;</a>
  <% } %>
</div>
```

Translation keys `common.previous` ("Precedent") and `common.next` ("Suivant") already exist in both en.json and fr.json.

### QWIN-04: Adding Auth to API Endpoints

In `server.js`, the `requireAuth` middleware is not currently imported. Add it and apply:
```javascript
const { requireAuth } = require('./middleware/auth');

// GET /api/instructor-message
app.get('/api/instructor-message', requireAuth, (req, res) => {
  res.json({ message: _instructorMessage });
});

// POST /api/instructor-message
app.post('/api/instructor-message', requireAuth, (req, res) => {
  _instructorMessage = req.body.message || null;
  res.json({ success: true });
});

// GET /api/summary
app.get('/api/summary', requireAuth, (req, res) => {
  // ... existing handler
});
```

**Critical consideration:** The POST endpoint is called by the classroom-manager process (`scripts/classroom-manager.js`) during fan-out broadcast. If the classroom-manager makes HTTP requests without a session cookie, adding `requireAuth` will break broadcasts. However, reviewing the architecture comment on line 106-108 of server.js: "NOTE: No authentication -- accessible only on the isolated classroom network". The requirement QWIN-04 explicitly says to add auth. This means the classroom-manager will need to authenticate or use a different approach. Check how the classroom-manager calls these endpoints.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded English in badges | Should use t() with translation keys | This phase | Completes French-only experience |
| No completion feedback | Celebration banner on 12/12 | This phase | Student motivation, clear completion signal |
| Back-to-list only navigation | Prev/next arrows in detail view | This phase | Reduces friction, faster review workflow |
| Unauthenticated API endpoints | Auth-protected endpoints | This phase | Closes security gap per QWIN-04 |

## Open Questions

1. **Classroom-manager broadcast compatibility with auth**
   - What we know: `POST /api/instructor-message` is called by `scripts/classroom-manager.js` for broadcast fan-out. The comment says "accessible only on the isolated classroom network".
   - What's unclear: Does the classroom-manager process have a session cookie? If not, adding `requireAuth` will break broadcasts.
   - Recommendation: Check `scripts/classroom-manager.js` to see how it calls the endpoint. If it uses plain HTTP without cookies, consider making POST require auth but with a fallback (e.g., check for a shared secret header from classroom-manager), or just add `requireAuth` per the requirement and accept that classroom-manager broadcasts may need adjustment. Per the requirement text, auth is the explicit goal.

2. **GET /api/instructor-message auth and the header banner**
   - What we know: The banner script in `header.ejs` polls this endpoint every 30 seconds via `fetch()`. Since it runs inside the authenticated layout (header.ejs is only included for logged-in users), the session cookie will be sent automatically.
   - What's unclear: Nothing -- this should work. The `catch(() => {})` handles any edge cases.
   - Recommendation: Safe to add `requireAuth`. No changes needed to the banner script.

3. **Badge label translation scope**
   - What we know: The requirement says "badges display in French". The badge labels ("MFA", "RBAC", "Passwords", etc.) and values ("ON"/"OFF", "Encrypted"/"Plaintext") are all English.
   - What's unclear: Should technical acronyms like "MFA", "RBAC", "HTTPS" be translated? In French security contexts, these acronyms are used as-is.
   - Recommendation: Keep technical acronyms (MFA, RBAC, HTTPS) untranslated. Translate descriptive labels and values: "Passwords" -> "Mots de passe", "ON" -> "ACTIVE", "Encrypted" -> "Chiffre", etc.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Custom smoke test (scripts/smoke-test.js) |
| Config file | scripts/smoke-test.js |
| Quick run command | `npm test` |
| Full suite command | `npm test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| QWIN-01 | Security badges render in French | manual | Visual check: load any page, verify status bar badges are French | N/A manual |
| QWIN-02 | Celebration banner on 12/12 completion | manual | Log in as student, submit all 12 findings, verify banner appears | N/A manual |
| QWIN-03 | Prev/next arrows on finding detail | manual | Navigate to /sca/findings/1, verify prev/next arrows, click through | N/A manual |
| QWIN-04 | API endpoints require auth | smoke | `curl -s http://localhost:3000/api/summary` should return redirect/401, not JSON | Wave 0 |

### Sampling Rate
- **Per task commit:** Visual inspection of affected pages
- **Per wave merge:** `npm test` (smoke test)
- **Phase gate:** All 4 requirements manually verified + smoke test green

### Wave 0 Gaps
- [ ] No automated test for QWIN-04 auth enforcement -- Phase 8 (TEST-03) will add integration tests for this. For Phase 7, manual curl verification is sufficient.

None of the other requirements (QWIN-01 through QWIN-03) are automatable without a browser testing framework, which is out of scope. Phase 8 will add integration tests.

## Sources

### Primary (HIGH confidence)
- `views/partials/header.ejs` -- Security status bar badges, lines 558-582 (hardcoded English strings identified)
- `config/translations/fr.json` -- Existing French translations including `security.status.*` keys
- `config/translations/en.json` -- English reference translations
- `routes/sca.js` -- SCA route handlers, finding detail at line 139, student lab at line 51
- `views/sca/student-lab.ejs` -- Student lab view with `submitted`/`total` variables
- `views/sca/finding-detail.ejs` -- Finding detail view (no prev/next currently)
- `server.js` -- API endpoints at lines 115-224 (no auth middleware applied)
- `middleware/auth.js` -- `requireAuth` middleware implementation
- `utils/i18n.js` -- Translation system with `t()`, `localize()`, `languageMiddleware`

### Secondary (MEDIUM confidence)
- None needed -- all findings are from direct codebase inspection

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no new libraries, all existing project infrastructure
- Architecture: HIGH -- all patterns already established in codebase
- Pitfalls: HIGH -- identified through direct code reading of affected files
- QWIN-04 classroom-manager impact: MEDIUM -- needs verification of how classroom-manager calls POST endpoint

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- no external dependencies changing)
