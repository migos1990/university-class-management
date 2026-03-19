# Phase 7: Instructor Answer Key - Research

**Researched:** 2026-03-19
**Domain:** Role-gated instructor views, i18n answer key content, collapsible UI sections, EJS templates, Express routing
**Confidence:** HIGH

## Summary

Phase 7 adds an instructor-only answer key to the SCA lab. This involves two deliverables: (1) a standalone answer key page listing all 12 findings with their expected classifications, reasoning, and discussion prompts in Quebec French, and (2) a collapsible inline answer section on the existing finding detail page visible only to instructors. Both must be role-gated at the handler level (not just hidden in the UI) so students cannot access answer content even by inspecting page source.

The codebase already has all the patterns needed: `requireAuth` + `requireRole(['admin', 'professor'])` for handler-level gating (used on `/sca/stats`, `/sca/student/:studentId`, `/sca/import-to-vm/:id`), the `localize()` + `t()` i18n system with ~136 keys in `fr.json`, the white-card/HEC-navy visual language, and role-conditional rendering in EJS (`user.role !== 'student'`). The SOLUTION-GUIDE.md already contains English expected classifications for all 12 findings (11 confirmed, 1 needs investigation), which must be translated to Quebec French with pedagogical reasoning and discussion prompts added.

The critical design decision is AKEY-05's constraint: "invisible to students even in page source." The finding detail page (`/sca/findings/:id`) is a shared route serving both students and instructors. The inline answer section must NOT be rendered in the EJS output for students -- it cannot simply be hidden with CSS (`display:none`) because students could view it in page source. The route handler already branches on `user.role` (lines 147-153 of `routes/sca.js`), so the pattern is to pass answer key data only when the user is an instructor, and wrap the EJS rendering in a role check that prevents the HTML from being emitted at all for students.

**Primary recommendation:** Add a new route `GET /sca/answer-key` gated with `requireAuth` + `requireRole(['admin', 'professor'])`, a new EJS template `views/sca/answer-key.ejs`, answer key content as new i18n keys under `sca.answerKey.*` in both `en.json` and `fr.json`, and modify the existing finding detail route + template to conditionally pass and render inline answer data for instructors only. Link the answer key from the SCA instructor dashboard page.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| AKEY-01 | Instructor can view a standalone answer key page with all 12 findings' expected classifications | New route `GET /sca/answer-key` with `requireRole`, new EJS template, answer data from i18n keys or inline data structure |
| AKEY-02 | Answer key displays reasoning explaining why each finding has its expected classification | Reasoning text added as i18n keys (`sca.answerKey.{id}.reasoning`) in fr.json/en.json; SOLUTION-GUIDE.md provides source classifications |
| AKEY-03 | Answer key includes discussion prompts for in-class use per finding | Discussion prompt text added as i18n keys (`sca.answerKey.{id}.discussion`); new pedagogical content in Quebec French |
| AKEY-04 | Answer key is role-gated (visible only to professor/admin, never to students) | Use existing `requireRole(['admin', 'professor'])` middleware on route handler; verified pattern from `/sca/stats`, `/sca/student/:studentId` |
| AKEY-05 | Instructor can see an inline collapsible answer section in the finding detail view | Modify `GET /sca/findings/:id` to pass answer data only for instructor roles; EJS conditional `<% if (user.role !== 'student' && answerKey) { %>` prevents HTML emission for students |
| AKEY-06 | All answer key content is in Quebec French | Add ~60 new i18n keys to fr.json under `sca.answerKey.*`; follow established `t()` function pattern |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Express.js | 4.18.x | Route handlers, middleware | Already in use; all routes follow this pattern |
| EJS | 3.1.x | Server-side template rendering | All 25+ templates use EJS; no client-side framework |
| i18n (custom) | N/A | `t()` and `localize()` from `utils/i18n.js` | Established translation system with ~136 keys; `fr.json` / `en.json` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `requireAuth` middleware | N/A | Verify user is logged in | Every protected route |
| `requireRole` middleware | N/A | Restrict by role array | Instructor-only routes (AKEY-04) |
| Prism.js (vendored) | 1.30.0 | Syntax highlighting in code snippets | If answer key page shows code snippets (optional) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| i18n keys for answer content | Hardcoded French strings in template | i18n keys maintain consistency and support potential future EN fallback; hardcoded strings are simpler but break the convention |
| Separate answer key route | Query param on existing instructor page | Separate route is cleaner, more bookmarkable, and easier to role-gate |

**Installation:**
```bash
# No new dependencies needed -- everything is already in the project
```

## Architecture Patterns

### Recommended Project Structure
```
routes/
  sca.js              # Add GET /sca/answer-key route (+ modify GET /sca/findings/:id)
views/sca/
  answer-key.ejs       # NEW: standalone answer key page
  finding-detail.ejs   # MODIFY: add inline collapsible answer section
  instructor.ejs       # MODIFY: add link to answer key page
config/translations/
  fr.json              # ADD: ~60 keys under sca.answerKey.*
  en.json              # ADD: ~60 keys under sca.answerKey.* (English equivalents)
```

### Pattern 1: Role-Gated Route Handler
**What:** Use `requireRole` middleware to deny access at the handler level, not just hide UI elements.
**When to use:** Every instructor-only endpoint (AKEY-04 success criterion).
**Example:**
```javascript
// Source: routes/sca.js lines 108, 214, 236 (existing patterns)
router.get('/answer-key', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  const lang = req.session.language || 'fr';
  const findings = db.prepare('SELECT * FROM sca_findings').all();
  const localizedFindings = findings.map(f => localize(f, lang));

  res.render('sca/answer-key', {
    title: t(lang, 'sca.answerKey.title'),
    findings: localizedFindings,
    needsPrism: false  // code snippets optional on this page
  });
});
```

### Pattern 2: Conditional Data Passing for Inline Answer (AKEY-05)
**What:** Pass answer key data to template only for instructor roles, preventing student access at the data level.
**When to use:** The shared `/sca/findings/:id` route where both students and instructors see the same page.
**Example:**
```javascript
// Source: routes/sca.js line 139 (existing finding-detail route)
router.get('/findings/:id', requireAuth, (req, res) => {
  // ... existing code ...
  const lang = req.session.language || 'fr';

  // Only pass answer key data for instructors
  let answerKey = null;
  if (user.role !== 'student') {
    answerKey = {
      classification: t(lang, `sca.answerKey.${finding.id}.classification`),
      reasoning: t(lang, `sca.answerKey.${finding.id}.reasoning`),
      discussion: t(lang, `sca.answerKey.${finding.id}.discussion`)
    };
  }

  res.render('sca/finding-detail', {
    // ... existing locals ...
    answerKey  // null for students, populated for instructors
  });
});
```

### Pattern 3: Collapsible Section in EJS
**What:** A `<details>/<summary>` HTML element that the instructor can expand/collapse, wrapped in a role check.
**When to use:** Inline answer key on finding detail page (AKEY-05).
**Example:**
```ejs
<%# This block is NOT rendered for students -- it doesn't appear in page source %>
<% if (user.role !== 'student' && answerKey) { %>
<div class="card" style="margin-top:1rem; border-left:4px solid #002855;">
  <details>
    <summary style="cursor:pointer; font-weight:600; color:#002855;">
      <%= t('sca.answerKey.inlineTitle') %>
    </summary>
    <div style="margin-top:0.75rem;">
      <p><strong><%= t('sca.answerKey.expectedClassification') %> :</strong>
        <span class="badge-sm cls-confirmed"><%= answerKey.classification %></span>
      </p>
      <p style="margin-top:0.5rem;"><strong><%= t('sca.answerKey.reasoning') %> :</strong> <%= answerKey.reasoning %></p>
      <p style="margin-top:0.5rem;"><strong><%= t('sca.answerKey.discussionPrompt') %> :</strong> <%= answerKey.discussion %></p>
    </div>
  </details>
</div>
<% } %>
```

### Pattern 4: i18n Key Structure for Answer Key Content
**What:** Nested translation keys under `sca.answerKey` following the existing `sca.findings` pattern.
**When to use:** All answer key text content (AKEY-06).
**Example:**
```json
{
  "sca": {
    "answerKey": {
      "title": "Corrige - Analyse de code statique",
      "subtitle": "Classification attendue, raisonnement et pistes de discussion pour les 12 constats",
      "expectedClassification": "Classification attendue",
      "reasoning": "Raisonnement",
      "discussionPrompt": "Piste de discussion",
      "inlineTitle": "Reponse attendue (instructeur)",
      "confirmed": "Vrai positif (confirme)",
      "needsInvestigation": "Necessite une investigation",
      "1": {
        "classification": "Vrai positif (confirme)",
        "reasoning": "Le secret de session est code en dur...",
        "discussion": "Demandez aux etudiants : que se passerait-il si..."
      }
    }
  }
}
```

### Pattern 5: Dashboard Link Placement
**What:** Add an answer key link to the SCA instructor dashboard.
**When to use:** Discoverability requirement (success criterion 4).
**Example:**
```ejs
<%# In views/sca/instructor.ejs, add a button/link near the page header %>
<a href="/sca/answer-key" class="btn btn-primary" style="font-size:0.85rem;">
  <%= t('sca.answerKey.linkLabel') %>
</a>
```

### Anti-Patterns to Avoid
- **CSS-only hiding for security:** NEVER use `display:none` or `visibility:hidden` to "hide" answer key content from students. Students can inspect page source and see the answers. The EJS `<% if %>` block must prevent the HTML from being rendered at all.
- **Client-side role checks:** NEVER rely on JavaScript to show/hide answer data. The server must not send the data to students in the first place.
- **Separate answer key database table:** The 12 findings are fixed teaching content. The answer key data belongs in the i18n translation files alongside the existing finding translations, not in a separate database table.
- **Hardcoded French strings in templates:** All text must go through the `t()` function for consistency with the established pattern, even though all users speak French.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Role-based access control | Custom role checking logic | `requireRole(['admin', 'professor'])` middleware | Already handles RBAC bypass when disabled, audit logging of denied access, proper 403 response |
| Translation/i18n | Inline French strings | `t(lang, key)` function with fr.json keys | Established pattern, English fallback, parameter interpolation support |
| Collapsible sections | Custom JS toggle | HTML `<details>/<summary>` element | Native browser support, no JS needed, accessible, already used in instructor.ejs (line 25 of instructor.ejs) |
| Finding data retrieval | New database queries | Existing `db.prepare('SELECT * FROM sca_findings').all()` | Same query pattern used in all SCA routes |

**Key insight:** Phase 7 requires zero new libraries, zero new database tables, and zero new middleware. Every technical component already exists in the codebase. The work is content creation (answer key text in French) and template/route assembly using established patterns.

## Common Pitfalls

### Pitfall 1: Answer Key Visible in Student Page Source (CRITICAL)
**What goes wrong:** Developer uses `display:none` CSS to hide the answer section, or renders it in EJS but wraps it in a hidden div. Students inspect page source and find all answers.
**Why it happens:** Natural instinct is to show/hide with CSS. The distinction between "not visible" and "not in the DOM" is easy to miss.
**How to avoid:** Use EJS `<% if (user.role !== 'student' && answerKey) { %>` to prevent the HTML from being generated. Pass `answerKey = null` for students in the route handler. Double protection: data-level (route) + template-level (EJS conditional).
**Warning signs:** If you see `style="display:none"` wrapping answer content, it's wrong.

### Pitfall 2: RBAC Bypass Mode Leaking Answer Key
**What goes wrong:** When RBAC is disabled via the security panel, the `requireRole` middleware allows all users through (including students). A student navigating to `/sca/answer-key` would see the answer key.
**Why it happens:** The `requireRole` middleware has an intentional RBAC bypass mode (see `middleware/rbac.js` line 13: `if (!req.securitySettings.rbac_enabled) { req.rbacBypass = true; return next(); }`). This is a teaching tool for demonstrating what happens without RBAC.
**How to avoid:** For the answer key route specifically, add a secondary check inside the route handler: `if (req.session.user.role === 'student') return res.status(403)...` even when RBAC is bypassed. The answer key should NEVER be visible to students regardless of RBAC toggle state.
**Warning signs:** Test the route with RBAC disabled while logged in as a student.

### Pitfall 3: Missing i18n Key Fallback
**What goes wrong:** A typo in an i18n key path returns the key string itself (e.g., `sca.answerKey.1.reasoning`) instead of the translated text, displayed raw on the page.
**Why it happens:** The `t()` function returns the key path string when translation is not found (line 49 of `utils/i18n.js`).
**How to avoid:** After adding all keys, manually verify every key renders correctly by viewing the answer key page. Use consistent key naming (`sca.answerKey.{findingId}.{field}`).
**Warning signs:** Raw dotted key paths appearing on the rendered page.

### Pitfall 4: Forgetting English Translation File
**What goes wrong:** Keys added to `fr.json` but not `en.json`, causing the English fallback to return key paths.
**Why it happens:** Developer focuses on French (the primary language) and forgets the English file.
**How to avoid:** Always update both `en.json` and `fr.json` in the same commit. The `t()` function falls back to English first (line 43 of `utils/i18n.js`), so English keys must exist.
**Warning signs:** English key paths appearing if someone switches language.

### Pitfall 5: Not Linking from Dashboard
**What goes wrong:** Answer key page exists and works but instructors don't know it's there because there's no link from the instructor dashboard.
**Why it happens:** Developer focuses on the answer key page itself and forgets the discoverability requirement.
**How to avoid:** Success criterion 4 explicitly requires: "Answer key page is linked from the instructor dashboard." Add the link in `views/sca/instructor.ejs`.
**Warning signs:** Instructor has to type `/sca/answer-key` manually.

## Code Examples

Verified patterns from the existing codebase:

### Role-Gated Route with requireRole
```javascript
// Source: routes/sca.js lines 108, 214 (existing patterns)
router.get('/stats', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  // ... only admins and professors reach here ...
});

router.get('/student/:studentId', requireAuth, requireRole(['admin', 'professor']), (req, res) => {
  // ... only admins and professors reach here ...
});
```

### Conditional Rendering by Role in EJS
```ejs
<!-- Source: views/sca/finding-detail.ejs lines 58, 80, 106, 140, 164 -->
<% if (user.role === 'student') { %>
  <!-- student-only content -->
<% } %>

<% if (user.role !== 'student') { %>
  <!-- instructor-only content -->
<% } %>
```

### i18n Translation Function Usage
```ejs
<!-- Source: views/sca/instructor.ejs line 4 -->
<h1 class="page-title"><%= t('sca.instructor.title') %></h1>

<!-- Source: views/sca/finding-detail.ejs line 47 -->
<h3 style="margin-bottom:0.5rem;"><%= t('sca.findingDetail.location') %></h3>
```

### Adding New i18n Keys (following existing pattern)
```json
// Source: config/translations/fr.json lines 336-531 (sca section)
// Existing pattern: sca.findings.{id}.{field}
// New pattern: sca.answerKey.{id}.{field}
{
  "sca": {
    "answerKey": {
      "title": "Corrige - Analyse de code statique",
      "1": {
        "classification": "Vrai positif (confirme)",
        "reasoning": "...",
        "discussion": "..."
      }
    }
  }
}
```

### Localize Function for Finding Data
```javascript
// Source: utils/i18n.js line 92 (existing localize function)
function localize(finding, lang) {
  if (lang === 'en') return finding;
  const fields = ['title', 'description', 'remediation'];
  const localized = { ...finding };
  for (const field of fields) {
    const key = `sca.findings.${finding.id}.${field}`;
    const translated = t(lang, key);
    if (translated !== key) localized[field] = translated;
  }
  return localized;
}
```

## Expected Classifications (Source Data)

All 12 expected classifications from SOLUTION-GUIDE.md (lines 628-641). This is the authoritative source for answer key content:

| # | Title | Expected Classification | Reasoning Summary |
|---|-------|------------------------|-------------------|
| 1 | Hardcoded Session Secret | **Confirmed** | Secret is in source code; anyone with repo access can forge sessions |
| 2 | Hardcoded AES Encryption Key | **Confirmed** | AES key is in source code; compromise exposes all encrypted PII |
| 3 | Plaintext Credentials Logged | **Confirmed** | Passwords appear in console/logs on every login attempt |
| 4 | Plaintext Password Comparison | **Confirmed** | Passwords stored and compared in plaintext; DB breach exposes all |
| 5 | Audit Logging Defaults to OFF | **Confirmed** | Security events go unrecorded; no incident detection possible |
| 6 | IDOR: No Ownership Check | **Confirmed** | Student ID from URL, not session; any student can view others' data |
| 7 | No CSRF Protection | **Confirmed** | No CSRF middleware configured; state-changing requests are forgeable |
| 8 | Rate Limiting Only on Login | **Confirmed** | Other sensitive endpoints (MFA, API) are unprotected |
| 9 | No HTTP Security Headers | **Confirmed** | No helmet middleware; vulnerable to clickjacking and MIME-sniffing |
| 10 | Path Traversal in Backup | **Confirmed** | Filename from URL unsanitized; arbitrary server files readable |
| 11 | Outdated express-session | **Needs Investigation** | Requires `npm audit` to verify if actual CVEs apply |
| 12 | Session Cookie Missing secure | **Confirmed** | `secure: false` in config; session token sent over HTTP |

This data must be translated to Quebec French with detailed reasoning and discussion prompts for each finding.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| No answer key | SOLUTION-GUIDE.md in English | v1.0 (2026-03-12) | Instructor has a markdown reference but no in-app tool |
| English-only classifications | Full French i18n for all SCA content | v1.0 Phase 3 | fr.json has 12 finding translations including hints |
| No inline code | Syntax-highlighted code snippets | v1.1 Phase 6 | Finding detail page now shows actual source code |

**What Phase 7 adds:**
- In-app French answer key (replaces English markdown reference)
- Inline collapsible answers on finding detail pages (replaces mental lookup)
- Pedagogical discussion prompts (new content, not in SOLUTION-GUIDE.md)

## Open Questions

1. **Should the answer key page include code snippets?**
   - What we know: Finding detail pages already have Prism.js-highlighted code. The answer key page is a summary view.
   - What's unclear: Whether instructors want to see code on the answer key page or just classifications + reasoning.
   - Recommendation: Keep the answer key page as a clean summary table (no code). Instructors can click through to individual finding detail pages to see code + inline answer. This keeps the page scannable for in-class facilitation. Set `needsPrism: false` on the answer key route.

2. **How granular should discussion prompts be?**
   - What we know: The existing hints (3 per finding) guide students. Discussion prompts are for the instructor to lead class discussion.
   - What's unclear: Whether prompts should be one-liners or multi-paragraph.
   - Recommendation: One concise discussion question per finding that encourages class-wide debate about real-world implications. Keep it short since the instructor is reading it during live class facilitation.

3. **Where exactly to place the answer key link on the instructor dashboard?**
   - What we know: `views/sca/instructor.ejs` has a page header with title and subtitle stats, then two card sections (findings overview table, student progress matrix).
   - What's unclear: Whether to put it in the header area, as a floating button, or as a new card.
   - Recommendation: Add it as a button in the page header area, next to the title, styled consistently with the HEC navy `btn-primary` pattern. This is immediately discoverable without scrolling.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Custom smoke test (`scripts/smoke-test.js`) |
| Config file | `scripts/smoke-test.js` (monolithic) |
| Quick run command | `npm test` |
| Full suite command | `npm test` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AKEY-01 | Answer key page renders for instructor | smoke | `npm test` (add answer-key page check) | No - Wave 0 |
| AKEY-02 | Reasoning text visible on answer key | manual | Visual verification | N/A |
| AKEY-03 | Discussion prompts visible | manual | Visual verification | N/A |
| AKEY-04 | Student gets 403 on answer key route | smoke | `npm test` (add role-gate check) | No - Wave 0 |
| AKEY-05 | Inline answer visible for instructor, absent for student | manual | Inspect page source as student | N/A |
| AKEY-06 | All text in Quebec French | manual | Visual verification | N/A |

### Sampling Rate
- **Per task commit:** `npm test`
- **Per wave merge:** `npm test`
- **Phase gate:** Full smoke test green + manual verification of all 6 requirements

### Wave 0 Gaps
- [ ] Add answer key page accessibility check to `scripts/smoke-test.js` -- covers AKEY-01
- [ ] Add role-gate denial check (student accessing `/sca/answer-key` gets redirect/403) -- covers AKEY-04

## Sources

### Primary (HIGH confidence)
- `routes/sca.js` -- All existing SCA routing patterns (5 routes, role-gating pattern)
- `middleware/rbac.js` -- `requireRole` implementation with RBAC bypass behavior
- `middleware/auth.js` -- `requireAuth` implementation
- `utils/i18n.js` -- `t()`, `localize()`, `languageMiddleware` implementations
- `config/translations/fr.json` -- 136 existing i18n keys, SCA findings translations
- `config/translations/en.json` -- English equivalents
- `views/sca/finding-detail.ejs` -- Existing finding detail template with role-conditional sections
- `views/sca/instructor.ejs` -- Instructor dashboard layout and patterns
- `SOLUTION-GUIDE.md` lines 628-641 -- Authoritative expected classifications for all 12 findings
- `utils/seedData.js` lines 195-394 -- Complete SCA findings seed data structure

### Secondary (MEDIUM confidence)
- `views/partials/header.ejs` -- Sidebar navigation structure, CSS patterns, Prism.js conditional loading
- Product review (docs/product-review-2026-03-19.md) -- Design context, ratings, future plans

### Tertiary (LOW confidence)
None -- all findings are from direct codebase analysis.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- No new libraries needed; all patterns exist in codebase
- Architecture: HIGH -- Direct extension of existing SCA routing and template patterns
- Pitfalls: HIGH -- RBAC bypass behavior verified in source code; page-source visibility is a well-known web security issue
- Content: HIGH -- SOLUTION-GUIDE.md provides authoritative expected classifications; French translation follows established patterns

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- no external dependencies, all patterns from existing codebase)
