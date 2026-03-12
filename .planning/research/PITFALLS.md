# Domain Pitfalls

**Domain:** Classroom SCA lab deployment -- Codespaces, EJS i18n, non-technical student UX
**Researched:** 2026-03-12
**Context:** 30+ non-technical HEC Montreal students, no TA, tonight's class, SCA module focus

---

## Critical Pitfalls

Mistakes that will break the class or cause significant student frustration.

### Pitfall 1: Zero EJS Templates Use the `t()` Translation Function

**What goes wrong:** The i18n infrastructure exists (`utils/i18n.js`, `fr.json`, `en.json`, `languageMiddleware`) and is loaded on every request. But **zero views** call `t()`. Every single string in every EJS template is hardcoded in English. Simply adding French keys to `fr.json` will not change what students see -- the templates themselves must be modified to call `<%= t('key.path') %>` instead of raw English strings.

**Evidence:** `grep -r "t(" views/` returns zero hits for translation function calls. All 32 EJS files contain raw English strings: "Static Code Analysis Lab", "Submit", "Save Draft", "findings submitted", "Classification", "True Positive (confirmed vulnerability)", etc.

**Why it happens:** The i18n system was built as infrastructure but never wired into templates. The middleware makes `t()` available via `res.locals.t`, but no template author ever replaced hardcoded strings with `t()` calls.

**Consequences:** Students see an entirely English interface despite being French-speaking. For non-technical HEC Montreal students, this creates confusion and disengagement on the very first interaction.

**Prevention:**
1. Replace hardcoded strings in SCA views (`student-lab.ejs`, `finding-detail.ejs`, `instructor.ejs`, `student-detail.ejs`) with `<%= t('sca.keyName') %>` calls
2. Replace hardcoded strings in shared views (`header.ejs`, `login.ejs`, `error.ejs`, `footer.ejs`)
3. Add all corresponding keys to `fr.json` under an `sca` namespace
4. Focus on the student-facing flow first: login -> dashboard -> SCA lab -> finding detail -> review form

**Detection:** Before deploying, search all SCA-path views for any raw English string that is not inside a `t()` call.

**Phase:** Must be addressed in the i18n/translation phase. This is the single most impactful workstream.

**Confidence:** HIGH -- verified by direct codebase grep.

---

### Pitfall 2: Language Defaults to English, Not French

**What goes wrong:** The `languageMiddleware` in `utils/i18n.js` line 75 defaults to English when no session language is set: `const lang = req.session && req.session.language ? req.session.language : 'en'`. New sessions (every student's first visit) will render English even after templates are translated.

**Evidence:** Line 75 of `utils/i18n.js`: `const lang = req.session && req.session.language ? req.session.language : 'en';`. There is no mechanism to set the language to French automatically -- the only way is via `POST /auth/set-language`, which requires a deliberate API call.

**Why it happens:** The system was designed with an English default and optional French, but tonight's class requires the opposite.

**Consequences:** Even after all templates are wired to `t()`, students will see English because no session language is set. The professor would need to instruct 30+ students to manually change their language, which defeats the purpose.

**Prevention:** Change the default on line 75 from `'en'` to `'fr'`:
```javascript
const lang = req.session && req.session.language ? req.session.language : 'fr';
```

**Detection:** Log in as a new user and verify the interface renders in French without any manual language selection.

**Phase:** Must be addressed alongside the i18n template work. Single line change but easy to forget.

**Confidence:** HIGH -- verified by reading source code.

---

### Pitfall 3: `<html lang="en">` Hardcoded in All Layouts

**What goes wrong:** All four HTML entry points (`header.ejs`, `login.ejs`, `error.ejs`, `mfa-verify.ejs`) have `<html lang="en">` hardcoded. Even with French content, screen readers and browser spell-checkers will treat the page as English. More importantly, browser auto-translate features may trigger and create a confusing double-translation.

**Evidence:** `grep 'html lang=' views/` shows four files, all set to `"en"`.

**Prevention:** Change to `<html lang="<%= typeof currentLang !== 'undefined' ? currentLang : 'fr' %>">` in all four files. For `login.ejs` and `error.ejs` (which render outside the authenticated layout), hardcode `lang="fr"` since there is no language toggle and all students are French-speaking.

**Detection:** View page source in browser and verify the `lang` attribute matches the displayed language.

**Phase:** Address during template translation.

**Confidence:** HIGH -- direct file evidence.

---

### Pitfall 4: Codespaces Port Visibility Defaults to Private

**What goes wrong:** All forwarded ports in Codespaces default to "private" visibility. This means only the Codespace owner can access them via GitHub authentication. If the professor starts the classroom manager and 12 team instances, students on other machines **cannot access their team's port** without the professor manually changing each port's visibility.

**Evidence:** GitHub documentation confirms "All forwarded ports are private by default." The `devcontainer.json` specifies `forwardPorts` for ports 3000-3012 but does not set visibility. The `onAutoForward: "silent"` for team ports only controls the VS Code notification, not the port's network accessibility.

**Why it happens:** Codespaces has no `devcontainer.json` property to pre-set port visibility to "public". This must be done manually via the VS Code Ports panel or the `gh codespace ports visibility` CLI command after the Codespace starts.

**Consequences:** Students arrive, click their team URL, and get a 404 or authentication wall. Class time is wasted troubleshooting access. With 13 ports (dashboard + 12 teams), manually changing visibility takes significant time.

**Prevention:**
1. Add a post-start script or README instruction to run:
   ```bash
   gh codespace ports visibility 3000:public 3001:public 3002:public 3003:public 3004:public 3005:public 3006:public 3007:public 3008:public 3009:public 3010:public 3011:public 3012:public -c $CODESPACE_NAME
   ```
2. Alternatively, use `portsAttributes` with organization-level policies that allow public ports
3. Document this step prominently in the instructor setup checklist
4. Test from a different browser/incognito window before class to verify access

**Detection:** After launching, open a team URL in an incognito/private window (not signed into GitHub). If you get a login wall, ports are still private.

**Phase:** Must be verified during Codespaces setup/verification phase.

**Confidence:** HIGH -- confirmed by GitHub documentation.

---

### Pitfall 5: Codespaces Session Cookies Fail with Secure Flag + Port Forwarding

**What goes wrong:** The `server.js` session configuration (line 51) sets `secure: !!startupSecuritySettings.https_enabled`. If HTTPS is enabled in the security settings, the `secure` cookie flag is set. Codespaces port forwarding uses HTTPS on the external URL but proxies to HTTP internally. If a student or the instructor toggles HTTPS in the security panel and restarts, cookies may stop working -- the internal server sees HTTP but the cookie has `secure: true`, causing sessions to silently fail. Students click "Login" and get bounced back to the login page with no error.

**Evidence:** `server.js` line 44-53 shows the session cookie `secure` flag is set at startup based on the security settings database value. The `trust proxy` setting is not configured in Express, which means Express will not honor the `X-Forwarded-Proto` header from Codespaces' reverse proxy.

**Why it happens:** Codespaces adds an HTTPS reverse proxy in front of your HTTP server. Without `app.set('trust proxy', 1)`, Express does not know the original request was HTTPS, so `secure` cookies may behave unpredictably.

**Consequences:** Login appears to work (POST succeeds) but the session cookie is not stored by the browser, so the user is immediately redirected back to login. This is extremely confusing for non-technical students who will assume the credentials are wrong.

**Prevention:**
1. Ensure HTTPS is NOT enabled in the security settings for classroom use (it is off by default -- do not toggle it)
2. Consider adding `app.set('trust proxy', 1)` if Codespaces use is expected
3. Test login flow in the actual Codespaces environment before class, not just locally

**Detection:** After deploying to Codespaces, log in and verify you reach the dashboard. Check that the session cookie exists in browser DevTools > Application > Cookies.

**Phase:** Codespaces verification phase.

**Confidence:** MEDIUM -- based on known Express/Codespaces proxy behavior; exact impact depends on security settings state at boot.

---

### Pitfall 6: SCA Seed Data Is English-Only

**What goes wrong:** The 12 SCA findings seeded in `utils/seedData.js` have English titles, descriptions, remediation text, and code snippet context. Even if the UI chrome is translated to French, the actual content students analyze -- finding titles like "Hardcoded Session Secret", descriptions like "The Express session secret is hardcoded in source code" -- remains in English.

**Evidence:** `seedData.js` lines 179-251 contain all 12 SCA findings with hardcoded English strings for title, description, remediation, and false_positive_reason fields.

**Why it happens:** Seed data was written once in English. The i18n system only covers UI strings in `fr.json`, not database content.

**Consequences:** Students see a French UI wrapper around English security analysis content. This creates a jarring bilingual experience. For non-technical students, the English security terminology (CWE descriptions, remediation guidance) may be difficult to parse.

**Prevention:**
1. Translate the seed data fields (title, description, remediation) to French directly in `seedData.js`
2. Keep technical terms (CWE numbers, file paths, code snippets) in English as these are universal
3. Alternatively, add a `description_fr` / `remediation_fr` column and use the language setting to choose which to display -- but this is more complex and risky for tonight

**Detection:** After seeding, open the SCA student lab and verify finding titles and descriptions are in French.

**Phase:** Seed data enhancement phase. This is high-impact because students spend most of their time reading finding content, not UI chrome.

**Confidence:** HIGH -- direct file evidence.

---

## Moderate Pitfalls

Issues that cause friction or confusion but have workarounds.

### Pitfall 7: Login Page Hardcoded English with No Translation Hooks

**What goes wrong:** The `login.ejs` is a standalone HTML page (not using the `header.ejs` partial) with its own `<html>`, `<head>`, and `<body>` tags. All text is hardcoded: "HEC Montreal", "Application Security Learning Platform", "Username", "Password", "Login", "Default Accounts", "Login Failed". Even if `header.ejs` and other partials are translated, the login page -- the very first thing students see -- remains English.

**Evidence:** `login.ejs` does not include any partials and does not use `t()`. It is a self-contained HTML file.

**Prevention:** Either:
1. Rewrite `login.ejs` to use `t()` calls (the middleware runs before rendering, so `t` is available even on unauthenticated routes)
2. Or simply replace the English strings directly with French strings in the template (simpler, since there will be no language toggle)

**Detection:** Load the login page and verify all text is French.

**Phase:** Template translation phase -- should be the first view translated since it is the first thing students see.

---

### Pitfall 8: Error Page Displays English Errors from Routes

**What goes wrong:** The `error.ejs` template displays `<%= message %>` which comes from route handlers. Throughout `routes/sca.js` and other route files, error messages are hardcoded in English: `'Finding not found'`, `'Student not found'`, `'Invalid classification'`. Even with a translated error page UI, the error message body will be English.

**Evidence:** `routes/sca.js` line 92: `res.status(404).render('error', { message: 'Finding not found', error: { status: 404 } })`. Similar patterns in `routes/auth.js` line 28: `res.render('login', { error: 'Invalid username or password' })`.

**Prevention:** Replace route-level error strings with `t()` calls:
```javascript
res.render('login', { error: req.res.locals.t('auth.invalidCredentials') });
```
Or since the `t` function is available via the i18n module directly:
```javascript
const { t } = require('../utils/i18n');
// Then in route: t('fr', 'auth.invalidCredentials')
```

**Detection:** Trigger a 404 or login error and verify the message appears in French.

**Phase:** Error handling polish phase.

---

### Pitfall 9: Hardcoded English in JavaScript Alert/Confirm Dialogs

**What goes wrong:** The SCA views contain JavaScript `alert()`, `confirm()`, and inline message strings in English. Examples from `finding-detail.ejs`: `confirm('Push "<%= finding.title %>" to the Vulnerability Manager?')`, `alert('Imported to VM! Reloading...')`, `alert('Network error')`. From `student-lab.ejs`: `msg.textContent = 'Saving...'`, `msg.textContent = 'Network error - please try again.'`.

**Evidence:** Multiple `alert()` and `confirm()` calls in SCA view JavaScript blocks, all with English strings.

**Prevention:**
1. Replace inline strings with data attributes or a `window.__translations` object populated from server-side `t()` calls
2. Or simply hardcode French strings in the JavaScript since there is no language toggle
3. Focus on student-facing views first: `student-lab.ejs` feedback messages ("Saving...", "Submitted!", "Draft saved.", "Network error")

**Detection:** Perform a save/submit action in the SCA lab and verify feedback messages appear in French.

**Phase:** Template translation phase -- easy to miss because these strings are in `<script>` blocks, not in the HTML body.

---

### Pitfall 10: Sidebar Navigation Labels Are Hardcoded English

**What goes wrong:** The `header.ejs` sidebar navigation contains hardcoded English labels: "Dashboard", "Classes", "Security Panel", "Audit Logs", "MFA Setup", "Backups", "My Classes", "My Enrollments", "Static Analysis", "Dynamic Analysis", "Vuln Management", "Pentest Lab", "Security Labs", "Main", "Administration", "Teaching", "Learning", "Logout", "Security Status".

**Evidence:** `header.ejs` lines 459-541 contain approximately 25+ hardcoded English navigation strings.

**Prevention:** Replace each with `<%= t('nav.keyName') %>` or `<%= t('common.keyName') %>` calls. Add corresponding keys to `fr.json`. Some keys already exist in `fr.json` (e.g., `nav.security`, `nav.auditLogs`, `nav.classes`) but many are missing (e.g., "Security Labs", "Static Analysis", "Learning", "Logout").

**Detection:** Log in and check every sidebar label is in French.

**Phase:** Template translation phase.

---

### Pitfall 11: npm install Slow on First Codespace Boot

**What goes wrong:** The `devcontainer.json` runs `npm install && node scripts/setup.js` as `postCreateCommand`. The `npm install` step installs `bcrypt` (which requires native compilation), `selfsigned`, and other dependencies. On first Codespace creation, this can take 2-5 minutes. Combined with the container image pull, total boot time can exceed 5-10 minutes. If the professor starts the Codespace at class start rather than pre-warming it, students wait with nothing to do.

**Evidence:** `devcontainer.json` postCreateCommand: `"npm install && node scripts/setup.js"`. `bcrypt` in `package.json` requires native bindings compilation, which is the slowest part.

**Prevention:**
1. Create the Codespace **before** class (at least 30 minutes ahead) to ensure `postCreateCommand` has completed
2. Verify the Codespace is fully booted by checking the terminal output for "Setup completed successfully!"
3. Run `npm start` manually and verify all 12 instances come online before sharing URLs with students
4. Consider pre-building: run `npm install` once and commit `node_modules` or use a Codespaces prebuild configuration

**Detection:** Check the Codespace terminal for setup completion messages. Run `npm test` (smoke test) to verify.

**Phase:** Codespaces verification phase -- pre-class setup checklist.

---

### Pitfall 12: autoResetOnStart Is False -- Stale Data on Restart

**What goes wrong:** `classroom.config.json` has `"autoResetOnStart": false`. If the professor stops and restarts the classroom manager (e.g., after a code change), all team instances retain their previous database state. This means student data from a previous test run or debugging session persists, creating confusing stale state for the actual class.

**Evidence:** `classroom.config.json` line 11: `"autoResetOnStart": false`. The `classroom-manager.js` line 935-940 checks this flag and only wipes instance data when true.

**Prevention:**
1. Set `"autoResetOnStart": true` before tonight's class so each restart gives fresh seeded databases
2. Alternatively, use the dashboard's "Reset All Instances" button before class starts
3. After making code changes, restart with auto-reset to ensure students get the French translations from the updated seed data

**Detection:** After restarting the classroom manager, log into a team instance and verify the database has fresh seed data (check that no previous student reviews exist).

**Phase:** Pre-class configuration.

---

## Minor Pitfalls

### Pitfall 13: Security Status Bar Shows English Labels

**What goes wrong:** The security status bar in `header.ejs` (lines 548-571) shows badges like "MFA: ON", "RBAC: OFF", "Passwords: Encrypted", "Data: Plaintext", "HTTPS", "Logging: ON", "Rate Limit: ON". These are hardcoded English strings even though `fr.json` already has translations for these concepts under `security.status` and `security.panel`.

**Prevention:** Replace with `t()` calls using the existing `security.status.on`/`security.status.off` keys.

---

### Pitfall 14: "Application Security" Subtitle in Header Is English

**What goes wrong:** The sidebar header in `header.ejs` line 452 says `"Application Security"` as a subtitle. This should be "Securite applicative" or "Securite des applications" for French-speaking students.

**Prevention:** Replace with a `t()` call or hardcode the French string.

---

### Pitfall 15: Login Page Shows English Demo Account Instructions

**What goes wrong:** `login.ejs` shows "Default Accounts:" with English labels "Admin:", "Professor:", "Student:" and the credential pairs. Non-technical students may not understand these are the accounts they should use.

**Prevention:** Translate the "Default Accounts" section to French. Consider renaming to "Comptes de demonstration" with clearer instructions like "Utilisez ces identifiants pour vous connecter:".

---

### Pitfall 16: Date Formatting Uses English Locale

**What goes wrong:** `server.js` line 68 defines `formatDate` using `new Date(dateStr).toLocaleString()` which defaults to the server's locale (likely `en-US` in a Codespaces container). Dates will appear as "3/12/2026, 7:30:00 PM" instead of the French format "12/03/2026 a 19h30".

**Prevention:** Pass the locale explicitly: `d.toLocaleString('fr-CA')` for Quebec French date formatting.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| i18n translation | Templates do not use `t()` at all (Pitfall 1) | Must rewrite templates, not just add JSON keys |
| i18n translation | Language defaults to English (Pitfall 2) | Change one line in `utils/i18n.js` |
| i18n translation | `<html lang="en">` hardcoded (Pitfall 3) | Update 4 files |
| i18n translation | JS alert/confirm strings are English (Pitfall 9) | Must translate script blocks too |
| i18n translation | Login page is standalone, not using partials (Pitfall 7) | Separate translation effort from main views |
| Seed data enhancement | SCA findings are English content (Pitfall 6) | Translate seedData.js fields |
| Codespaces verification | Port visibility defaults private (Pitfall 4) | Must run `gh codespace ports visibility` command |
| Codespaces verification | Session cookies + proxy (Pitfall 5) | Do not enable HTTPS in security panel |
| Codespaces verification | Slow first boot (Pitfall 11) | Pre-warm Codespace 30+ min before class |
| Pre-class configuration | autoResetOnStart is false (Pitfall 12) | Set to true before deploying |
| Error handling | Route error messages are English (Pitfall 8) | Translate error strings in route handlers |
| UX polish | Date formatting is English locale (Pitfall 16) | Pass `fr-CA` locale to `toLocaleString()` |

## Priority Ranking for Tonight

Given the time pressure (class is tonight), pitfalls should be addressed in this order:

1. **Pitfall 1 + 2 + 3** (i18n wiring) -- Without this, nothing displays in French. Highest impact.
2. **Pitfall 6** (seed data) -- Students spend 90% of their time reading finding content, not UI chrome.
3. **Pitfall 7** (login page) -- First impression; sets the tone.
4. **Pitfall 4** (port visibility) -- Without this, students literally cannot access the app.
5. **Pitfall 12** (autoResetOnStart) -- One config line, prevents stale data.
6. **Pitfall 10** (sidebar navigation) -- Visible throughout the session.
7. **Pitfall 9** (JS feedback messages) -- Students see these during the core workflow.
8. **Pitfall 5** (session cookies) -- Risk mitigation; just avoid enabling HTTPS.
9. **Pitfalls 13-16** (minor polish) -- Nice to have but not blocking.

## Sources

- GitHub Codespaces port forwarding documentation: https://docs.github.com/en/codespaces/developing-in-a-codespace/forwarding-ports-in-your-codespace
- GitHub Codespaces port visibility restriction: https://docs.github.com/en/codespaces/managing-codespaces-for-your-organization/restricting-the-visibility-of-forwarded-ports
- Port forwarding troubleshooting: https://docs.github.com/en/codespaces/troubleshooting/troubleshooting-port-forwarding-for-github-codespaces
- Codespaces port visibility first boot issue: https://github.com/orgs/community/discussions/156546
- GitHub Classroom Codespaces FAQ: https://github.com/orgs/community/discussions/145312
- Express-session secure cookie issue: https://github.com/expressjs/session/issues/983
- EJS variable undefined errors: https://github.com/tj/ejs/issues/232
- Direct codebase analysis of all files listed above (HIGH confidence)
