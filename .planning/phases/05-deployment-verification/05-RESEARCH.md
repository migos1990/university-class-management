# Phase 5: Deployment Verification - Research

**Researched:** 2026-03-12
**Domain:** GitHub Codespaces configuration, port visibility, smoke testing, first-boot hardening
**Confidence:** HIGH

## Summary

Phase 5 is a configuration and verification phase -- no new features, only changes to configuration files, security defaults, and the creation of a comprehensive smoke test. The three requirements (DEPL-01, DEPL-02, DEPL-03) cover first-boot reliability, end-to-end student journey verification, and port visibility for student access.

The most critical discovery is that **port visibility cannot be set declaratively in devcontainer.json**. The `portsAttributes` specification does not include a `visibility` property. Port visibility must be set using the `gh codespace ports visibility` CLI command, which can be automated via `postAttachCommand` in devcontainer.json. This is a departure from the CONTEXT.md decision which assumed adding `"visibility": "public"` to portsAttributes would work.

The existing codebase already has `https_enabled: 0` as the default in `config/database.js`, but `encryption_at_rest` defaults to `0` and needs to be changed to `1` per the user's safe-defaults decision. The HTTPS toggle in the admin security panel needs to be disabled to prevent students from accidentally enabling HTTPS (which breaks Codespaces proxy). The existing `smoke-test.js` provides a solid foundation with login/session cookie handling already implemented -- it needs to be rewritten to test all 13 ports, verify French content, and check the stats endpoint.

**Primary recommendation:** Split into two plans: (1) configuration hardening (devcontainer.json, classroom.config.json, security defaults, HTTPS toggle disable) and (2) comprehensive smoke test rewrite.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Set all ports (3000-3012) to public visibility -- students access URLs shared by instructor from classroom-manager output
- Each team shares one set of demo credentials (alice_student/student123, prof_jones/prof123) -- no per-student accounts
- No changes to authentication or credential seeding
- Flip `autoResetOnStart` to `true` in classroom.config.json
- Disable the HTTPS toggle in the security panel -- Codespaces provides HTTPS via proxy
- Keep full auto-start flow: postCreateCommand (npm install + setup.js) then postStartCommand (npm start)
- Hardcode safe security defaults in seed data: https_enabled=false, rbac_enabled=true, encryption_at_rest=true, mfa_enabled=false
- Extend or replace existing smoke-test.js with comprehensive HTTP-level verification
- Test ALL 13 ports (3000 dashboard + 3001-3012 team instances)
- Verify each instance responds with 200 status
- Check key French phrases per page type: Login "Connexion", SCA lab "Analyse statique", Finding detail "Classification", Dashboard "Etudiants"
- Verify GET /sca/stats returns valid JSON with studentsStarted, totalStudents, avgCompletion, pace fields
- No browser automation (Puppeteer/Playwright) -- HTTP requests only, no new dependencies
- Emoji pass/fail output: checkmarks with team names and port numbers
- Final summary line: X/13 passed
- Smoke test IS the pre-class checklist -- run `npm test`, all green = ready for class
- If some instances fail: reduce TEAM_COUNT env var, redistribute students

### Claude's Discretion
- Exact HTTP request flow for verifying login + SCA routes (cookie handling for authenticated routes)
- Whether to test one instance deeply (login -> SCA lab -> finding detail -> stats) and the rest with just health checks, or test all 13 at the same depth
- Exact French phrases to check for on each page (within the key phrases listed above)
- How to handle the HTTPS toggle disable (seed data override, middleware guard, or UI-level disable)
- Timeout thresholds and retry logic in the smoke test

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DEPL-01 | Codespaces first-boot works cleanly (seeding, SSL, all team instances start) | autoResetOnStart flip, security defaults hardening, HTTPS toggle disable, devcontainer lifecycle commands |
| DEPL-02 | End-to-end student journey verified (login -> SCA lab -> review finding -> save draft -> submit -> instructor sees submission) | Smoke test with cookie-based HTTP flow, French content verification, stats endpoint check |
| DEPL-03 | Codespaces port visibility configured for student access | gh CLI port visibility command in postAttachCommand (NOT portsAttributes -- see pitfall below) |
</phase_requirements>

## Architecture Patterns

### Configuration Changes Map

```
classroom.config.json           -- autoResetOnStart: false -> true
config/database.js:19           -- encryption_at_rest: 0 -> 1  (in default security_settings)
config/database.js:1087         -- encryption_at_rest: 0 -> 1  (in initializeDatabase fallback)
config/security.js:20           -- encryption_at_rest: 0 -> 1  (in getSecuritySettings fallback)
.devcontainer/devcontainer.json -- add postAttachCommand for port visibility
views/admin/security-panel.ejs  -- disable HTTPS toggle (checkbox + handler)
routes/admin.js:35              -- guard against https_enabled toggle via API
scripts/smoke-test.js           -- rewrite with comprehensive 13-port verification
```

### Pattern 1: Port Visibility via gh CLI in postAttachCommand
**What:** Use `gh codespace ports visibility` in devcontainer.json `postAttachCommand` to set all ports public
**When to use:** Every Codespace start (postAttachCommand runs each time VS Code attaches)
**Why postAttachCommand, not postStartCommand:** postStartCommand is already used for `npm start`. Using postAttachCommand ensures ports are visible after the forwarding is established. The `gh` CLI is pre-installed in Codespaces images.

```json
{
  "postAttachCommand": "gh codespace ports visibility 3000:public 3001:public 3002:public 3003:public 3004:public 3005:public 3006:public 3007:public 3008:public 3009:public 3010:public 3011:public 3012:public -c $CODESPACE_NAME"
}
```

**Alternative (more robust script approach):**
```bash
#!/bin/bash
# .devcontainer/set-ports-public.sh
if [ -n "$CODESPACE_NAME" ]; then
  PORTS=""
  for p in $(seq 3000 3012); do
    PORTS="$PORTS $p:public"
  done
  gh codespace ports visibility $PORTS -c "$CODESPACE_NAME" 2>/dev/null || true
fi
```

### Pattern 2: HTTPS Toggle Disable (Recommended Approach: Multi-Layer)
**What:** Prevent HTTPS from being enabled in the Codespaces environment
**Approach:** Three layers of protection:
1. **Seed data**: `https_enabled: 0` is already the default -- no change needed here
2. **API guard**: In `routes/admin.js`, reject the `https_enabled` toggle with a message explaining why
3. **UI disable**: In `views/admin/security-panel.ejs`, disable the HTTPS checkbox and add explanatory text

**Recommendation:** Use both API guard and UI disable. The API guard is the safety net; the UI disable gives clear feedback. Do NOT just hide the toggle -- add a disabled state with tooltip explaining "HTTPS is managed by Codespaces proxy."

### Pattern 3: Smoke Test HTTP Flow (Cookie-Based)
**What:** Test authenticated routes using HTTP requests with session cookie forwarding
**Flow:**
1. GET `/` on port 300X -- verify 200 and "Connexion" in body (French login page)
2. POST `/auth/login` with `alice_student/student123` -- capture `connect.sid` cookie from 302 response
3. GET `/sca` with cookie -- verify 200 and "Analyse statique" in body (French SCA lab)
4. GET `/sca/findings/1` with cookie -- verify 200 and "Classification" in body (finding detail)
5. GET `/sca/stats` on port 3000 (dashboard) -- requires prof login, verify JSON shape

**Existing code reuse:** The current `smoke-test.js` already has `request()`, `getSessionCookie()`, and `testLogin()` functions that handle the HTTP request/cookie extraction pattern. The rewrite should preserve this pattern.

### Pattern 4: Test Depth Strategy (Recommended)
**What:** Deep test one instance, health-check the rest
**Reasoning:** Testing all 13 instances at full depth (login + navigate + verify French) would take significantly longer and provides diminishing returns since all instances run identical code. One deep test proves the code works; health checks prove all instances started.

**Recommended structure:**
- **All 13 ports**: GET `/health` -- verify 200 + JSON response (proves instance is up)
- **All 13 ports**: GET `/` -- verify 200 + "Connexion" in body (proves French login renders)
- **One instance (3001)**: Full authenticated flow (login -> SCA lab -> finding detail -> draft save -> submit)
- **Dashboard (3000)**: GET `/sca/stats` with prof credentials -- verify JSON shape

### Anti-Patterns to Avoid
- **Never add `"visibility": "public"` to devcontainer.json portsAttributes** -- this is not a valid property in the devcontainer spec and will be silently ignored
- **Never use Puppeteer/Playwright** -- adds npm dependencies, violates project constraint
- **Never test over HTTPS URLs** -- the smoke test runs locally inside the Codespace, so it should use `http://localhost:PORT`, not the Codespaces proxy URLs
- **Never skip the API guard for HTTPS** -- UI-only protection can be bypassed via DevTools or direct API call

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Port visibility | Custom proxy or network config | `gh codespace ports visibility` CLI | Only supported method; pre-installed in Codespaces |
| HTTP client for tests | External npm package (axios, got, node-fetch) | Node.js built-in `http` module | No new dependencies constraint; existing smoke-test.js already uses it |
| Cookie parsing | Custom regex parsing | Existing `getSessionCookie()` in smoke-test.js | Already handles `connect.sid` extraction from `set-cookie` header |

## Common Pitfalls

### Pitfall 1: portsAttributes "visibility" Is Not a Valid Property
**What goes wrong:** Adding `"visibility": "public"` to devcontainer.json portsAttributes -- it gets silently ignored and ports remain private
**Why it happens:** Many tutorials and Stack Overflow answers suggest this property exists, but it is NOT part of the devcontainer specification (verified against official spec at containers.dev)
**How to avoid:** Use `gh codespace ports visibility` CLI command in a lifecycle hook
**Warning signs:** Ports show as "Private" in the Codespaces Ports tab despite the devcontainer.json setting
**Confidence:** HIGH -- verified against official devcontainer JSON reference

### Pitfall 2: HTTPS Breaks Codespaces Proxy
**What goes wrong:** If a student (or the instructor testing) enables HTTPS in the security panel, the app starts listening on port 3443 instead of the configured port, AND sets `secure: true` on session cookies. The Codespaces proxy forwards traffic to the original port, so:
- The HTTP redirect on the original port sends browsers to `https://localhost:3443` which doesn't exist in the proxy
- Even if traffic somehow reaches the HTTPS listener, the self-signed cert conflicts with the Codespaces proxy SSL termination
- Session cookies with `secure: true` may not be sent properly through the proxy chain
**Why it happens:** `server.js` line 264 checks `securitySettings.https_enabled` and starts an HTTPS server on port 3443 instead of the normal port
**How to avoid:** Disable the HTTPS toggle at both the API and UI level
**Warning signs:** "Connection refused" or redirect loops when accessing team URLs through the Codespaces proxy
**Confidence:** HIGH -- verified by reading server.js startup logic

### Pitfall 3: autoResetOnStart Must Be Paired with Fresh Seed Data
**What goes wrong:** Setting `autoResetOnStart: true` deletes `data.json` files but doesn't guarantee correct security defaults because defaults come from `config/database.js` initialization code
**Why it happens:** The classroom-manager deletes DB files; then server.js calls `initializeDatabase()` + `seedDatabase()` on the empty state. The defaults in `config/database.js` are what matter.
**How to avoid:** Ensure `config/database.js` default `security_settings` has the correct values: `https_enabled: 0, rbac_enabled: 1, encryption_at_rest: 1, mfa_enabled: 0`
**Warning signs:** Encryption not enabled after fresh start; or HTTPS mysteriously enabled
**Confidence:** HIGH -- traced the exact code path

### Pitfall 4: Smoke Test Race Condition on Startup
**What goes wrong:** Running `npm test` immediately after `npm start` -- instances haven't finished booting yet
**Why it happens:** classroom-manager spawns instances asynchronously; they take several seconds to initialize DB and start listening
**How to avoid:** The smoke test should implement a startup wait/retry: poll `/health` with timeouts before running deep checks. The existing classroom-manager already polls health every 30s.
**Warning signs:** ECONNREFUSED errors in smoke test output
**Confidence:** HIGH -- standard issue with multi-process startup
**Recommended timeout:** 5 seconds per-request, with 3 retries at 2-second intervals for the initial health check

### Pitfall 5: Cookie Domain Mismatch in Smoke Test
**What goes wrong:** The smoke test makes requests to `localhost:PORT` but cookies might have domain or path restrictions
**Why it happens:** Express-session by default doesn't set an explicit domain on cookies, which means they're scoped to the exact origin
**How to avoid:** The existing smoke-test.js already handles this correctly by extracting `connect.sid` from `set-cookie` headers and sending it back in the `Cookie` header. Maintain this pattern.
**Confidence:** HIGH -- verified in existing code

### Pitfall 6: Organization Policy May Block Public Ports
**What goes wrong:** The `gh codespace ports visibility` command fails silently or returns an error if the GitHub organization has a policy restricting port visibility to "private" or "org" only
**Why it happens:** Organization owners can create policies that prevent public port forwarding
**How to avoid:** The port visibility script should use `|| true` to avoid breaking the startup flow. Document that the organization must allow public ports, or use "org" visibility if the students are in the same GitHub org.
**Warning signs:** `gh` command exits with non-zero code; ports remain private
**Confidence:** MEDIUM -- depends on the specific GitHub org configuration for HEC Montreal

## Code Examples

### Example 1: devcontainer.json with Port Visibility Automation
```json
{
  "name": "University Class Management",
  "image": "mcr.microsoft.com/devcontainers/javascript-node:22",
  "postCreateCommand": "npm install && node scripts/setup.js",
  "postStartCommand": "npm start",
  "postAttachCommand": "bash .devcontainer/set-ports-public.sh",
  "forwardPorts": [3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012],
  "portsAttributes": {
    "3000": { "label": "Instructor Dashboard", "onAutoForward": "openBrowser" },
    "3001": { "label": "Team Alpha", "onAutoForward": "silent" }
  }
}
```

### Example 2: Port Visibility Script
```bash
#!/bin/bash
# .devcontainer/set-ports-public.sh
# Sets all classroom ports to public visibility in Codespaces
if [ -n "$CODESPACE_NAME" ]; then
  echo "Setting ports 3000-3012 to public visibility..."
  gh codespace ports visibility \
    3000:public 3001:public 3002:public 3003:public \
    3004:public 3005:public 3006:public 3007:public \
    3008:public 3009:public 3010:public 3011:public \
    3012:public \
    -c "$CODESPACE_NAME" 2>/dev/null && echo "Done." || echo "Warning: Could not set port visibility. Set manually in the Ports tab."
fi
```

### Example 3: HTTPS Toggle API Guard
```javascript
// In routes/admin.js, inside the toggle route handler
router.post('/security/toggle/:feature', requireAuth, requireRole(['admin']), async (req, res) => {
  const feature = req.params.feature;

  // Prevent HTTPS toggle in Codespaces (causes proxy conflicts)
  if (feature === 'https_enabled') {
    return res.json({
      success: false,
      message: 'HTTPS is managed by the Codespaces proxy. This toggle is disabled to prevent connection issues.',
      blocked: true
    });
  }

  // ... rest of existing toggle logic
});
```

### Example 4: HTTPS Toggle UI Disable
```html
<!-- In views/admin/security-panel.ejs, replace the HTTPS card's toggle -->
<label class="toggle-switch">
  <input type="checkbox" disabled title="HTTPS is managed by Codespaces">
  <span class="toggle-slider" style="opacity: 0.5;"></span>
</label>
<p style="font-size: 0.75rem; color: #e67e22; margin-top: 0.5rem;">
  Disabled -- HTTPS is provided by the Codespaces proxy
</p>
```

### Example 5: Smoke Test Retry-Based Health Check
```javascript
// Retry wrapper for initial connectivity
async function waitForInstance(port, maxRetries = 3, delayMs = 2000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const res = await request({ url: `http://localhost:${port}/health`, timeout: 5000 });
      if (res.statusCode === 200) return true;
    } catch (e) { /* retry */ }
    if (attempt < maxRetries) await new Promise(r => setTimeout(r, delayMs));
  }
  return false;
}
```

### Example 6: Smoke Test French Content Verification
```javascript
async function verifyFrenchLogin(port) {
  const res = await request({ url: `http://localhost:${port}/` });
  const hasFrench = res.body.includes('Connexion');
  return { status: res.statusCode === 200, french: hasFrench };
}
```

### Example 7: Smoke Test Stats Endpoint Verification
```javascript
async function verifyStatsEndpoint(port, sessionCookie) {
  const res = await request({
    url: `http://localhost:${port}/sca/stats`,
    headers: { 'Cookie': sessionCookie }
  });
  if (res.statusCode !== 200) return false;
  try {
    const data = JSON.parse(res.body);
    const hasFields = 'studentsStarted' in data && 'totalStudents' in data
                   && 'avgCompletion' in data && 'pace' in data;
    return hasFields;
  } catch (e) { return false; }
}
```

## Existing Code Inventory

### Files to Modify
| File | Change | Scope |
|------|--------|-------|
| `classroom.config.json` | `autoResetOnStart: false` -> `true` | 1 line |
| `config/database.js:19` | `encryption_at_rest: 0` -> `1` in default security_settings | 1 field |
| `config/database.js:1087` | `encryption_at_rest: 0` -> `1` in initializeDatabase fallback | 1 field |
| `config/security.js:20` | `encryption_at_rest: 0` -> `1` in getSecuritySettings fallback | 1 field |
| `.devcontainer/devcontainer.json` | Add `postAttachCommand`, keep existing portsAttributes as-is | ~2 lines |
| `routes/admin.js:35-40` | Add early return guard for `https_enabled` toggle | ~8 lines |
| `views/admin/security-panel.ejs:258-271` | Disable HTTPS checkbox, add explanatory text | ~5 lines |
| `scripts/smoke-test.js` | Full rewrite -- comprehensive 13-port verification | ~200-250 lines |

### Files to Create
| File | Purpose |
|------|---------|
| `.devcontainer/set-ports-public.sh` | Port visibility automation script |

### Files NOT to Touch
- `server.js` -- no changes needed; HTTPS logic is fine as-is since we prevent it from being enabled
- `utils/seedData.js` -- security defaults come from `config/database.js`, not seed data
- `routes/sca.js` -- already complete from Phase 3-4
- `views/` (other than security-panel.ejs) -- already translated from Phases 1-4

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `portsAttributes.visibility` in devcontainer.json | `gh codespace ports visibility` via lifecycle hook | Never worked declaratively | Must use CLI script instead |
| Manual port visibility in UI | `postAttachCommand` automation | gh CLI v2.x | Runs automatically on Codespace attach |

## Open Questions

1. **GitHub Organization Port Policy**
   - What we know: GitHub orgs can restrict port visibility to private/org-only
   - What's unclear: Whether the HEC Montreal GitHub org has such a policy in place
   - Recommendation: The script should handle failure gracefully (`|| true`). If public visibility is blocked, "org" visibility is the fallback (students must be in the same GitHub org). Document this for the instructor.

2. **postAttachCommand Reliability**
   - What we know: Users report occasional timing issues with postAttachCommand
   - What's unclear: Whether it reliably fires in the Codespaces web editor (vs VS Code Desktop)
   - Recommendation: Implement as best-effort. The instructor can also run the script manually. Add a note in the smoke test output if ports appear inaccessible.

## Sources

### Primary (HIGH confidence)
- Official devcontainer JSON reference at containers.dev -- verified that `visibility` is NOT a valid portsAttributes property
- GitHub Docs: Forwarding ports in your codespace -- confirmed `gh codespace ports visibility` as the only method
- Direct code inspection of `server.js`, `config/database.js`, `classroom-manager.js`, `smoke-test.js`, `routes/sca.js`, `routes/auth.js`, `routes/admin.js`, `views/admin/security-panel.ejs`

### Secondary (MEDIUM confidence)
- GitHub Community Discussion #4068 (Allow ports to be public by default) -- confirmed feature not implemented, workarounds documented
- GitHub Community Discussion #10394 -- confirmed postAttachCommand as recommended lifecycle hook
- GitHub Docs: Restricting visibility of forwarded ports -- organizational policy implications

## Metadata

**Confidence breakdown:**
- Configuration changes (autoResetOnStart, security defaults): HIGH -- direct code reading, single-line changes
- Port visibility approach: HIGH -- verified against official spec that declarative approach doesn't work; CLI approach confirmed by GitHub docs
- HTTPS toggle disable: HIGH -- traced exact code path through server.js/admin.js/security-panel.ejs
- Smoke test architecture: HIGH -- existing smoke-test.js provides proven patterns for HTTP requests and cookie handling
- postAttachCommand reliability: MEDIUM -- community reports occasional timing issues

**Research date:** 2026-03-12
**Valid until:** 2026-04-12 (stable domain; devcontainer spec and gh CLI unlikely to change significantly)
