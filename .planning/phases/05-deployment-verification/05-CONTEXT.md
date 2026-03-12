# Phase 5: Deployment Verification - Context

**Gathered:** 2026-03-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Confirm the complete French SCA lab works end-to-end in a fresh Codespaces environment with zero manual intervention beyond starting the Codespace. This phase configures port visibility, hardens first-boot defaults, disables the HTTPS toggle, and builds an automated smoke test that validates all 13 ports, French content rendering, and the instructor stats endpoint. No new features — only configuration and verification.

</domain>

<decisions>
## Implementation Decisions

### Port visibility
- Set all ports (3000-3012) to `"visibility": "public"` in devcontainer.json portsAttributes
- Students access their team's URL as shared by the instructor from the classroom-manager console output
- Each team shares one set of demo credentials (alice_student/student123, prof_jones/prof123) — no per-student accounts
- No changes to authentication or credential seeding

### First-boot configuration
- Flip `autoResetOnStart` to `true` in classroom.config.json — guarantees fresh seed data on every Codespace start
- Disable the HTTPS toggle in the security panel — Codespaces provides HTTPS via its proxy; app-level HTTPS causes certificate conflicts and cookie failures
- Keep full auto-start flow: postCreateCommand (npm install + setup.js) then postStartCommand (npm start) — zero manual steps
- Hardcode safe security defaults in seed data: https_enabled=false, rbac_enabled=true, encryption_at_rest=true, mfa_enabled=false

### Smoke test design
- Extend or replace existing smoke-test.js with comprehensive HTTP-level verification
- Test ALL 13 ports (3000 dashboard + 3001-3012 team instances)
- Verify each instance responds with 200 status
- Check key French phrases per page type:
  - Login page: "Connexion"
  - SCA student lab: "Analyse statique"
  - Finding detail: "Classification"
  - Instructor dashboard: "Étudiants"
- Verify GET /sca/stats returns valid JSON with studentsStarted, totalStudents, avgCompletion, pace fields
- No browser automation (Puppeteer/Playwright) — HTTP requests only, no new dependencies

### Smoke test output
- Emoji pass/fail list: ✅ Dashboard (3000) — OK, ✅ Team Alpha (3001) — French login OK, ❌ Team Bravo (3002) — timeout
- Final summary line: X/13 passed
- Smoke test IS the pre-class checklist — run `npm test`, all green = ready for class

### Fallback strategy
- If some instances fail: reduce TEAM_COUNT env var to only working instances, redistribute students across fewer teams
- Smoke test output should clearly indicate which ports failed so instructor knows which teams to skip

### Claude's Discretion
- Exact HTTP request flow for verifying login + SCA routes (cookie handling for authenticated routes)
- Whether to test one instance deeply (login → SCA lab → finding detail → stats) and the rest with just health checks, or test all 13 at the same depth
- Exact French phrases to check for on each page (within the key phrases listed above)
- How to handle the HTTPS toggle disable (seed data override, middleware guard, or UI-level disable)
- Timeout thresholds and retry logic in the smoke test

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `scripts/smoke-test.js`: Existing smoke test that polls /health endpoints — extend or rewrite with deeper checks
- `scripts/classroom-manager.js`: Codespace URL detection (CODESPACE_NAME, GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN) — reuse pattern
- `.devcontainer/devcontainer.json`: Already forwards ports 3000-3012 with labels — add visibility attribute
- `classroom.config.json`: Configuration for instance count, teams, autoResetOnStart — flip flag

### Established Patterns
- Health check polling: classroom-manager polls /health every 30s — smoke test can reuse similar HTTP fetch pattern
- Codespace detection: `IS_CODESPACES` flag in classroom-manager.js — smoke test can adapt URLs accordingly
- Console output: classroom-manager uses plain console.log with team labels — match style for smoke test output

### Integration Points
- `classroom.config.json:11`: autoResetOnStart flag — change from false to true
- `.devcontainer/devcontainer.json:10-26`: portsAttributes — add "visibility": "public" to each port
- `scripts/smoke-test.js`: Entry point for `npm test` — replace/extend with comprehensive verification
- `utils/seedData.js` or `config/security.js`: Security defaults — ensure https_enabled=false at seed time
- `routes/admin.js` or `config/security.js`: HTTPS toggle — disable or guard against enabling

</code_context>

<specifics>
## Specific Ideas

- The smoke test should be the professor's single pre-class command: `npm test` → all green → share URLs → class begins
- Output should be scannable "at a glance" — emoji checkmarks, team names, port numbers
- Fallback is practical: reduce team count, not fix infrastructure under pressure

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 05-deployment-verification*
*Context gathered: 2026-03-12*
