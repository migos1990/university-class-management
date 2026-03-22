# API Contract Audit — HEC Montreal Application Security Platform

**Date:** 2026-03-22

---

## Summary: 0 Critical, 1 High, 2 Medium

The codebase has strong contract integrity. All routes match views, all views reference valid routes, and the CTF implementation is internally consistent. The main finding is related to the QA-discovered 5x duplication bug.

---

## Findings

### HIGH

**API-H01: 5x finding duplication in template rendering**
- **Source:** QA-AUDIT.md (ISSUE-001)
- **Issue:** SCA, DAST, VM, and SCA instructor pages render their finding lists 5 times. On the SCA student page, 12 unique findings produce 60 DOM elements. This is a rendering contract issue — the route handler likely passes data correctly but the template iterates multiple times.
- **Fix:** Audit the EJS templates for duplicate `<% forEach %>` loops or multiple includes of the same partial.

### MEDIUM

**API-M01: CTF locked challenge returns raw JSON**
- **Route:** `GET /pentest/challenges/:id` (when challenge is locked)
- **Issue:** Returns `{"error":"Challenge verrouille"}` instead of rendering an error page.
- **Fix:** Render `views/error.ejs` with a friendly locked message instead of JSON response.

**API-M02: Nav link "Cours" → `/classes` returns 404**
- **Route:** `/classes`
- **Issue:** The route file `routes/classes.js` exists and is mounted in server.js, but the route may not match the nav link's URL path, or the handler may have a conditional that fails.
- **Fix:** Verify the classes route handler and ensure it renders for authenticated users.

---

## Verified Contracts (No Issues)

| Contract | Status |
|----------|--------|
| All 9 route files mounted in server.js | ✅ Match |
| All CTF challenge IDs in seeds match route params | ✅ Match |
| All EJS views rendered by at least one route | ✅ Match |
| CTF flag locations reference valid file paths | ✅ Match (FLAG.txt, backup files, hidden endpoints exist) |
| i18n keys in views → translation files | ✅ Match (pentest.ctf.* keys all present) |
| API endpoints (/api/summary, /api/instructor-message) require auth | ✅ Verified in tests |
| Answer key role-gated to instructor | ✅ Verified in tests |

---

## Recommendation

The 5x duplication bug (API-H01) is the highest priority — it's the critical QA finding and affects all lab pages. The other two are already captured in Phase 17 from the QA audit.
