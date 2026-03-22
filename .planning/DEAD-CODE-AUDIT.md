# Dead Code Audit — HEC Montreal Application Security Platform

**Date:** 2026-03-22

---

## Summary

| Category | Count | Severity |
|----------|-------|----------|
| Old pentest module NOT removed | 1 route file + 3 views still present | High |
| Unused npm dependencies | 0 | — |
| Unused views | 0 | — |
| Unused routes | 0 | — |

---

## Findings

### HIGH — Old Pentest Module Still Present

**Issue:** Phase 16 (CTF Pentest Lab) was supposed to remove the old pentest form-filling module, but the route and view files were **repurposed** rather than replaced. The CTF lab IS the pentest module now — `routes/pentest.js` contains CTF routes and `views/pentest/` contains CTF views.

This is actually correct — Phase 16 replaced the old pentest logic IN-PLACE. The files are not dead code; they contain the new CTF implementation. The roadmap item "old routes/views/tables removed" was achieved by overwriting the content, not deleting the files.

**Verdict:** Not dead code — confirmed repurposed. No action needed.

### LOW — Duplicate Welcome files

- `univeristyClass/Welcome.md` (typo in folder name)
- `universityClass/Welcome.md`

Two copies with different folder name spellings. Minor cleanup.

### LOW — .obsidian/ directory

Obsidian workspace config files in the repo root. Not harmful but unnecessary for deployment.

---

## Conclusion

The codebase is clean. All routes, views, middleware, and npm dependencies are in use. No dead code found beyond minor file duplication.
