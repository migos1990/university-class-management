# Phase 9: Security Boundary Documentation - Research

**Researched:** 2026-03-19
**Domain:** Security documentation / Markdown authoring
**Confidence:** HIGH

## Summary

Phase 9 is a documentation-only phase: create a single `SECURITY-BOUNDARY.md` file at the project root and add a link from `README.md`. No code changes, no new dependencies, no runtime behavior changes.

All 12 intentional vulnerabilities are fully defined in `utils/seedData.js` (lines 195-394) with CWE codes, file paths, line numbers, severities, descriptions, tools, and remediation guidance. The DIFFICULTY_MAP in `routes/sca.js` (lines 8-13) maps finding IDs to Easy/Medium/Hard levels. The v1.0 milestone audit (`.planning/milestones/v1.0-MILESTONE-AUDIT.md`) documents exactly 4 tech debt items. The security toggles are defined in `config/security.js` (VALID_SETTINGS array, lines 4-8) with defaults in `getSecuritySettings()` (lines 15-27).

**Primary recommendation:** Extract the 12 findings from seedData.js, cross-reference with DIFFICULTY_MAP for difficulty levels and the vulnerabilities table (lines 511-590) for OWASP categories, and produce a structured Markdown document. Add a "Deliberately Weakened Controls" section sourced from security.js defaults. Include the 4 tech debt items from the v1.0 audit. Link from README.md.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions
- Written in English -- standard for security documentation
- CWE codes, OWASP categories, and severity levels stay in English (industry terms)
- Each entry cross-references its SCA finding ID (e.g., "SCA Finding #3") for traceability to the student lab
- Explicit "DO NOT FIX" warning per intentional vulnerability entry -- prevents well-meaning PRs from breaking the lab
- Detailed entries (~5-8 lines per finding): SCA Finding ID, title, CWE, severity, difficulty level, file:line location, learning objective, and "Do Not Fix" note
- File:line reference only -- no inline code snippets (avoids duplication with seedData.js, stays maintainable)
- Include the student-facing difficulty level (Easy/Medium/Hard) per entry -- useful for instructor class planning
- Separate "Deliberately Weakened Controls" section for security toggles (audit logging off by default, rate limiting configurable, etc.) -- distinct from code-level vulnerabilities
- List the 4 tech debt items from the v1.0 milestone audit with status only (Open / Accepted Risk / Mitigated) -- no severity rating
- Upfront definitions section clearly distinguishing "Intentional Vulnerability" (planted for teaching) from "Accepted Risk" (real limitation assessed and accepted)
- Primary audience: future contributors opening a PR or reviewing the repo
- Direct and technical tone -- no narrative or backstory
- Named SECURITY-BOUNDARY.md (not SECURITY.md) to avoid confusion with GitHub's vulnerability disclosure convention
- Linked from the main README (add a Security section pointing to this doc)
- Version stamp in footer: "Last verified: v1.1, [date]"
- Brief "Adding a New Teaching Vulnerability" contributor guide section (update seedData.js, add entry here, assign CWE)

### Claude's Discretion
- Exact ordering of the 12 entries (by finding ID, by severity, or by difficulty)
- Wording of the "Do Not Fix" warning
- How to structure the contributor guide section
- Which 4 tech debt items from v1.0 audit to include and their exact status

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SDOC-01 | SECURITY-BOUNDARY.md documents all 12 intentional vulnerabilities (purpose, location) separately from real security findings | All 12 findings sourced from seedData.js lines 195-394; difficulty from DIFFICULTY_MAP; OWASP categories from vulnerabilities table lines 511-590; 4 tech debt items from v1.0-MILESTONE-AUDIT.md; security toggles from config/security.js |

</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Markdown | N/A | Document format | Universal, renders natively on GitHub, no tooling needed |

### Supporting
No additional libraries needed. This is a pure documentation task.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Markdown | AsciiDoc | Markdown is universal on GitHub; AsciiDoc adds friction |
| Manual authoring | Generated from seedData.js | Manual is correct here -- document needs editorial judgment on learning objectives and wording |

## Architecture Patterns

### Recommended Document Structure
```
SECURITY-BOUNDARY.md
  - Header / purpose statement
  - Definitions (Intentional Vulnerability vs Accepted Risk)
  - Intentional Vulnerabilities table (12 entries)
  - Deliberately Weakened Controls section
  - Real Security Findings (tech debt) table
  - Adding a New Teaching Vulnerability (contributor guide)
  - Version stamp footer
```

### Pattern 1: Tabular Entry Format
**What:** Each of the 12 vulnerabilities as a structured entry with consistent fields
**When to use:** For the main vulnerability listing
**Example:**
```markdown
### Finding #1: Hardcoded Session Secret

| Field | Value |
|-------|-------|
| SCA Finding ID | #1 |
| CWE | CWE-798 (Hardcoded Credentials) |
| OWASP | A02:2021 - Cryptographic Failures |
| Severity | Critical |
| Difficulty | Easy |
| Location | `server.js:45` |
| Learning Objective | Recognize hardcoded secrets and understand session forgery risk |

> **DO NOT FIX** -- This vulnerability is intentionally planted for the SCA lab exercise.
```

### Pattern 2: Compact Table for Weakened Controls
**What:** Security toggles that default to insecure state, listed as a quick-reference table
**When to use:** For the "Deliberately Weakened Controls" section
**Example:**
```markdown
| Control | Default | File | Purpose |
|---------|---------|------|---------|
| Audit Logging | OFF (0) | config/database.js | Students observe the absence of audit trails |
| Rate Limiting | OFF (0) | config/database.js | Students test brute-force without throttling |
```

### Pattern 3: README Cross-Link
**What:** A "Security" section in README.md pointing to SECURITY-BOUNDARY.md
**When to use:** After creating the boundary document
**Example:**
```markdown
## Security

This project contains **intentional security vulnerabilities** for educational purposes. Before reporting a vulnerability or submitting a fix, read [SECURITY-BOUNDARY.md](SECURITY-BOUNDARY.md) to understand which issues are deliberate teaching tools and which are real findings.
```

### Anti-Patterns to Avoid
- **Duplicating code snippets:** CONTEXT.md explicitly forbids inline code snippets; use file:line references only
- **Severity ratings on tech debt:** CONTEXT.md says status only (Open / Accepted Risk / Mitigated), no severity
- **Using SECURITY.md name:** GitHub interprets SECURITY.md as a vulnerability disclosure policy; use SECURITY-BOUNDARY.md

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Extracting finding data | Parse seedData.js at runtime | Read seedData.js manually, copy data | This is a static document, not generated code |
| CWE descriptions | Invent your own CWE wording | Use CWE names from seedData.js entries | seedData.js already has precise CWE codes and descriptions |
| OWASP category mapping | Create a new mapping | Use the vulnerabilities table (seedData.js lines 511-590) | Already maps each finding to OWASP 2021 categories |

**Key insight:** All data sources already exist in the codebase. This phase is assembly and editorial work, not creation of new information.

## Common Pitfalls

### Pitfall 1: Missing or Incorrect Finding Data
**What goes wrong:** Copying finding details manually introduces transcription errors (wrong CWE, wrong line number)
**Why it happens:** The 12 findings span 200 lines of seedData.js with dense data
**How to avoid:** Cross-reference every entry against seedData.js (lines 195-394) for CWE, severity, file_path, line_number. Cross-reference DIFFICULTY_MAP (sca.js lines 8-13) for difficulty level. Cross-reference vulnerabilities table (seedData.js lines 511-590) for OWASP category.
**Warning signs:** A finding listed as "Medium" severity when seedData.js says "High"

### Pitfall 2: Confusing Difficulty with Severity
**What goes wrong:** Mixing up "severity" (Critical/High/Medium from the SCA finding) with "difficulty" (Easy/Medium/Advanced from DIFFICULTY_MAP)
**Why it happens:** Both use overlapping terms ("Medium")
**How to avoid:** Always label fields explicitly. Severity comes from the finding's severity field. Difficulty comes from DIFFICULTY_MAP. Note: DIFFICULTY_MAP uses "advanced" not "hard" -- CONTEXT.md says "Easy/Medium/Hard" but the codebase uses "Easy/Medium/Advanced". Use the codebase values.
**Warning signs:** An "Advanced" difficulty finding listed as "Hard"

### Pitfall 3: Forgetting the README Link
**What goes wrong:** SECURITY-BOUNDARY.md exists but nobody discovers it
**Why it happens:** The README update is a secondary task easily forgotten
**How to avoid:** Make the README edit a tracked task in the plan
**Warning signs:** SECURITY-BOUNDARY.md created but README.md unchanged

### Pitfall 4: Tech Debt Items -- Wrong Status Assignment
**What goes wrong:** Assigning incorrect status to the 4 tech debt items
**Why it happens:** The audit describes items but doesn't assign Open/Accepted Risk/Mitigated status explicitly
**How to avoid:** Review each item's actual current state. All 4 are described as non-blocking, cosmetic/low items with "None are blockers" and "All can be addressed in a v2 cleanup cycle" -- suggesting "Accepted Risk" or "Open" status depending on whether they have been triaged
**Warning signs:** Marking something "Mitigated" when it hasn't been fixed

## Code Examples

### Data Source: All 12 SCA Findings (seedData.js)

The complete finding data, verified from source:

| ID | Title | File | Line | CWE | Severity | OWASP Category |
|----|-------|------|------|-----|----------|----------------|
| 1 | Hardcoded Session Secret | server.js | 45 | CWE-798 | Critical | A02:2021 - Cryptographic Failures |
| 2 | Hardcoded AES Encryption Key | utils/encryption.js | 6 | CWE-321 | Critical | A02:2021 - Cryptographic Failures |
| 3 | Plaintext Credentials Logged to Console | server.js | 141 | CWE-312 | High | A09:2021 - Security Logging and Monitoring Failures |
| 4 | Plaintext Password Comparison | routes/auth.js | 38 | CWE-256 | Critical | A07:2021 - Identification and Authentication Failures |
| 5 | Audit Logging Defaults to OFF | config/database.js | 19 | CWE-778 | High | A09:2021 - Security Logging and Monitoring Failures |
| 6 | IDOR: No Ownership Check on Enrollment Access | routes/classes.js | 39 | CWE-639 | High | A01:2021 - Broken Access Control |
| 7 | No CSRF Protection on State-Changing Requests | server.js | 1 | CWE-352 | High | A01:2021 - Broken Access Control |
| 8 | Rate Limiting Only on Login Route | middleware/rateLimiter.js | 9 | CWE-307 | Medium | A07:2021 - Identification and Authentication Failures |
| 9 | No HTTP Security Headers | server.js | 17 | CWE-693 | Medium | A05:2021 - Security Misconfiguration |
| 10 | Path Traversal in Backup Download | routes/admin.js | 509 | CWE-22 | High | A01:2021 - Broken Access Control |
| 11 | Outdated express-session with Known Vulnerabilities | package.json | 24 | CWE-1035 | Medium | A06:2021 - Vulnerable and Outdated Components |
| 12 | Session Cookie Missing secure Flag | server.js | 51 | CWE-614 | Medium | A02:2021 - Cryptographic Failures |

Source: `utils/seedData.js` lines 195-394 (SCA findings), lines 511-590 (vulnerabilities/OWASP mapping)

### Data Source: DIFFICULTY_MAP (routes/sca.js)

```javascript
// Source: routes/sca.js lines 8-13
const DIFFICULTY_MAP = {
  1: 'easy', 2: 'easy', 3: 'easy', 4: 'easy',
  6: 'medium', 7: 'medium', 8: 'medium',
  5: 'advanced', 9: 'advanced', 10: 'advanced',
  11: 'advanced', 12: 'advanced'
};
```

Mapped to findings:
- **Easy (4):** #1, #2, #3, #4
- **Medium (3):** #6, #7, #8
- **Advanced (5):** #5, #9, #10, #11, #12

### Data Source: Deliberately Weakened Controls (config/security.js + config/database.js)

Security settings with insecure defaults (from `config/security.js` lines 15-27):

| Setting | Default | Teaching Purpose |
|---------|---------|-----------------|
| mfa_enabled | 0 (OFF) | Students see authentication without second factor |
| rbac_enabled | 1 (ON) | ON by default, but toggleable to demonstrate broken access control |
| encryption_at_rest | 1 (ON) | ON by default, but toggleable to show plaintext storage |
| field_encryption | 0 (OFF) | Students observe PII stored in cleartext |
| https_enabled | 0 (OFF) | Students observe HTTP traffic without TLS |
| audit_logging | 0 (OFF) | Students observe absence of security event recording |
| rate_limiting | 0 (OFF) | Students test brute-force without throttling |
| backup_enabled | 0 (OFF) | Backup feature available but not active by default |
| segregation_of_duties | 0 (OFF) | Students see uncontrolled admin operations |

The "Deliberately Weakened Controls" section should focus on the security-relevant toggles that default to OFF and create intentional weak postures for teaching: `audit_logging`, `rate_limiting`, `mfa_enabled`, `field_encryption`, `https_enabled`.

### Data Source: Tech Debt Items (v1.0-MILESTONE-AUDIT.md)

| # | Phase | Item | Recommended Status |
|---|-------|------|--------------------|
| 1 | Phase 3 | 2 hardcoded French strings in `finding-detail.ejs` lines 61, 64 | Accepted Risk |
| 2 | Phase 4 | `GET /sca/findings/:id` missing `users` query for instructor view | Open |
| 3 | Phase 4 | HTML comment in `instructor.ejs` contains English (non-visible) | Accepted Risk |
| 4 | Phase 5 | `/auth/set-language` endpoint is dead code (no UI calls it) | Accepted Risk |

Rationale: Items 1, 3, and 4 are cosmetic/inert issues with zero classroom impact, making "Accepted Risk" appropriate. Item 2 is a functional gap (instructor sees student IDs instead of usernames in finding-detail) that could be fixed in a future update, so "Open" is more accurate.

### README.md Edit Point

The README currently has no "Security" section. The best insertion point is after the "Security Features" section (after line 82) or as a new top-level section before "How It Works" (before line 109). A compact 3-4 line section suffices.

## State of the Art

Not applicable for this phase -- this is a documentation authoring task, not a technology choice.

## Open Questions

1. **Difficulty terminology: "Hard" vs "Advanced"**
   - What we know: CONTEXT.md says "Easy/Medium/Hard" but DIFFICULTY_MAP uses "easy/medium/advanced"
   - What's unclear: Which label to use in the document
   - Recommendation: Use "Easy/Medium/Advanced" to match the codebase (DIFFICULTY_MAP and the student-facing UI). This is a discretion area -- the planner should use codebase values for consistency.

2. **Learning objectives per finding**
   - What we know: CONTEXT.md requires a "learning objective" field per entry
   - What's unclear: seedData.js stores `description` and `remediation` but not an explicit "learning objective"
   - Recommendation: Derive learning objectives from the description + remediation fields. Each finding teaches students to recognize a specific vulnerability class. This is editorial work the implementer will do per entry.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, no dependency) |
| Config file | None (uses node --test directly) |
| Quick run command | `node --test test/sca-review.test.js` |
| Full suite command | `node --test test/*.test.js` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SDOC-01 | SECURITY-BOUNDARY.md exists and contains all 12 findings + real findings section | smoke | `node -e "const fs=require('fs'); const c=fs.readFileSync('SECURITY-BOUNDARY.md','utf8'); const ids=[1,2,3,4,5,6,7,8,9,10,11,12]; ids.forEach(i=>{if(!c.includes('#'+i))throw new Error('Missing finding '+i)}); if(!c.includes('Tech Debt')||!c.includes('Real'))throw new Error('Missing real findings section'); console.log('PASS')"` | No -- Wave 0 |

Note: Since SDOC-01 is a documentation-only requirement, automated testing is limited to verifying file existence and content presence. A full content review is inherently manual. The smoke check above verifies all 12 finding IDs are referenced and a real-findings section exists.

### Sampling Rate
- **Per task commit:** Verify SECURITY-BOUNDARY.md exists and contains expected sections
- **Per wave merge:** `node --test test/*.test.js` (ensures no regressions from README edit)
- **Phase gate:** Manual review of document completeness + automated existence check

### Wave 0 Gaps
- [ ] No test file needed for a documentation phase -- the verification is content review, not code behavior
- [ ] Existing test suite (`test/*.test.js`) should pass unchanged since no code is modified

## Sources

### Primary (HIGH confidence)
- `utils/seedData.js` lines 195-394 -- all 12 SCA finding definitions (CWE, severity, file path, line number, description, remediation)
- `utils/seedData.js` lines 506-590 -- vulnerabilities table with OWASP 2021 category mapping
- `routes/sca.js` lines 8-13 -- DIFFICULTY_MAP mapping finding IDs to easy/medium/advanced
- `config/security.js` lines 4-8, 15-27 -- security toggle settings and defaults
- `.planning/milestones/v1.0-MILESTONE-AUDIT.md` -- 4 tech debt items with descriptions and severity
- `README.md` -- current structure for identifying insertion point for Security section link

### Secondary (MEDIUM confidence)
- None needed -- all data is in the codebase

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- pure Markdown, no libraries needed
- Architecture: HIGH -- document structure fully specified in CONTEXT.md decisions
- Pitfalls: HIGH -- all data sources verified in codebase, edge cases identified
- Data accuracy: HIGH -- every finding field cross-referenced against seedData.js source

**Research date:** 2026-03-19
**Valid until:** 2026-04-19 (stable -- documentation task, data sources unlikely to change)
