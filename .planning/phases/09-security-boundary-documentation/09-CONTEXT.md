# Phase 9: Security Boundary Documentation - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

A SECURITY-BOUNDARY.md file at the project root that clearly distinguishes the 12 intentional teaching vulnerabilities from real security findings. Anyone reviewing the codebase (especially future contributors) immediately understands what is deliberate and must not be fixed. Covers SDOC-01.

</domain>

<decisions>
## Implementation Decisions

### Document language
- Written in English — standard for security documentation
- CWE codes, OWASP categories, and severity levels stay in English (industry terms)
- Each entry cross-references its SCA finding ID (e.g., "SCA Finding #3") for traceability to the student lab
- Explicit "DO NOT FIX" warning per intentional vulnerability entry — prevents well-meaning PRs from breaking the lab

### Content structure
- Detailed entries (~5-8 lines per finding): SCA Finding ID, title, CWE, severity, difficulty level, file:line location, learning objective, and "Do Not Fix" note
- File:line reference only — no inline code snippets (avoids duplication with seedData.js, stays maintainable)
- Include the student-facing difficulty level (Easy/Medium/Hard) per entry — useful for instructor class planning
- Separate "Deliberately Weakened Controls" section for security toggles (audit logging off by default, rate limiting configurable, etc.) — distinct from code-level vulnerabilities

### Real security findings section
- List the 4 tech debt items from the v1.0 milestone audit with status only (Open / Accepted Risk / Mitigated) — no severity rating
- Upfront definitions section clearly distinguishing "Intentional Vulnerability" (planted for teaching) from "Accepted Risk" (real limitation assessed and accepted)

### Document audience & tone
- Primary audience: future contributors opening a PR or reviewing the repo
- Direct and technical tone — no narrative or backstory
- Named SECURITY-BOUNDARY.md (not SECURITY.md) to avoid confusion with GitHub's vulnerability disclosure convention
- Linked from the main README (add a Security section pointing to this doc)
- Version stamp in footer: "Last verified: v1.1, [date]"
- Brief "Adding a New Teaching Vulnerability" contributor guide section (update seedData.js, add entry here, assign CWE)

### Claude's Discretion
- Exact ordering of the 12 entries (by finding ID, by severity, or by difficulty)
- Wording of the "Do Not Fix" warning
- How to structure the contributor guide section
- Which 4 tech debt items from v1.0 audit to include and their exact status

</decisions>

<specifics>
## Specific Ideas

- The doc should work as a quick-reference checklist: a contributor scanning for "is this a real bug?" should find their answer in seconds
- "Deliberately Weakened Controls" section covers things like audit_logging defaulting to 0 — these aren't code bugs but intentional config choices for the teaching environment

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `utils/seedData.js:191-391`: All 12 SCA findings with CWE codes, file paths, line numbers, severities, and code snippets — primary data source for the doc
- `utils/seedData.js:506-590`: Vulnerabilities table with OWASP categories mapped to each CWE
- `.planning/milestones/v1.0-MILESTONE-AUDIT.md`: Contains the 4 tech debt items to reference in the real findings section

### Established Patterns
- DIFFICULTY_MAP in routes/sca.js maps finding IDs to Easy/Medium/Hard — source for difficulty levels in the doc
- `config/security.js` and Security Panel: toggleable controls (audit_logging, rate_limiting, mfa_enabled, etc.) — source for "Deliberately Weakened Controls" section

### Integration Points
- `README.md`: Add a Security section linking to SECURITY-BOUNDARY.md
- Project root: SECURITY-BOUNDARY.md placed alongside README.md, package.json

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 09-security-boundary-documentation*
*Context gathered: 2026-03-19*
