# Phase 13: Documentation - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

README and instructor-facing docs (SOLUTION-GUIDE.md) accurately describe the v1.1 feature set so a new instructor (or future Julie) can understand and use the platform without tribal knowledge. No new docs created — update existing files only.

</domain>

<decisions>
## Implementation Decisions

### README update scope
- Weave v1.1 features into existing sections (not a separate "What's New" block)
- Expand SCA lab description to a 3-5 sentence paragraph covering the full student experience (code snippets, difficulty levels, hints, prev/next nav, completion banner)
- Expand "For Instructors" section to mention answer key, student activity tracking, and progress cards
- Keep Pentest section as-is — Phase 16 (CTF) will rewrite it when it ships
- No new sections; update existing ones to reflect current state

### Instructor docs format
- Update SOLUTION-GUIDE.md with v1.1 features in the relevant existing sections (SCA lab, DAST lab, Classroom Management)
- Answer key documentation: usage-focused paragraph (how to access, what it shows, where to find inline version) — not a step-by-step walkthrough
- Brief mention of DAST French in the DAST lab section (one sentence noting all scenarios display in Quebec French)
- Update Pre-Class Checklist (section 20) with 1-2 new verification items (answer key access, code snippets render)

### Version history approach
- Collapse old version entries to milestones: keep v1.1 (initial), v2.0 (UI redesign), v3.0 (Codespaces) — remove v1.2-v1.9 granular bug fix entries
- Add v3.1 entry (continuing README version scheme, not internal "v1.1" milestone name)
- v3.1 entry grouped by feature categories: Pedagogy, French, Instructor Tools, Quality
- Include actual ship date on the v3.1 entry

### Doc language
- All docs stay English (README, SOLUTION-GUIDE, SECURITY-BOUNDARY)
- When documenting French features, describe what's translated without showing French text examples (e.g., "DAST scenarios display in Quebec French" — no inline French)

### Claude's Discretion
- Exact wording and sentence structure of updated sections
- How to organize the v3.1 feature categories
- Which SOLUTION-GUIDE sections need minor vs substantial updates
- Whether to add cross-references between README and SOLUTION-GUIDE

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `README.md` (337 lines): Current README with outdated content — structure is sound, content needs updating
- `SOLUTION-GUIDE.md`: Comprehensive 22-section instructor manual — add v1.1 features to existing sections
- `SECURITY-BOUNDARY.md`: Up to date (Phase 9) — no changes needed

### Established Patterns
- README follows a clear section structure: Quick Start → Accounts → Security Features → Labs → How It Works → Troubleshooting → npm Scripts → For Instructors → Version History
- SOLUTION-GUIDE uses numbered sections with subsections, table of contents, and code examples
- Version history uses `### Version X.Y (date)` format with bold subtitle and bullet lists

### Integration Points
- README references `npm test` smoke test — still accurate
- README references port 3000 (instructor) and 3001-3012 (teams) — still accurate
- SOLUTION-GUIDE Pre-Class Checklist section needs new items for v1.1 features

</code_context>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches for documentation updates.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 13-documentation*
*Context gathered: 2026-03-20*
