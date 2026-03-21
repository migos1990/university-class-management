# Phase 13: Documentation - Research

**Researched:** 2026-03-20
**Domain:** Documentation updates (README.md + SOLUTION-GUIDE.md)
**Confidence:** HIGH

## Summary

Phase 13 is a pure documentation update phase -- no code changes, no new files. The task is to update two existing files (README.md and SOLUTION-GUIDE.md) to reflect v1.1 features shipped in Phases 6-12: inline code snippets, SCA UX enhancements (difficulty levels, prev/next nav, completion banner), DAST French translation, student activity tracking, progress cards, and the instructor answer key.

The existing docs are well-structured. README.md (337 lines) has a clear section layout. SOLUTION-GUIDE.md (1111 lines) is a comprehensive 22-section instructor manual. The version history needs cleanup: collapse v1.2-v1.9 bug fix entries into milestones and add a v3.1 entry for the v1.1 milestone features.

**Primary recommendation:** Two sequential tasks -- (1) update README.md (SCA section expansion, instructor section additions, version history cleanup + v3.1 entry, npm scripts table), (2) update SOLUTION-GUIDE.md (SCA lab section, DAST lab section, classroom management section, pre-class checklist, footer version).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Weave v1.1 features into existing sections (not a separate "What's New" block)
- Expand SCA lab description to a 3-5 sentence paragraph covering the full student experience (code snippets, difficulty levels, hints, prev/next nav, completion banner)
- Expand "For Instructors" section to mention answer key, student activity tracking, and progress cards
- Keep Pentest section as-is -- Phase 16 (CTF) will rewrite it when it ships
- No new sections; update existing ones to reflect current state
- Update SOLUTION-GUIDE.md with v1.1 features in the relevant existing sections (SCA lab, DAST lab, Classroom Management)
- Answer key documentation: usage-focused paragraph (how to access, what it shows, where to find inline version) -- not a step-by-step walkthrough
- Brief mention of DAST French in the DAST lab section (one sentence noting all scenarios display in Quebec French)
- Update Pre-Class Checklist (section 20) with 1-2 new verification items (answer key access, code snippets render)
- Collapse old version entries to milestones: keep v1.1 (initial), v2.0 (UI redesign), v3.0 (Codespaces) -- remove v1.2-v1.9 granular bug fix entries
- Add v3.1 entry (continuing README version scheme, not internal "v1.1" milestone name)
- v3.1 entry grouped by feature categories: Pedagogy, French, Instructor Tools, Quality
- Include actual ship date on the v3.1 entry
- All docs stay English (README, SOLUTION-GUIDE, SECURITY-BOUNDARY)
- When documenting French features, describe what's translated without showing French text examples

### Claude's Discretion
- Exact wording and sentence structure of updated sections
- How to organize the v3.1 feature categories
- Which SOLUTION-GUIDE sections need minor vs substantial updates
- Whether to add cross-references between README and SOLUTION-GUIDE

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| DOCS-01 | README reflects current v1.1 project state (features, setup, usage) | Gap analysis below identifies exactly which README sections need updating, with specific content to add for each shipped feature |
| DOCS-02 | Instructor-facing documentation describes how to use the answer key and new features | SOLUTION-GUIDE section-by-section analysis below identifies which of the 22 sections need updates, with content scope for each |
</phase_requirements>

## Standard Stack

This phase has no library dependencies. It is pure Markdown editing.

### Core
| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| Markdown | N/A | Documentation format | Both files already use Markdown |

### Supporting
None required.

### Alternatives Considered
None -- this is documentation-only.

## Architecture Patterns

### File Structure (no changes)
```
README.md                 # 337 lines, update in-place
SOLUTION-GUIDE.md         # 1111 lines, update in-place
SECURITY-BOUNDARY.md      # No changes needed (already up to date from Phase 9)
```

### Pattern 1: In-Place Section Updates
**What:** Modify existing prose within established section boundaries. No new headings, no structural changes.
**When to use:** Always in this phase -- locked decision says "no new sections."
**Example approach:**
- Locate the section heading
- Expand the existing content with new feature descriptions
- Maintain existing formatting conventions (bullet lists, tables, code blocks)

### Pattern 2: Version History Cleanup
**What:** Collapse granular patch entries into milestone summaries, then add a new milestone entry.
**When to use:** Version History section only.
**Existing format:**
```markdown
### Version X.Y (YYYY-MM-DD)
**Bold subtitle:**

- **Feature category** — description
- **Feature category** — description
```

### Anti-Patterns to Avoid
- **Creating a "What's New" section:** The user explicitly decided to weave features into existing sections, not create a standalone change summary.
- **Step-by-step walkthrough for answer key:** The user wants a usage-focused paragraph, not numbered instructions.
- **Showing French text in docs:** Describe what is translated without including French language examples.
- **Touching the Pentest section:** Phase 16 (CTF) will rewrite it.

## Don't Hand-Roll

Not applicable -- this phase is pure documentation editing with no code involved.

## Common Pitfalls

### Pitfall 1: Inconsistent Feature Counts
**What goes wrong:** Saying "12 findings" in one place and "10 findings" in another, or misrepresenting the number of DAST scenarios.
**Why it happens:** Multiple sections reference SCA findings (12) and DAST scenarios (6). Easy to introduce inconsistency.
**How to avoid:** Cross-reference all mentions of counts before finalizing. The actual counts are: 12 SCA findings, 6 DAST scenarios, 12 VM vulnerabilities.
**Warning signs:** Any number that doesn't match the seed data.

### Pitfall 2: Version Numbering Confusion
**What goes wrong:** Confusing the internal milestone name "v1.1" with the README version scheme (v3.1).
**Why it happens:** The project uses "v1.1" internally for the Polish & Pedagogy milestone, but the README already has v1.1 (Initial Release), v2.0 (UI Redesign), v3.0 (Codespaces). The next entry is v3.1.
**How to avoid:** Always use "v3.1" in README version history. Never use "v1.1" in user-facing docs.
**Warning signs:** Any mention of "v1.1" outside of planning files.

### Pitfall 3: Forgetting to Update SOLUTION-GUIDE Footer
**What goes wrong:** SOLUTION-GUIDE.md footer still says "v3.0" after updates.
**Why it happens:** The footer is on line 1111, easy to miss.
**How to avoid:** Explicitly include footer update in the plan.

### Pitfall 4: Mentioning Features That Don't Exist Yet
**What goes wrong:** Documenting CTF lab, ESLint/Prettier, or CSS extraction as if they are shipped.
**Why it happens:** These are in the roadmap (Phases 14-16) but not yet implemented.
**How to avoid:** Only document features from completed phases (6-12). Cross-check against REQUIREMENTS.md "Complete" checkmarks.

### Pitfall 5: Missing the npm Scripts Table Update
**What goes wrong:** The `npm run test:integration` command exists in package.json but is not in the README npm scripts table.
**Why it happens:** It was added in Phase 8 but the README wasn't updated.
**How to avoid:** Include the npm scripts table in the README update scope.

## Code Examples

Not applicable -- this phase produces Markdown prose, not code. However, the following content patterns are relevant:

### README SCA Section -- Current vs Target

**Current (line 94-95):**
```markdown
### Static Code Analysis (SCA)
Instructors create code findings with CWE references and severity levels. Students classify and assess each finding. A review matrix tracks student submission progress. Findings can be imported into the Vulnerability Manager.
```

**Target (3-5 sentences covering full student experience):**
The paragraph should cover: 12 pre-seeded findings with syntax-highlighted code snippets showing the vulnerable line, difficulty levels (Easy/Medium/Advanced), prev/next navigation between findings, classification workflow (confirmed/false positive/needs investigation), and a completion banner when all 12 are submitted.

### README For Instructors Section -- Additions Needed

After the existing "What Students Can Observe" list, the "For Instructors" section needs to mention:
- Answer key: standalone page at `/sca/answer-key` (professor/admin only) showing expected classifications, reasoning, and discussion prompts for all 12 findings
- Inline answer key: collapsible section on each finding detail page (professor/admin only)
- Student activity tracking: last-active timestamps and current finding being analyzed
- Progress cards: per-student completion summary on the instructor dashboard

### Version History -- v3.1 Entry Structure

Following the existing format:
```markdown
### Version 3.1 (YYYY-MM-DD)
**Polish & Pedagogy:**

**Pedagogy:**
- ...

**French:**
- ...

**Instructor Tools:**
- ...

**Quality:**
- ...
```

### SOLUTION-GUIDE Section Updates Map

| Section | Update Scope | Content |
|---------|-------------|---------|
| 15. SCA Lab | Substantial | Add code snippets, difficulty levels, prev/next nav, completion banner to "How It Works" and "Student workflow" descriptions. Add answer key paragraph to instructor workflow |
| 16. DAST Lab | Minor | One sentence noting all scenarios display in Quebec French |
| 19. Classroom Management | Minor-to-moderate | Add student activity tracking and progress summary cards to Instructor Dashboard Features |
| 20. Pre-Class Checklist | Minor | Add 1-2 verification items: answer key accessible as professor, code snippets render on finding detail |
| Footer (line 1111) | Minor | Change "v3.0" to "v3.1" |

## State of the Art

Not applicable -- this is documentation for an existing application, not a technology choice.

## Open Questions

1. **Ship date for v3.1 entry**
   - What we know: Phase 13 is being researched on 2026-03-20. Phases 6-12 completed over 2026-03-12 through 2026-03-20.
   - What's unclear: The exact date to put on the v3.1 version history entry.
   - Recommendation: Use the date when Phase 13 (documentation) is completed, since that is when the v3.1 content is "shipped." If executing today, use 2026-03-20.

2. **Cross-references between README and SOLUTION-GUIDE**
   - What we know: This is in Claude's discretion. README currently links to SECURITY-BOUNDARY.md but not SOLUTION-GUIDE.md.
   - Recommendation: Add a brief mention in the README "For Instructors" section pointing to SOLUTION-GUIDE.md for detailed teaching guides. This helps new instructors discover the comprehensive guide.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | node:test (built-in, no npm dependency) |
| Config file | none (scripts in package.json) |
| Quick run command | `npm test` (smoke tests, requires running server) |
| Full suite command | `npm run test:integration` (unit/integration, no server needed) |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| DOCS-01 | README reflects current v1.1 state | manual-only | N/A -- visual review of prose accuracy | N/A |
| DOCS-02 | SOLUTION-GUIDE describes answer key and new features | manual-only | N/A -- visual review of prose accuracy | N/A |

**Manual-only justification:** Documentation requirements are about prose accuracy and completeness. There is no behavioral code to test. Verification is done by reading the updated files and confirming they describe the shipped features accurately.

### Sampling Rate
- **Per task commit:** Visual diff review of changed Markdown
- **Per wave merge:** Read full updated sections to confirm coherence
- **Phase gate:** Both files updated, no stale references to pre-v1.1 state

### Wave 0 Gaps
None -- existing test infrastructure covers all phase requirements (which are all manual-only).

## Detailed Gap Analysis

### README.md -- Section-by-Section

| Line(s) | Section | Current State | Gap | Action |
|----------|---------|---------------|-----|--------|
| 90-95 | SCA Lab | 2 sentences, no mention of code snippets or UX features | Missing: code snippets, syntax highlighting, difficulty levels, prev/next nav, completion banner | Expand to 3-5 sentence paragraph |
| 97-98 | DAST Lab | 1 sentence, English only | Missing: French language mention | Add note about Quebec French display |
| 100-111 | VM + Pentest | Accurate | None | No changes (Pentest locked as-is per user decision) |
| 165-175 | npm Scripts | Missing test:integration | Phase 8 added integration tests | Add `npm run test:integration` row |
| 178-213 | For Instructors | No mention of answer key, activity tracking, or progress cards | Missing all v1.1 instructor features | Expand "What Students Can Observe" and add instructor tool mentions |
| 217-337 | Version History | v1.2-v1.9 granular entries, no v3.1 | Needs collapse + new entry | Collapse to milestones, add v3.1 |

### SOLUTION-GUIDE.md -- Section-by-Section

| Section | Line Range | Current State | Gap | Action |
|---------|------------|---------------|-----|--------|
| 15. SCA Lab | 614-679 | Pre-v1.1: no code snippets, no difficulty, no answer key | Missing all v1.1 SCA enhancements | Substantial update |
| 16. DAST Lab | 681-786 | English-only description | Missing French mention | Add one sentence |
| 19. Classroom Mgmt | 1003-1033 | Basic dashboard features only | Missing activity tracking + progress cards | Add new bullet points |
| 20. Pre-Class Checklist | 1035-1061 | 10 items, no v1.1 checks | Missing answer key + code snippet verification | Add 1-2 checklist items |
| Footer | 1111 | "v3.0" | Stale version reference | Update to "v3.1" |

### Features to Document (from completed phases)

| Phase | Feature | README Section | SOLUTION-GUIDE Section |
|-------|---------|---------------|----------------------|
| 6 | Inline code snippets with Prism.js syntax highlighting | SCA Lab | 15. SCA Lab |
| 6 | Vulnerable line highlight (background + left border) | SCA Lab | 15. SCA Lab |
| 6 | Line numbers matching actual file | SCA Lab | 15. SCA Lab |
| 6 | Compact code preview on student-lab cards | SCA Lab | 15. SCA Lab |
| 7 | Security status bar badges in French (AMF, etc.) | (minor, not worth separate mention) | -- |
| 7 | SCA completion celebration banner | SCA Lab | 15. SCA Lab |
| 7 | Prev/next navigation between findings | SCA Lab | 15. SCA Lab |
| 7 | requireAuth on POST /api/instructor-message and GET /api/summary | (internal, not user-facing doc) | -- |
| 8 | Integration tests (sca-review, answer-key-gating, api-auth) | npm Scripts table | -- |
| 9 | SECURITY-BOUNDARY.md | Already done (Phase 9) | -- |
| 10 | DAST scenarios in Quebec French | DAST Lab | 16. DAST Lab |
| 11 | Student activity tracking (last_active_at, current finding) | For Instructors | 19. Classroom Mgmt |
| 11 | Progress summary card (per-student completion) | For Instructors | 19. Classroom Mgmt |
| 12 | Standalone answer key page (/sca/answer-key) | For Instructors | 15. SCA Lab |
| 12 | Answer key: expected classifications, reasoning, discussion prompts | For Instructors | 15. SCA Lab |
| 12 | Inline collapsible answer section on finding detail | For Instructors | 15. SCA Lab |
| 12 | Answer key role-gated (professor/admin only) | For Instructors | 15. SCA Lab |
| 12 | Answer key content in Quebec French | For Instructors | 15. SCA Lab |

## Sources

### Primary (HIGH confidence)
- README.md (337 lines) -- read in full, all sections analyzed
- SOLUTION-GUIDE.md (1111 lines) -- read in full, all 22 sections analyzed
- SECURITY-BOUNDARY.md -- read in full, confirmed up to date (Phase 9)
- REQUIREMENTS.md -- all requirement IDs cross-referenced with completion status
- STATE.md -- project history and decisions verified
- CONTEXT.md -- all user decisions captured and constrained research scope
- package.json -- npm scripts verified
- routes/sca.js -- answer key routes confirmed
- test/ directory -- integration test files confirmed

### Secondary (MEDIUM confidence)
None needed -- all findings verified against primary sources.

### Tertiary (LOW confidence)
None.

## Metadata

**Confidence breakdown:**
- Gap analysis: HIGH -- read both target files in full and cross-referenced against all shipped features
- Content scope: HIGH -- constrained by explicit user decisions in CONTEXT.md
- Version history format: HIGH -- derived from existing entries in README.md

**Research date:** 2026-03-20
**Valid until:** 2026-04-20 (stable -- documentation of already-shipped features)
