# Feature Research

**Domain:** Educational SCA (Static Code Analysis) hands-on lab for university application security course
**Researched:** 2026-03-12
**Confidence:** HIGH

## Context

This analysis covers features needed to make the HEC Montreal SCA lab module production-ready for tonight's 30+ student class. The platform already has a working SCA workflow: 12 pre-seeded findings mapped to real CWE vulnerabilities in the codebase, a student review workflow (classify, notes, remediation, save draft, submit), an instructor dashboard with a review matrix, and team-based Codespaces deployment. The gap is that all SCA views are in English, the seed data descriptions are thin, and there are no guided cues for non-technical students.

The feature landscape is assessed through the lens of: what makes a vulnerability triage exercise effective for non-technical French-speaking students, with a single instructor and no TA, in a single evening session.

## Feature Landscape

### Table Stakes (Must Have for Tonight's Class to Work)

Features without which the class experience fails or degrades severely.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Full French translation of all SCA views (student-lab, finding-detail, instructor, student-detail) | Students are French-speaking; English-only interface creates cognitive friction and slows comprehension. The rest of the app partially uses the i18n system but SCA views have zero French strings. | MEDIUM | 4 EJS templates need all hardcoded English replaced with `t()` calls. ~80-100 strings across student-lab.ejs, finding-detail.ejs, instructor.ejs, student-detail.ejs. Must add `sca` section to fr.json. |
| French translation of shared UI (header, footer, login) | The sidebar says "Dashboard", "Logout", "Static Analysis" in English. Login page is entirely English. Students see these first and will be confused. | MEDIUM | Header has ~20 hardcoded English strings (nav labels, section titles, security badges). Login has ~10 strings. Footer is minimal. The i18n infrastructure exists but these views do not use it. |
| Default language set to French | The i18n middleware defaults to English (`req.session.language || 'en'`). Every student would see English on first load. | LOW | One-line change in `utils/i18n.js`: change default from `'en'` to `'fr'`. |
| Smooth save/submit flow with French feedback messages | Current AJAX feedback is in English ("Saving...", "Submitted!", "Draft saved.", "Network error"). Non-technical students need clear French confirmations. | LOW | ~6 strings in the inline JavaScript of student-lab.ejs and finding-detail.ejs need to use translated values or be replaced with French strings. |
| Friendly French error messages | Error page says "Finding not found" in English. 404s and validation errors need French text so students do not hit dead ends. | LOW | Error view already partially uses i18n. SCA route error messages (line 92, 159) are hardcoded English. |
| Classification labels in French | Dropdown options say "True Positive (confirmed vulnerability)", "False Positive", "Needs Further Investigation" in English. These are the core learning concepts. | LOW | ~6 option labels across student-lab.ejs and finding-detail.ejs. Critical for comprehension: students need to understand triage categories in their language. |
| Codespaces first-boot reliability | Students must access their team instance immediately. If seeding fails or the port is not visible, the entire team is blocked. | LOW | Verify that `seedDatabase()` runs correctly on first boot per instance, DATA_DIR isolation works, and ports 3001-3012 are forwarded. This is testing/verification rather than new code. |

### Differentiators (Would Make the Lab Memorable and Engaging)

Features that transform the exercise from "fill out a form" into an impactful learning experience. Not required, but high-value.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Enriched SCA seed data (richer descriptions, educational context) | Current finding descriptions are 1-2 sentences. Non-technical students need more context: why this matters, what the business impact is, what a real attacker could do. Richer descriptions turn each finding into a mini-lesson. | MEDIUM | Rewrite 12 finding descriptions, remediation text, and code snippet context in `utils/seedData.js`. Add business-impact framing. Consider adding French descriptions directly or a `description_fr` field. |
| Contextual hints/tips in the student review form | A small "Hint" or "Conseil" expandable section per finding giving students a starting point for analysis. Research shows scaffolded guidance is the primary differentiator for non-technical student success in security exercises. Students who are stuck will not raise their hand in a 30-person class. | MEDIUM | Could be a `hint` or `analysis_hint` field in the SCA findings seed data, rendered as a collapsible section in the finding-detail view. Alternatively, a static tip per severity level or category. |
| Live class progress stats on instructor dashboard | Current instructor dashboard shows per-finding review counts but no aggregate class stats (e.g., "18/30 students have submitted at least 1 finding", "class is 43% complete", "average time per finding"). The instructor needs at-a-glance awareness to pace the class. | LOW-MEDIUM | Aggregate query on `sca_student_reviews` joined with user count. Display as stat cards at the top of instructor.ejs. Polling-based refresh (every 30s) is sufficient per PROJECT.md. |
| Class consensus indicator per finding | Show the instructor what percentage of students classified each finding as "confirmed" vs "false positive" vs "needs investigation". Enables the instructor to identify findings where students disagree and use those for class discussion. This is the highest-impact teaching feature: the "aha moment" happens when the class debates a contentious finding. | LOW | Data already exists in the matrix. Compute distribution percentages and render as small bar charts or percentage text per finding in the instructor overview table. |
| Severity distribution visual | A small breakdown card showing how many findings are Critical/High/Medium/Low, helping students see the distribution before diving in. Frames the exercise as realistic triage, not just classification. | LOW | Simple count from the existing `findings` array, rendered as colored badges at the top of student-lab.ejs. |
| Guided workflow intro banner | A dismissible card at the top of the student lab view explaining what students should do, how to approach each finding, and what good analysis looks like. Research on security education shows that clear task framing is essential for non-technical students. | LOW | A static French-language banner at the top of student-lab.ejs with 3-4 bullet points. Dismissible with a simple JS toggle. |
| Finding difficulty indicators | Mark findings as easier or harder to triage, so students can start with accessible ones and build confidence before tackling ambiguous cases. Aligns with scaffolded learning research. | LOW | Add a `difficulty` field to seed data ("Facile", "Moyen", "Avance") and display as a badge. Straightforward findings (hardcoded credentials) are easy; ambiguous ones (outdated dependency, rate limiting scope) are harder. |
| Instructor broadcast message to all students | The header already has a broadcast banner that polls `/api/instructor-message`. The instructor can send a French message to all teams ("Concentrez-vous sur les constats de severite Critical d'abord"). Useful for pacing the class without walking to each team. | LOW | Infrastructure already exists in header.ejs. Just needs to be wired to a simple POST endpoint or a form on the instructor dashboard. Verify the endpoint exists. |

### Anti-Features (Deliberately NOT Building Given Time Pressure)

Features that seem good but would risk tonight's class if attempted.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Real-time WebSocket updates on instructor dashboard | Feels more responsive than polling | Adds a dependency (socket.io or ws), complicates the server, risk of connection issues in Codespaces network. Polling at 30s intervals is more than sufficient for a 2-hour class. | Use `setInterval(fetch, 30000)` polling on the instructor dashboard. Already works in header broadcast. |
| Grading/scoring system | Natural for an academic setting | Tonight's exercise is formative, not summative. Adding scores changes student behavior (gaming for points instead of thoughtful analysis). Research shows gamification via leaderboards is less valued by students than real-world problem-solving tasks. | Instructor reviews submissions qualitatively. Can add scoring in a future iteration. |
| Language toggle UI (EN/FR switch) | Seems user-friendly | All students are French-speaking. A toggle adds UI complexity, testing burden, and risk of half-translated states. Defaulting to French is simpler and sufficient. | Hard-default to French. Remove or hide language switching. |
| Auto-grading or "correct answer" comparison | Would give instant feedback | SCA triage is inherently subjective. There is no single "correct" classification for every finding (a vulnerable dependency might be "confirmed" or "needs investigation" depending on context). Auto-grading would teach the wrong lesson: that security analysis has one right answer. | Use class consensus indicators to surface disagreement. Let the instructor lead discussion on ambiguous findings. |
| Mobile responsive design | Some students might use phones | PROJECT.md explicitly states students use laptops. Responsive CSS changes risk breaking the carefully laid-out tables and forms. | Not needed. Students are on laptops in a classroom. |
| New npm dependencies | tempting for many features | Constraint: no new dependencies (time pressure + stability). Every new package is an install step, a compatibility risk, and a Codespaces build-time increase. | Work within Express/EJS/vanilla JS as stated in constraints. |
| Solution guide visible to students | Students might want to check their work | Premature answers undermine the learning exercise. The SOLUTION-GUIDE.md already exists for the instructor to reference during discussion. | Keep solution guide instructor-only. Use hints instead of answers. |
| DAST/Pentest/VM module polish | Other modules exist and could be improved | Tonight is SCA-only. Touching other modules risks regressions in the SCA flow. Focus prevents sprawl. | Explicitly out of scope per PROJECT.md. |
| Elaborate animations or UI polish | Would make the app feel more professional | High risk, low learning impact. CSS animations can break in Codespaces browsers, and time spent on polish is time not spent on content and translation. | Keep the current clean, functional design. Focus on content quality. |

## Feature Dependencies

```
[Default Language to French]
    (no dependencies, immediate change)

[SCA View French Translation]
    requires [Default Language to French] (so translations are actually displayed)
    requires [Classification Labels in French] (part of the same translation work)
    requires [French Error Messages] (error states must also be translated)

[Shared UI French Translation (header, login, footer)]
    requires [Default Language to French]

[Enriched SCA Seed Data]
    (independent, can be done in parallel with translations)
    enhances [Contextual Hints/Tips] (richer data makes hints more meaningful)

[Contextual Hints/Tips]
    requires [Enriched SCA Seed Data] (hints reference finding descriptions)
    requires [SCA View French Translation] (hints must be in French)

[Live Class Progress Stats]
    (independent of translation work)
    enhances [Instructor Dashboard]

[Class Consensus Indicators]
    (independent of translation work)
    enhances [Instructor Dashboard]
    enhances [Live Class Progress Stats] (consensus + progress together give full picture)

[Guided Workflow Intro Banner]
    requires [SCA View French Translation] (banner must be in French)

[Finding Difficulty Indicators]
    requires [Enriched SCA Seed Data] (difficulty metadata added to seed data)

[Instructor Broadcast Message]
    enhances [Live Class Progress Stats] (instructor sees stats, then broadcasts guidance)
```

### Dependency Notes

- **SCA View Translation requires Default Language**: Translations must actually render. If language defaults to English, `t()` calls will pull English strings and nothing changes.
- **Contextual Hints requires Enriched Seed Data**: Hints are only valuable if they reference rich, pedagogically sound descriptions. Thin 1-sentence descriptions cannot support meaningful hints.
- **Live Class Stats and Consensus are independent**: These are purely instructor-side features that do not depend on translation work. They can be built in parallel.
- **Guided Workflow Banner requires SCA Translation**: The banner is part of the student-lab view and must be in French. It makes no sense to add an English banner.

## MVP Definition

### Must Ship Tonight (P0)

Minimum viable experience -- what is needed for 30 students to successfully complete the SCA lab in French.

- [ ] Default language set to French -- 1-line change, unlocks all other translations
- [ ] SCA views fully translated to French -- student-lab, finding-detail, instructor, student-detail
- [ ] Shared UI translated to French -- header sidebar, login page, error page
- [ ] Classification labels in French -- "Vrai positif", "Faux positif", "Necessite une investigation"
- [ ] French feedback messages in AJAX save/submit flow -- "Sauvegarde...", "Soumis!", "Brouillon enregistre."
- [ ] French error messages on SCA routes -- "Constat introuvable" instead of "Finding not found"
- [ ] Codespaces first-boot verification -- confirm seeding, port forwarding, and team isolation

### Should Ship Tonight if Time Allows (P1)

Features that meaningfully improve learning outcomes and instructor experience.

- [ ] Enriched SCA seed data -- richer descriptions, business impact context, educational framing
- [ ] Guided workflow intro banner in French -- explains the task and how to approach analysis
- [ ] Live class progress stats on instructor dashboard -- aggregate completion metrics
- [ ] Class consensus indicators per finding -- distribution of student classifications

### Add After Tonight (P2)

Features to consider for future class sessions.

- [ ] Contextual hints per finding -- scaffolded analysis guidance
- [ ] Finding difficulty indicators -- help students prioritize easier findings first
- [ ] Instructor broadcast message integration -- form on instructor dashboard to send messages
- [ ] Severity distribution visual -- framing card on student lab view
- [ ] Per-finding time tracking -- how long students spend analyzing each finding

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Default language to French | HIGH | LOW | P0 |
| SCA views French translation | HIGH | MEDIUM | P0 |
| Shared UI French translation | HIGH | MEDIUM | P0 |
| Classification labels in French | HIGH | LOW | P0 |
| French AJAX feedback messages | HIGH | LOW | P0 |
| French error messages | MEDIUM | LOW | P0 |
| Codespaces boot verification | HIGH | LOW | P0 |
| Enriched SCA seed data | HIGH | MEDIUM | P1 |
| Guided workflow intro banner | HIGH | LOW | P1 |
| Live class progress stats | MEDIUM | LOW | P1 |
| Class consensus indicators | MEDIUM | LOW | P1 |
| Contextual hints per finding | MEDIUM | MEDIUM | P2 |
| Finding difficulty indicators | LOW | LOW | P2 |
| Instructor broadcast form | LOW | LOW | P2 |
| Severity distribution visual | LOW | LOW | P2 |

**Priority key:**
- P0: Must ship for tonight's class to function
- P1: Should ship to make tonight's class impactful
- P2: Nice to have, defer to future sessions

## Competitor Feature Analysis

| Feature | OWASP Security Shepherd | PentesterLab | Secure Code Warrior | Our Approach |
|---------|------------------------|--------------|---------------------|--------------|
| Vulnerability classification exercise | Lessons + challenges with layman-term explanations | Guided code review with step-by-step walkthroughs | Role-based training with coding labs | 12 real findings in the actual codebase, student classifies + explains reasoning |
| Scaffolded guidance | Lessons before each challenge | Video walkthroughs + written hints | In-app guidance with difficulty levels | Guided intro banner + optional hints per finding (P1/P2) |
| Instructor monitoring | Scoreboard per student | No real-time monitoring | Enterprise reporting dashboard | Real-time review matrix + class progress stats + consensus indicators |
| Language support | English primarily | English primarily | Multi-language | Quebec French default with full i18n infrastructure |
| False positive triage | Not a focus | Mentioned in advanced exercises | Limited | Core mechanic: classify as confirmed/FP/needs investigation |
| Real code context | Hardened real vulnerabilities | Real vulnerable apps | Simulated environments | Actual vulnerabilities in the platform's own codebase (self-referential) |

**Our key differentiator**: Students analyze the very application they are using. The findings are real vulnerabilities in the platform's own code. This self-referential design creates a uniquely engaging "meta" experience that no other platform offers.

## Sources

- [OWASP Application Security Curriculum](https://owasp.org/www-project-application-security-curriculum/) -- educational framework for application security training
- [OWASP Security Shepherd](https://owasp.org/www-project-security-shepherd/) -- classroom-mode security training platform with user-specific solution keys
- [Leveraging Gamification in Cybersecurity Education for Non-Cyber Students](https://www.researchgate.net/publication/378541770_Leveraging_Gamification_and_Game-based_Learning_in_Cybersecurity_Education_Engaging_and_Inspiring_Non-Cyber_Students) -- research on engaging non-technical students, finding real-world problem-solving tasks preferred over leaderboards
- [PentesterLab Code Review Exercise](https://pentesterlab.com/exercises/codereview) -- guided code review training with progressive difficulty
- [OWASP Secure Coding Dojo - Code Review 101](https://owasp.org/SecureCodingDojo/codereview101/) -- structured code review training
- [Cyber Range and Cyber Defense Exercises: Gamification Meets University Students](https://dl.acm.org/doi/10.1145/3617553.3617888) -- ACM study on gamification effectiveness in university cybersecurity courses
- [Monitoring Student Progress in Real Time](https://www.innovationassessments.com/blog/2025/02/09/monitoring-student-progress-in-real-time/) -- instructor dashboard best practices for real-time progress monitoring
- [Vulnerability Triage Best Practices](https://www.getastra.com/blog/dast/false-positive-triage/) -- industry approach to false positive vs true positive classification
- [Secure Code Warrior](https://www.securecodewarrior.com/) -- developer security training platform with role-based, hands-on labs

---
*Feature research for: HEC Montreal SCA Lab Production Release*
*Researched: 2026-03-12*
