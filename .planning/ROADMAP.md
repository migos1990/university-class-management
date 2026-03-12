# Roadmap: HEC Montreal SCA Lab Production Release

## Overview

Transform the existing English-only SCA lab platform into a fully French, classroom-ready experience for tonight's 30+ student application security class at HEC Montreal. The work moves from invisible infrastructure (translation keys, default language) through the student-visible surfaces (login, navigation, SCA workflow) to the instructor monitoring layer, culminating in a full deployment verification that proves the entire chain works end-to-end in Codespaces. Every phase delivers something observable; the final phase is the "does it actually work in the real classroom?" gate.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 1: Translation Foundation** - Default language to French, translation keys in fr.json, localize() helper for seed data
- [ ] **Phase 2: Shared UI Translation** - French login page, sidebar navigation, and error page
- [ ] **Phase 3: SCA Student Experience** - Fully French student workflow with enriched content, guided hints, and difficulty indicators
- [ ] **Phase 4: SCA Instructor Experience** - French instructor dashboard and student-detail views with live class progress stats
- [ ] **Phase 5: Deployment Verification** - Codespaces first-boot, port visibility, and end-to-end French workflow confirmation

## Phase Details

### Phase 1: Translation Foundation
**Goal**: The application defaults to French and has all translation infrastructure ready for template integration
**Depends on**: Nothing (first phase)
**Requirements**: TRAN-01
**Success Criteria** (what must be TRUE):
  1. A new browser session loads the application in French (no manual language selection needed)
  2. The fr.json file contains all SCA, navigation, and shared UI translation keys needed by subsequent phases
  3. A localize() helper exists that returns French content from seed data objects when available, falling back to English
**Plans:** 1 plan

Plans:
- [ ] 01-01-PLAN.md -- Default language to French, localize() helper, bulk SCA translation keys in fr.json and en.json

### Phase 2: Shared UI Translation
**Goal**: Students see French from the moment they open the application -- login, navigation, error pages are all in Quebec French
**Depends on**: Phase 1
**Requirements**: TRAN-06, TRAN-07, TRAN-08
**Success Criteria** (what must be TRUE):
  1. The login page displays all labels, placeholders, buttons, and demo account instructions in French
  2. The sidebar/header navigation shows all links, role badges, and team names in French on every authenticated page
  3. Error pages display friendly French messages with clear guidance on what to do next
**Plans**: TBD

Plans:
- [ ] 02-01: TBD

### Phase 3: SCA Student Experience
**Goal**: Students can complete the entire SCA lab workflow in French -- browsing findings, reading enriched descriptions, classifying vulnerabilities, writing notes, and submitting -- with guided support throughout
**Depends on**: Phase 2
**Requirements**: TRAN-02, TRAN-03, TRAN-09, TRAN-10, SCAC-01, SCAC-02, SCAC-03, SCAC-04
**Success Criteria** (what must be TRUE):
  1. The SCA student lab view lists all 12 findings with French titles, enriched French descriptions including business impact, and difficulty indicators (Facile/Moyen/Avance)
  2. The finding detail view shows classification dropdowns in French (Vrai positif, Faux positif, Necessite une investigation), French form labels, and French placeholder text
  3. Saving a draft and submitting a finding produces French feedback messages (AJAX responses) confirming the action
  4. A dismissible guided workflow intro banner in French explains the analysis approach to students on the lab view
  5. Each finding offers contextual hints in French with scaffolded analysis guidance that helps students understand what good triage looks like
**Plans**: TBD

Plans:
- [ ] 03-01: TBD
- [ ] 03-02: TBD

### Phase 4: SCA Instructor Experience
**Goal**: The instructor can monitor class progress in French -- seeing which students have started, their completion rates, and reviewing individual student submissions
**Depends on**: Phase 3
**Requirements**: TRAN-04, TRAN-05, INST-01
**Success Criteria** (what must be TRUE):
  1. The SCA instructor dashboard displays all table headers, matrix labels, and action buttons in French
  2. The student-detail view (individual student review) is fully in French
  3. Live class progress stats show on the instructor SCA dashboard: number of students started, average completion percentage, and overall class pace -- updating automatically without page refresh
**Plans**: TBD

Plans:
- [ ] 04-01: TBD

### Phase 5: Deployment Verification
**Goal**: The complete French SCA lab works end-to-end in a fresh Codespaces environment with zero manual intervention beyond starting the Codespace
**Depends on**: Phase 4
**Requirements**: DEPL-01, DEPL-02, DEPL-03
**Success Criteria** (what must be TRUE):
  1. A fresh Codespace boots cleanly: npm install completes, seed data populates all 12 findings, all team instances (ports 3001-3012) and the instructor dashboard (port 3000) start without errors
  2. Codespaces port visibility is configured so students on separate machines can access their team's port (public or org-visible)
  3. The full student journey works end-to-end: login (French) -> SCA lab (French) -> select finding -> review detail (French) -> classify + write notes -> save draft (French feedback) -> submit (French feedback) -> instructor dashboard reflects the submission
**Plans**: TBD

Plans:
- [ ] 05-01: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Translation Foundation | 0/1 | Not started | - |
| 2. Shared UI Translation | 0/? | Not started | - |
| 3. SCA Student Experience | 0/? | Not started | - |
| 4. SCA Instructor Experience | 0/? | Not started | - |
| 5. Deployment Verification | 0/? | Not started | - |
