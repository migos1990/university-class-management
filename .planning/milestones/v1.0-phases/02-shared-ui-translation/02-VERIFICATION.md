---
phase: 02-shared-ui-translation
verified: 2026-03-12T15:45:00Z
status: passed
score: 6/6 must-haves verified
re_verification: false
gaps: []
human_verification:
  - test: "Open the login page at http://localhost:3000/ while logged out"
    expected: "All visible text is in Quebec French: form labels (Nom d'utilisateur, Mot de passe, Connexion), subtitle (Plateforme pédagogique de sécurité applicative), demo accounts in French role format, footer text in French. Browser tab reads 'Connexion - HEC Montréal Sécurité applicative'."
    why_human: "EJS rendering with t() calls cannot be confirmed without a live browser request through Express + languageMiddleware."
  - test: "Log in as admin and inspect the sidebar"
    expected: "All section titles in French (Principal, Administration, Enseignement, Apprentissage, Laboratoires de sécurité). Nav links in French (Tableau de bord, Cours, Panneau de sécurité, Journaux d'audit, Configuration AMF, Sauvegardes, Analyse statique, Analyse dynamique, Gestion des vulnérabilités, Test d'intrusion). Role badge shows 'Administrateur'. Logout shows 'Déconnexion'. Security status label shows 'État de sécurité :'. Badge VALUES stay English (MFA: ON, RBAC: ON, etc.)."
    why_human: "Role-conditional nav sections (admin/professor/student) and security badge rendering require a live session."
  - test: "Visit http://localhost:3000/nonexistent to trigger a 404"
    expected: "Error page shows 'Page introuvable' as title and 'La page que vous recherchez n'existe pas ou a été déplacée.' as guidance. Back button reads 'Retour au tableau de bord'. Browser tab reads 'Erreur - HEC Montréal Sécurité applicative'."
    why_human: "Status-code-based lookup (titleMap/guidanceMap) requires Express to render the template with an actual error object."
---

# Phase 2: Shared UI Translation Verification Report

**Phase Goal:** Students see French from the moment they open the application -- login, navigation, error pages are all in Quebec French
**Verified:** 2026-03-12T15:45:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Login page displays all labels, placeholders, buttons, and demo account instructions in French | VERIFIED | login.ejs: 13 t() calls confirmed — auth.username, auth.password, common.login, login.demoAccounts, login.demoAdmin, login.demoProf, login.demoStudent, login.formTitle, login.subtitle, login.loginFailed, auth.invalidCredentials, login.footerText, nav.appSubtitle. No hardcoded English strings found. |
| 2 | Sidebar navigation shows all links, section titles, role badges, and lab names in French | VERIFIED | header.ejs: 26 t() calls confirmed — nav.main, nav.administration, nav.teaching, nav.learning, nav.securityLabs, nav.classes, nav.securityPanel, nav.auditLogs, nav.mfaSetup, nav.backups, nav.myClasses, nav.myEnrollments, nav.staticAnalysis, nav.dynamicAnalysis, nav.vulnManagement, nav.pentestLab, nav.roleAdmin, nav.roleProf, nav.roleStudent, common.dashboard, common.logout, common.close, nav.appSubtitle, nav.defaultTitle, nav.securityStatus. Inline role lookup map confirmed. |
| 3 | Security status bar label is in French while badge values stay in English | VERIFIED | header.ejs line 549: `t('nav.securityStatus')` renders "État de sécurité :". Badge value strings are hardcoded English (MFA: ON/OFF, RBAC: ON/OFF, etc.) per user decision. |
| 4 | Error pages display French title and guidance text per status code (404, 403, 429, 500) | VERIFIED | error.ejs lines 101-115: statusCode variable, titleMap (404/403/429), guidanceMap (404/403/429), errorTitle/errorGuidance fallback to serverErrorTitle/serverErrorGuidance. All 8 errors.* keys (notFoundTitle, forbiddenTitle, tooManyAttemptsTitle, serverErrorTitle, notFoundGuidance, forbiddenGuidance, tooManyAttemptsGuidance, serverErrorGuidance) present in fr.json with proper accents. |
| 5 | Browser tab titles are in French on login, header, and error pages | VERIFIED | login.ejs line 6: `t('login.formTitle') - HEC Montréal t('nav.appSubtitle')`. header.ejs line 6: `t('nav.defaultTitle')` fallback. error.ejs line 6: `t('common.error') - HEC Montréal t('nav.appSubtitle')`. All title keys present in fr.json. |
| 6 | All three templates declare lang=fr on the html element | VERIFIED | login.ejs line 2: `<html lang="fr">`. header.ejs line 2: `<html lang="fr">`. error.ejs line 2: `<html lang="fr">`. No `lang="en"` found in any of the three files. |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `config/translations/fr.json` | All French translation keys for nav, login, and error pages; contains nav.securityPanel | VERIFIED | File exists. All 21 new keys present with proper Unicode accents and cedillas. nav.pentestLab = "Test d'intrusion" (overwritten). |
| `config/translations/en.json` | Matching English fallback keys; contains nav.securityPanel | VERIFIED | File exists. All 21 matching English keys present. |
| `views/login.ejs` | French login page; contains t('auth.username') | VERIFIED | File exists, 178 lines, substantive. Contains t('auth.username') and 12 other t() calls. lang="fr" set. |
| `views/partials/header.ejs` | French sidebar and security bar; contains t('nav.main') | VERIFIED | File exists, 577 lines, substantive. Contains t('nav.main') and 25 other t() calls. lang="fr" set. |
| `views/error.ejs` | French error page with status-code-based messages; contains t('errors.notFoundTitle') | VERIFIED | File exists, 130 lines, substantive. Contains t('errors.notFoundTitle') and all other error keys. Status-code lookup pattern implemented. lang="fr" set. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| views/login.ejs | config/translations/fr.json | t() calls for login.* and auth.* keys | WIRED | Pattern `t('login.` found 7 times; `t('auth.` found 2 times. All referenced keys exist in fr.json. |
| views/partials/header.ejs | config/translations/fr.json | t() calls for nav.* and common.* keys | WIRED | Pattern `t('nav.` found 20 times; `t('common.` found 4 times. All referenced keys exist in fr.json. |
| views/error.ejs | config/translations/fr.json | t() calls for errors.* keys with status-code-based lookup | WIRED | Pattern `t('errors.` found 9 times (8 keys + backToDashboard). titleMap/guidanceMap lookup confirmed. All referenced keys exist in fr.json. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| TRAN-06 | 02-01-PLAN.md | Header/sidebar navigation translated to French (all nav links, role badges, team name) | SATISFIED | header.ejs fully wired with t() calls for all 20+ nav items. Role badge lookup map confirmed. REQUIREMENTS.md marks this [x] Complete. |
| TRAN-07 | 02-01-PLAN.md | Login page fully translated to French | SATISFIED | login.ejs fully wired with 13 t() calls. No hardcoded English user-facing strings. REQUIREMENTS.md marks this [x] Complete. |
| TRAN-08 | 02-01-PLAN.md | Error page translated to French | SATISFIED | error.ejs uses status-code lookup with 9 t() calls for errors.* namespace. Four status codes (404, 403, 429, 500) covered. REQUIREMENTS.md marks this [x] Complete. |

No orphaned requirements — no additional Phase 2 requirement IDs appear in REQUIREMENTS.md beyond the three claimed in the plan.

### Anti-Patterns Found

None. No TODO, FIXME, XXX, HACK, PLACEHOLDER, or stub patterns found in any of the 5 modified files.

### Human Verification Required

#### 1. Login Page Rendering

**Test:** Start the server and visit `http://localhost:3000/` while not logged in.
**Expected:** All visible text is in Quebec French: form labels ("Nom d'utilisateur", "Mot de passe", "Connexion"), subtitle ("Plateforme pédagogique de sécurité applicative"), demo accounts with French role names, footer text in French. Browser tab reads "Connexion - HEC Montréal Sécurité applicative".
**Why human:** EJS rendering with t() calls cannot be confirmed without a live browser request through Express + languageMiddleware binding `res.locals.t`.

#### 2. Authenticated Sidebar (All Three Roles)

**Test:** Log in as admin, professor, and student — inspect the sidebar for each.
**Expected:** Admin: section titles "Principal", "Administration", "Enseignement", "Laboratoires de sécurité" all in French; links in French; role badge "Administrateur". Professor: "Enseignement" section with "Mes cours". Student: "Apprentissage" section with "Mes inscriptions". Security status label reads "État de sécurité :" with English badge values (MFA: ON, RBAC: ON, etc.). Logout button reads "Déconnexion".
**Why human:** Role-conditional nav sections and security badge rendering require a live session with a real user object.

#### 3. Error Page Per Status Code

**Test:** Visit `/nonexistent` (404), then trigger a 403 and 429 if possible.
**Expected:** 404 shows "Page introuvable" + "La page que vous recherchez n'existe pas ou a été déplacée." + "Retour au tableau de bord" button. 403 shows "Accès refusé" + appropriate guidance. Generic errors show "Erreur du serveur" + guidance. Browser tab reads "Erreur - HEC Montréal Sécurité applicative".
**Why human:** Status-code-based titleMap/guidanceMap lookup requires Express to render with an actual error object containing `error.status`.

### Gaps Summary

None. All six observable truths are verified against the actual codebase. All five artifacts exist, are substantive, and are wired. All three key links (login → fr.json, header → fr.json, error → fr.json) are confirmed by t() call patterns and matching key presence. All three requirement IDs (TRAN-06, TRAN-07, TRAN-08) are satisfied. No anti-patterns found. Three items require human verification with a live server but no automated checks failed.

---

_Verified: 2026-03-12T15:45:00Z_
_Verifier: Claude (gsd-verifier)_
