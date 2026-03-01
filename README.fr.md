> **[Read in English](README.md)** | Français (actuel)

# HEC Montréal - Plateforme de sécurité applicative
## Système de gestion de cours universitaires

Cette application permet aux étudiants d'apprendre la sécurité applicative par l'expérience pratique grâce à des fonctionnalités de sécurité activables et désactivables. Conçue pour le cours de sécurité applicative de HEC Montréal.

---

## Démarrage rapide (GitHub Codespaces)

GitHub Codespaces vous offre un environnement de développement complet dans le nuage — aucune installation de Node.js ou d'autre logiciel n'est requise sur votre machine.

1. Depuis la page du dépôt GitHub, cliquez sur le bouton vert **Code**, puis sélectionnez l'onglet **Codespaces**.
2. Cliquez sur **Create codespace on main** (ou la branche de votre choix).
3. Attendez que le conteneur se construise. La configuration s'exécute automatiquement (`npm install`, initialisation de la base de données, génération du certificat SSL).
4. L'application démarre automatiquement. Lorsque le port **3000** est détecté, cliquez sur **Open in Browser** pour accéder au **Tableau de bord de l'instructeur**.
5. Depuis le tableau de bord, vous pouvez voir toutes les instances d'équipe, suivre la progression et diffuser des messages.

> **Notes Codespaces**
> - L'application démarre automatiquement à chaque lancement de Codespace via `postStartCommand`.
> - Le port 3000 est le **Tableau de bord de l'instructeur** et s'ouvre automatiquement.
> - Les ports des équipes (3001–3012) sont identifiés par les noms d'équipe (Alpha à Lima) dans l'onglet **Ports**.
> - Pour partager une instance d'équipe avec les étudiants, faites un clic droit sur un port dans l'onglet **Ports** et réglez la visibilité sur **Public**.
> - Pour exécuter moins d'équipes (économise la mémoire) : arrêtez l'application, puis `TEAM_COUNT=4 npm start`.

### Exécution locale (alternative)

**Prérequis :** [Node.js](https://nodejs.org) LTS (v18 ou plus récent).

```bash
# 1. Installer les dépendances
npm install

# 2. Initialiser la base de données, insérer les données de démonstration, générer les certificats SSL
npm run setup

# 3. Démarrer l'application (lance le tableau de bord de l'instructeur + toutes les instances d'équipe)
npm start
```

Le Tableau de bord de l'instructeur s'ouvre à **http://localhost:3000**. Les instances d'équipe s'exécutent sur les ports 3001–3012.

> **Conseils pour Windows**
> - Si `npm` n'est pas reconnu, redémarrez votre terminal après l'installation de Node.js.
> - Si vous rencontrez des erreurs de permission, essayez d'exécuter le terminal en tant qu'Administrateur.

---

## Comptes de connexion par défaut

### Compte administrateur (accès complet)
- Nom d'utilisateur : `admin`
- Mot de passe : `admin123`

### Comptes professeurs (peuvent modifier les cours)
- Nom d'utilisateur : `prof_jones` | Mot de passe : `prof123`
- Nom d'utilisateur : `prof_smith` | Mot de passe : `prof123`

### Comptes étudiants
- Nom d'utilisateur : `alice_student` | Mot de passe : `student123`
- Nom d'utilisateur : `bob_student` | Mot de passe : `student123`
- Nom d'utilisateur : `charlie_student` | Mot de passe : `student123`
- Nom d'utilisateur : `diana_student` | Mot de passe : `student123`
- Nom d'utilisateur : `eve_student` | Mot de passe : `student123`

---

## Fonctionnalités de sécurité

Connectez-vous en tant qu'**admin** et visitez le **Panneau de sécurité** pour activer ou désactiver ces fonctionnalités :

1. **Authentification multifacteur (MFA)** - Exiger Google Authenticator pour la connexion administrateur
2. **Contrôle d'accès basé sur les rôles (RBAC)** - Restreindre l'accès selon les rôles des utilisateurs
3. **Chiffrement des mots de passe** - Hacher les mots de passe avec bcrypt
4. **Chiffrement des données** - Chiffrer les données sensibles (NAS, notes) avec AES-256-CBC
5. **HTTPS/TLS** - Sécuriser les communications par le chiffrement en transit
6. **Journalisation d'audit** - Suivre toutes les actions des utilisateurs
7. **Limitation du débit** - Protection contre les attaques par force brute (5 tentatives par 15 minutes)
8. **Séparation des tâches** - Exiger l'approbation de l'administrateur pour la suppression de cours par les professeurs
9. **Sauvegardes de la base de données** - Sauvegardes automatiques planifiées à intervalles configurables
10. **Apportez votre propre clé (BYOK)** - Téléverser des clés de chiffrement personnalisées pour la protection des données

---

## Laboratoires du programme de sécurité

La plateforme comprend quatre laboratoires spécialisés pour la formation pratique en sécurité :

### Analyse statique de code (SCA)
Les instructeurs créent des constats de code avec des références CWE et des niveaux de sévérité. Les étudiants classifient et évaluent chaque constat. Une matrice de révision suit la progression des soumissions étudiantes. Les constats peuvent être importés dans le gestionnaire de vulnérabilités.

### Tests dynamiques de sécurité des applications (DAST)
Scénarios de vulnérabilité prédéfinis avec des guides d'exploitation étape par étape. Les étudiants exécutent des tests et soumettent des constats avec des évaluations de sévérité et des scores CVSS. Les scénarios peuvent être importés dans le gestionnaire de vulnérabilités.

### Gestionnaire de vulnérabilités (VM)
Un registre central de vulnérabilités qui regroupe les constats des laboratoires SCA, DAST et Pentest. Suivi de l'état des vulnérabilités (`open` → `in_progress` → `resolved` → `wont_fix`) avec niveaux de priorité, suivi des correctifs, commentaires et historique complet des états.

### Tests d'intrusion (Pentest)
Les étudiants mènent des missions de tests d'intrusion selon une méthodologie en 5 phases :
1. Reconnaissance
2. Énumération
3. Identification des vulnérabilités
4. Exploitation
5. Rédaction du rapport

Chaque mission suit les notes, constats et rapports spécifiques à chaque phase. Les instructeurs peuvent réviser et noter les missions soumises.

---

## Fonctionnement

Lorsque vous exécutez `npm start`, le système lance :
- **Tableau de bord de l'instructeur** sur le port 3000 — surveiller toutes les équipes, les configurations de sécurité, la progression des laboratoires, diffuser des messages
- **Instances d'équipe** sur les ports 3001–3012 — chaque équipe dispose de sa propre base de données isolée et de sa propre instance applicative

### Configuration des équipes

Modifiez `classroom.config.json` pour personnaliser les noms d'équipe, les ports et d'autres paramètres.

Pour exécuter moins d'équipes (utile pour les classes plus petites ou les ressources limitées) :
```bash
TEAM_COUNT=4 npm start   # Lance uniquement les équipes 1 à 4
```

### Arrêt de l'application

```bash
npm stop    # Arrête proprement toutes les instances d'équipe
```

---

## Inspection de la base de données

L'application utilise une base de données au format JSON. Chaque instance d'équipe stocke ses données dans `instances/team-N/database/`.

### Éléments à observer :
- Tableau `users` : observer le chiffrement des mots de passe (texte clair vs hachages bcrypt)
- Tableau `enrollments` : observer le chiffrement des notes (texte clair vs chiffré)
- Tableau `audit_logs` : suivre toutes les actions des utilisateurs
- Activez ou désactivez les fonctionnalités de sécurité et rechargez le fichier pour voir les changements!

---

## Dépannage

**L'application ne démarre pas?**
- Assurez-vous d'avoir exécuté `npm run setup` d'abord (fait automatiquement dans Codespaces)
- Vérifiez que les ports 3000–3012 sont disponibles

**Impossible de se connecter après avoir activé MFA?**
- Assurez-vous d'avoir complété la configuration MFA d'abord
- Utilisez l'application Google Authenticator pour obtenir le code à 6 chiffres

**Besoin de réinitialiser une équipe?**
- Utilisez le bouton « Réinitialiser » dans le Tableau de bord de l'instructeur, ou supprimez le dossier `instances/team-N/database/` de l'équipe et redémarrez

---

## Scripts npm disponibles

| Commande | Description |
|----------|-------------|
| `npm install` | Installer toutes les dépendances |
| `npm run setup` | Initialiser la base de données, insérer les données de démonstration et générer les certificats SSL |
| `npm start` | Démarrer le tableau de bord de l'instructeur + toutes les instances d'équipe |
| `npm stop` | Arrêter toutes les instances en cours d'exécution |
| `npm test` | Exécuter les tests de fumée sur l'équipe Alpha (port 3001) |
| `npm run test:open` | Exécuter les tests de fumée et ouvrir automatiquement le rapport dans un navigateur |

---

## Pour les instructeurs

Cette application est conçue pour enseigner les concepts de sécurité applicative à des étudiants non techniques. Chaque fonctionnalité de sécurité peut être activée ou désactivée pour démontrer la différence entre les implémentations sécurisées et non sécurisées.

### Vérification avant le cours

Exécutez le test de fumée avant le cours pour vous assurer que l'application fonctionne correctement :

```bash
npm test
```

Cela génère un rapport HTML (`test-report.html`) affichant :
- Tests de connexion pour tous les rôles d'utilisateur (administrateur, professeur, étudiant)
- Vérification de l'accès aux pages
- État de réussite/échec avec détails des erreurs

### Ce que les étudiants peuvent observer

- Données en texte clair vs données chiffrées dans la base de données
- Différents niveaux d'accès selon les rôles
- Processus d'authentification MFA
- Connexions HTTP vs HTTPS
- Pistes d'audit des actions des utilisateurs
- Limitation du débit en action
- Processus de séparation des tâches pour la suppression de cours
- Processus de sauvegarde et de récupération
- Gestion de clés de chiffrement personnalisées (BYOK)
- Laboratoires pratiques de sécurité : SCA, DAST, gestion des vulnérabilités et tests d'intrusion

### Panneau de sécurité

Le Panneau de sécurité redessiné (Admin → Sécurité) affiche chaque fonctionnalité sous forme de carte avec :
- Description claire de la fonctionnalité
- Indicateur visuel de l'impact (p. ex., « admin123 » → « $2b$10$xK3... »)
- Interrupteur de basculement facile à utiliser

---

## Historique des versions

### Version 3.0 (2026-02-27)
**Simplification axée sur Codespaces :**

- **Le mode classe est désormais le mode par défaut** — `npm start` lance le tableau de bord de l'instructeur + toutes les instances d'équipe
- **Démarrage automatique dans Codespaces** — l'application se lance automatiquement au démarrage du Codespace
- **Nombre d'équipes configurable** — utilisez la variable d'environnement `TEAM_COUNT` pour exécuter moins d'instances
- **Détection des URL Codespaces** — les liens du tableau de bord fonctionnent correctement dans Codespaces (détection automatique des URL de redirection de port)
- **Scripts npm simplifiés** — suppression des scripts `classroom:*` redondants; `npm stop` remplace `npm run classroom:stop`
- **Écoute sur 0.0.0.0** — assure le bon fonctionnement de la redirection de port dans Codespaces

### Version 2.0 (2026-02-02)
**Refonte majeure de l'interface et image de marque HEC Montréal :**

**Nouvelles fonctionnalités :**
- **Image de marque HEC Montréal** - Couleurs officielles (#002855 marine), logo et style appliqués partout
- **Navigation par barre latérale** - Disposition moderne avec barre latérale fixe remplaçant la navigation supérieure
- **Panneau de sécurité en cartes** - Chaque fonctionnalité de sécurité affichée sous forme de carte avec aperçu de l'impact
- **Script de test de fumée** - Exécutez `npm test` pour vérifier toutes les fonctions clés avant le cours
- **Messages d'erreur améliorés** - Rétroaction plus claire en cas d'échec de connexion

**Améliorations de l'interface :**
- En-têtes de page cohérents avec titre et sous-titre
- Cartes de statistiques sur le tableau de bord administrateur
- Style des tableaux amélioré
- Meilleure gestion des états vides
- Barre d'état de sécurité fixe

**Pour les instructeurs :**
- Nouvelle commande `npm test` générant un rapport HTML
- Tests de connexion automatiques pour les 3 rôles
- Affichage réussite/échec avec informations d'erreur détaillées

**Changements majeurs :**
- Traduction française retirée (anglais seulement)
- Sélecteur de langue retiré de l'en-tête

---

### Version 1.9 (2026-02-01)
**Correctif majeur - Retour au patron de gabarits fonctionnel :**
- Retour de tous les gabarits EJS au patron fonctionnel de la v1.2 `<%- include('partials/header') %>` / `<%- include('partials/footer') %>`
- Le patron cassé `const body = \`...\`` utilisant les littéraux de gabarit a été complètement retiré
- Tous les gabarits utilisent maintenant la syntaxe EJS standard qui fonctionne de manière fiable
- Restauration de `views/partials/header.ejs` et `views/partials/footer.ejs`
- En-tête mis à jour avec le support de traduction (français) et le badge SoD
- Suppression de `views/layout.ejs` (non nécessaire avec les partiels header/footer)
- **IMPORTANT** : Supprimez complètement votre ancien dossier `university-class-management` avant l'extraction

### Version 1.8 (2026-02-01)
**Note :**
- Construction neuve avec tous les correctifs de gabarits EJS confirmés (problèmes persistants en raison du patron de gabarit cassé)
- **Utilisez la v1.9 à la place**

### Version 1.7 (2026-02-01)
**Correctifs :**
- Un audit automatisé approfondi a trouvé et corrigé la dernière balise EJS non échappée
- Correction de `views/admin/audit-logs.ejs` ligne 56 : `<% }); %>` → `\<% }); %>`

### Version 1.6
**Correctifs :**
- Audit complet et correction de TOUTES les erreurs de syntaxe des gabarits EJS dans l'ensemble de l'application
- Fichiers corrigés avec des balises EJS non échappées dans les littéraux de gabarit (`<%` → `\<%`) :
  - `views/classes/delete-request.ejs`
  - `views/admin/backups.ejs`
  - `views/admin/byok.ejs`
  - `views/admin/dashboard.ejs`
  - `views/admin/security-panel.ejs`
  - `views/admin/audit-logs.ejs`
  - `views/admin/mfa-setup.ejs`
  - `views/admin/deletion-requests.ejs`
  - `views/class-details.ejs`
  - `views/student/dashboard.ejs`
  - `views/session-view.ejs`
  - `views/professor/edit-session.ejs`
  - `views/professor/dashboard.ejs`

### Version 1.5
**Correctifs :**
- Correction partielle des erreurs de syntaxe des gabarits EJS (incomplète)

### Version 1.4
**Mises à jour :**
- Première tentative de correction des erreurs de gabarits EJS

### Version 1.3
**Mises à jour :**
- Mises à jour des paquets et maintenance

### Version 1.2
**Nouvelles fonctionnalités :**
- **Système de traduction française** - Basculer entre l'interface en anglais et en français
- **Séparation des tâches** - Approbation de l'administrateur requise pour la suppression de cours
- **Apportez votre propre clé (BYOK)** - Téléverser des clés de chiffrement personnalisées
- **Sauvegardes planifiées de la base de données** - Sauvegardes automatiques (intervalles de 5 min à 24 h)
- **Documentation enrichie** - Instructions de démarrage pour Windows, consultation de la base de données JSON

**Changements techniques :**
- Ajout de l'infrastructure de traduction i18n
- Ajout de la table `deletion_requests` dans la base de données
- Ajout du système de planification des sauvegardes
- Ajout du support de clés de chiffrement personnalisées
- Table `security_settings` enrichie de 3 nouveaux commutateurs

### Version 1.1 (version initiale - 2026-02-01)
**Fonctionnalités :**
- 7 fonctionnalités de sécurité activables (MFA, RBAC, chiffrement, HTTPS, journalisation d'audit, limitation du débit)
- Tableaux de bord par rôle (administrateur, professeur, étudiant)
- Système de base de données au format JSON
- Insertion de données de démonstration
- Génération de certificat SSL auto-signé

**Commutateurs de sécurité :**
1. Authentification multifacteur (MFA)
2. Contrôle d'accès basé sur les rôles (RBAC)
3. Chiffrement des mots de passe (bcrypt)
4. Chiffrement des champs (AES-256)
5. HTTPS/TLS
6. Journalisation d'audit
7. Limitation du débit
