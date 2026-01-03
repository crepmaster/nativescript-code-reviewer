# NativeScript Reviewer — Phase 1 Gate
## Boot & Entry Sanity Check (v1.0)

### Objectif
La Phase 1 est un **gate CI bloquant** qui garantit qu’une application NativeScript
dispose d’un **point d’entrée valide**, d’une **chaîne de bootstrap saine** et
qu’elle ne contient pas de patterns connus pour provoquer un **échec de démarrage**.

La Phase 1 vise à **détecter les erreurs le plus tôt possible**, sans lancer de build
(Android/iOS), afin d’éviter des pipelines lents, instables ou non déterministes.

---

### Principe
La Phase 1 agit comme une **porte technique automatique** :


Si **au moins une règle BLOCKER échoue**, la Phase 1 échoue et bloque la suite du pipeline.

---

### Portée

#### Inclus
- Résolution et unicité de l’entrypoint
- Cohérence de la configuration de démarrage (bundle / webpack / runtime)
- Chaîne de bootstrap NativeScript (`Application.run`)
- Détection d’imports top-level incompatibles avec le runtime NativeScript
- Sanity checks déterministes et rapides

#### Exclus (volontairement)
- Build Android (Gradle, AAB, APK)
- NDK / AGP / alignment 16 KB
- Tests unitaires
- Lint TypeScript complet
- Sécurité release (signing, versioning)

Ces contrôles appartiennent aux **phases suivantes**.

---

### Contrat d’exécution

- **Commande** : `npm run reviewer:phase1`
- **Durée cible** : < 30 secondes
- **Zéro build** : aucun Gradle, aucun webpack build
- **Aucune dépendance réseau**

#### Codes de sortie
- `0` : PASS (aucun BLOCKER détecté)
- `1` : FAIL (au moins un BLOCKER)

---

### Sévérité

- **BLOCKER**  
  Erreur critique rendant le démarrage instable ou non déterministe.
  Provoque l’échec immédiat du gate.

- **WARN**  
  Risque potentiel ou mauvaise pratique. N’échoue pas la Phase 1 mais doit être corrigé.

---

### Positionnement CI
La Phase 1 doit être exécutée :
- sur chaque **Pull Request vers la branche principale**
- avant tout **job de build** (via `needs: phase1-gate`)

---

### Philosophie
La Phase 1 n’est pas une revue humaine.
C’est une **loi technique déterministe** :
- objective
- reproductible
- non discutable

Elle garantit qu’un projet **peut démarrer correctement** avant toute autre étape.
