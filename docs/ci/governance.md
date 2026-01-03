# Gouvernance — NativeScript Reviewer Phase 1

## Objectif
Ce document définit les règles d’évolution de la Phase 1 afin de garantir :
- stabilité
- prévisibilité
- absence de faux positifs

---

## Principe fondamental
Une règle Phase 1 est une **loi technique**.
Elle ne doit jamais être :
- ambiguë
- heuristique
- dépendante de l’environnement

---

## Ajout d’une nouvelle règle

1. La règle est introduite en **WARN**
2. Elle est observée sur plusieurs PR
3. Les faux positifs sont éliminés
4. La règle peut être promue en **BLOCKER**

Aucune règle BLOCKER ne doit être ajoutée sans période d’observation.

---

## Modification d’une règle existante
- Toute modification doit être **rétro-compatible**
- Les messages d’erreur doivent rester explicites et actionnables
- Les IDs de règles sont **immutables**

---

## Versioning
- La Phase 1 est versionnée de manière sémantique
- `v1.x` : ajustements internes, pas de rupture
- `v2.0` : changement de contrat (rare)

---

## Anti-flakiness
Les règles Phase 1 doivent respecter :
- pas d’accès réseau
- pas de build
- pas de dépendance OS
- pas d’analyse non déterministe

---

## Philosophie
La Phase 1 protège le projet contre :
- les régressions invisibles
- les démarrages instables
- la dette technique silencieuse

Elle est volontairement stricte, mais toujours explicable.
