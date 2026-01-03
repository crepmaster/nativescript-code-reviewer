# Quickstart — Phase 1 Gate (Boot & Entry)

## Prérequis
- Node.js 20
- npm

## Intégration projet (vendoring)
1) Copier dans le projet :
- `tools/nativescript-reviewer/`
- `tools/run-phase1.js`

2) Ajouter le script npm (package.json racine) :
```json
{
  "scripts": {
    "reviewer:phase1": "node tools/run-phase1.js"
  }
}
