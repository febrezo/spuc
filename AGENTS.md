# AGENTS.md

This repository is the source of truth for SPUC behavior and engineering decisions.  
When chat history and repository content diverge, follow repository content.

## Project Intent

SPUC is a defensive STIX Pattern workflow tool:

- parse/normalize STIX patterns
- translate patterns to detection targets
- emulate defensive abilities from STIX patterns
- store/reuse abilities in a local catalog
- plan intrusion sets from cataloged abilities

SPUC must remain defensive and safe.  
Do not implement offensive payload logic or pretend runtime execution exists when it does not.

## Engineering Rules

1. Keep changes small, coherent, and testable.
2. Do not do broad refactors unless required.
3. Preserve existing CLI behavior unless intentionally changed and documented.
4. Do not fake semantics: unsupported means unsupported.
5. Every meaningful code change must include:
   - tests (new or updated)
   - docs updates
6. Prefer file-based persistence for catalog/intrusion-set data in current iterations.

## Immutable Knowledge Artifacts

Never modify these files:

- `kb/standards/STIXPattern.g4`
- `kb/standards/stix-v2.1-cs01.html`

English and Spanish guides are authoritative analyst-facing assets and must preserve intent:

- `kb/guides/GUIDE_EN.md`
- `kb/guides/GUIDE_ES.md`

## Docs To Read Before Coding

1. `README.md`
2. `docs/current-decisions.md`
3. `docs/abilities.md`
4. `docs/catalog.md`
5. `docs/intrusion-sets.md`
6. `docs/ability-roadmap.md`
7. `docs/intrusion-set-roadmap.md`
8. `kb/README.md`

## Working Workflow (Current)

1. Emulate ability:
   - `spuc emulate ...`
2. Translate detections:
   - `spuc translate ...`
3. Save/search catalog:
   - `spuc catalog abilities`
   - `spuc catalog search ...`
   - `spuc catalog translations`
   - `spuc catalog rules`
4. Plan intrusion set:
   - `spuc plan ...`
5. Interactive analyst flows:
   - `spuc explore`
   - then `translate`, `emulate` or `plan`

## Output and UX

- Use multi-section output blocks where available (`summary`, `canonical`, `artifact`, `manifest`).
- Keep terminal output readable and visually separated.
- Keep file outputs explicit and documented.

## Web Modal Convention

For analyst-facing web modals, keep a consistent footer action layout:

- left footer button: `Cancelar`, red (`btn-danger`), closes modal
- right footer button: primary action for the workflow (`Añadir`, `Aplicar`, etc.)
- avoid top-right close buttons in these workflow modals unless explicitly requested

## Session Hygiene

- Always inspect current repository state before implementing.
- Prefer updating existing modules over introducing duplicates.
- If behavior changes, reflect it in tests and docs in the same iteration.
