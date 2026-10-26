# AGENTS.md

This repository is the source of truth for SPUC behavior and engineering decisions.  
When chat history and repository content diverge, follow repository content.

## Project Intent

SPUC is a defensive STIX Pattern workflow tool:

- parse/normalize STIX patterns
- translate patterns to detection targets (Sigma, KQL, EQL, Snort, Suricata, YARA, ...)
- store/reuse translated rules in a local catalog (`catalog/rules.json`)
- track translation activity in a local activity log (`catalog/translation_activities.jsonl`)
- browse and manage rules through a localized web interface

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
6. Prefer file-based persistence for catalog/translation-activity data in current iterations.

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
3. `docs/catalog.md`
4. `docs/web.md`
5. `docs/deployment.md`
6. `docs/ci-cd.md`
7. `kb/README.md`

## Working Workflow (Current)

1. Translate detections:
   - `spuc translate ...`
2. Verify patterns:
   - `spuc verify ...`
3. Inspect Sigma availability:
   - `spuc sigma status`
4. Browse/manage the rules catalog (web):
   - `spuc web`
5. Serve JSON-RPC:
   - `spuc jsonrpc ...`

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

## Emulation Removed (2026-10)

The `spuc emulate` command, the adversary/payload web surface and the
underlying emulation engine were removed in October 2026. SPUC now
focuses on translating STIX patterns to detection targets and on the
rules catalog workflow. Guided adversary analysis may return later as a
strictly defensive, LLM/agent-assisted feature; until then, do not
re-introduce emulation execution semantics.
