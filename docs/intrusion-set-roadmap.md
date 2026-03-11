# Intrusion Set Roadmap

## Purpose

Track incremental evolution of intrusion-set composition from local ability catalog entries.

## Current Baseline

- `spuc plan` composes ordered intrusion-set manifests from cataloged abilities.
- Current schema includes:
  - `schema_version`
  - `intrusion_set_id`
  - `name`
  - `description`
  - `confidence`
  - ordered `steps`
- Step fields include:
  - `id`
  - `ability_ref`
  - `platform`
  - optional `after`, `delay_seconds`, `timeout_seconds`
- Interactive planner console exists:
  - `spuc console` -> `plan`
  - guided commands: `show/set/unset/search/filter_by/select/reorder/build`

## Near-Term Steps

1. Validation hardening:
   - stronger checks for step dependency consistency (`after` references)
   - validation of duplicated/reordered step references
2. Catalog integration quality:
   - improved ability filtering UX and richer selectors
3. Intrusion-set templates:
   - starter templates for common validation scenarios

## Medium-Term Steps

1. Extended planning semantics:
   - conditional step gates
   - explicit wait primitives
   - richer timeout/retry controls
2. Bundle/manifests:
   - package intrusion set + referenced abilities for transfer
3. Reporting model:
   - structured execution/report placeholders (still defensive)

## Guardrails

- Intrusion-set manifests are planning artifacts, not an execution engine yet.
- No fake orchestration semantics.
- Keep compatibility and safety constraints explicit.
- Each increment must ship with tests and docs updates.
