# Ability Roadmap

## Purpose

Track incremental, testable evolution of SPUC defensive abilities.

## Current Baseline

- `spuc emulate` builds defensive ability descriptors from supported STIX predicates.
- Current materialized subset includes file/directory/content plus process (`command_line/name/cwd`), Windows registry subset and destination-side network/DNS probes.
- Ability schema is versioned (`schema_version`).
- Export targets:
  - `spuc-agent` (canonical JSON + execution plan hints for file/directory materialization)
  - `bash` (concrete materialization for supported actions)
  - `powershell` (concrete materialization for supported actions, including Windows registry subset)
  - `atomic-red-team` (Atomic Red Team YAML)
  - `mitre-caldera` (MITRE Caldera ability JSON)
- Local catalog persistence is always enabled for `spuc emulate`.
- Interactive uses command-style emulate flow (`spuc console` -> `emulate <rule> to ...`).

## Near-Term Steps

1. Strengthen schema contract:
   - explicit schema validation helper and stricter field checks per action type
   - fixture corpus for compatibility testing
2. Improve STIX-to-ability semantics:
   - refine supported observables already included
   - add conservative support for additional observables where semantics are defensible
3. Expand exporter architecture:
   - refine `atomic-red-team` and `mitre-caldera` mapping quality and metadata fidelity
4. Traceability metadata:
   - optional author/source/tags fields with clear semantics

## Medium-Term Steps

1. Capability model maturation:
   - richer required/optional capability taxonomy
   - better host compatibility probing in `spuc-agent`
2. Action granularity:
   - clearer action classes and constraints
3. Signed/attested artifacts:
   - integrity metadata for ability interchange

## Guardrails

- Defensive-only behavior.
- No runtime offensive logic.
- Conservative semantic claims only.
- Every increment includes tests + docs updates.
