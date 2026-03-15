# SPUC Emulation Abilities

## Purpose

SPUC abilities are **defensive emulation descriptors** generated from STIX Patterns.
They are designed for:

- safe simulation in test environments
- purple-team validation
- traceable detection testing
- compatibility checks before controlled execution

This feature does **not** implement offensive payloads or malware behavior.

## Current Scope

- Build command: `spuc emulate`
- Catalog integration: abilities are persisted automatically into local catalog
- Export targets:
  - `spuc-agent` (JSON contract + `execution_plan` for materializable file/directory actions)
  - `bash` (concrete materialization for file/directory/process/network probes where feasible; emits a note when a rule includes Windows registry predicates)
  - `powershell` (concrete materialization for file/directory/process/network and Windows registry where feasible)
  - `atomic-red-team` (Atomic Red Team YAML with platform-aware safe commands)
  - `mitre-caldera` (MITRE Caldera ability JSON with platform-aware safe commands)
- For `atomic-red-team` and `mitre-caldera`, SPUC appends an explicit action trace section so every parseable generated action remains visible in the exported artifact.
- Supported STIX observables in generation:
  - `process:command_line`
  - `process:name`
  - `process:cwd`
  - `file:name`
  - `file:size`
  - `artifact:payload_bin` (string/regex content materialization)
  - `directory:path`
  - `windows-registry-key:key`
  - `windows-registry-key:number_of_subkeys`
  - `windows-registry-key:values[*].name`
  - `windows-registry-key:values[*].data`
  - `windows-registry-key:values[*].data_type` (`REG_SZ` / `REG_DWORD`, `=` only)
  - `network-traffic:dst_ref.value`
  - `network-traffic:dst_ref.type` (`=` / `!=`)
  - `network-traffic:dst_port`
  - `network-traffic:protocols`
  - `domain-name:value`
  - `ipv4-addr:value`
  - `ipv6-addr:value`
  - `url:value` (preserved as conservative observable hint)
- Canonical aliases normalized during ability generation:
  - `win-registry-key:*` -> `windows-registry-key:*`
  - `file:created|modified|accessed` -> `file:ctime|mtime|atime`
  - `file:parent_directory_ref.path` -> `directory:path`
- Structural operators no longer hard-fail ability generation by themselves:
  - `OR` (`ANY`), `FOLLOWEDBY`, and qualifiers (`WITHIN`, `REPEATS`, `START/STOP`) are flattened into predicate extraction.
  - Predicates outside concrete materialization scope are preserved as explicit `emit_observable_hint` actions.
- Unsupported for concrete materialization in v1 (kept as hints when possible):
  - file hash predicates (`file:hashes.*`)
  - binary-hex payload literals (`artifact:payload_bin = h'...'`)
  - process fields `process:pid`, `process:created_time`, `process:is_hidden`
  - network source-side fields (`network-traffic:src_ref.value`, `network-traffic:src_ref.type`, `network-traffic:src_port`)
  - `windows-registry-key:modified_time`
  - file/directory temporal predicates (`file:ctime|mtime|atime`, `directory:ctime|mtime|atime`)
  - observables outside the concrete list above

## CLI Usage

Generate ability for `spuc-agent`:

```bash
spuc emulate \
  --rule "[process:command_line MATCHES '^.*powershell.*-enc.*$']" \
  --to spuc-agent
```

Generate multiple artifact targets and write files to output directory:

```bash
spuc emulate \
  --rule "[process:command_line MATCHES '^.*echo.*$']" \
  --to spuc-agent --to bash --to powershell --to atomic-red-team --to mitre-caldera \
  --output ./artifacts
```

Run with partial mode (skip unsupported rules when possible):

```bash
spuc emulate \
  --file examples/process.stix \
  --to bash \
  --mode partial
```

Validate with agent:

```bash
spuc-agent validate --input ability.json
```

`emulate` follows the same operational style as `translate`:

```bash
spuc emulate --rule "<stix-pattern>" --to <target[,target2]> --output <directory>
```

`emulate` options:

- `--rule` / `--file`
- `--to` (repeatable, defaults to all emulation targets)
- `--output` (directory for materialized artifacts)
- `--export csv` (optional, writes emulation CSV summary to `spuc_emulation_output.csv` in `--output`)
- `--description`
- `--rule-confidence` (`0..100`, default used by ability generation is `70`)
- `--mode` (`strict|partial`)
- `--refresh` (force recalculation of background dual-flow cache)

`emulate` renders only emulation sections on screen, but it also evaluates translation convertibility in background so catalog history stays complete across both flows.

Interactive (`spuc console`) uses the same style:

```text
emulate [process:command_line MATCHES '^.*echo.*$'] to spuc-agent,bash out=./artifacts conf=80
```

## Ability JSON Contract (`spuc-agent`)

### Schema versioning

The contract now includes `schema_version`.

- Current supported schema: `1.0`
- `spuc-agent validate` fails if `schema_version` is missing or unsupported.

### Shape

```json
{
  "schema_version": "1.0",
  "id": "abl-1740000000000",
  "name": "STIX defensive emulation ability",
  "description": "Defensive and controlled telemetry emulation...",
  "supported_platforms": ["linux", "macos", "windows"],
  "requires": [
    {
      "id": "cap.process.spawn",
      "description": "Host can spawn a benign process for telemetry simulation."
    }
  ],
  "optional": [
    {
      "id": "cap.shell.powershell",
      "description": "PowerShell shell available for command-line shaped simulation."
    }
  ],
  "agent_capabilities": ["cap.telemetry.process"],
  "actions": [
    {
      "id": "act-001",
      "title": "Emit process command-line observable",
      "action_type": "emit_process_command_line",
      "observable": "process:command_line",
      "operator": "MATCHES",
      "value": "^.*powershell.*-enc.*$",
      "safe_instructions": "Run a benign command that produces telemetry aligned with this predicate."
    }
  ],
  "source_pattern": "[process:command_line MATCHES '^.*powershell.*-enc.*$']",
  "classification": "command_line_trace",
  "emulation_level": "trace_simulation",
  "confidence": 70
}
```

## Compatibility Model (`spuc-agent`)

`spuc-agent validate` returns:

- `executable`
- `partially_executable`
- `not_executable`

Validation checks include:

1. `schema_version`
2. structural validation
3. platform compatibility (`supported_platforms`)
4. required capabilities (`requires` + `agent_capabilities`)
5. optional capabilities (`optional`)

Reasons are explicit, for example:

- `unsupported platform`
- `missing required capability`
- `optional capability unavailable`

## Current Limitations

- No action runner yet for `spuc-agent` (generation/export/validation only).
- Capability detection uses a basic static profile.
- Semantics are conservative and intentionally scoped.

## Next Increment Candidates

1. Add stricter JSON schema checks (field constraints per action type).
2. Extend supported STIX observable subset incrementally.
3. Add another export target with richer mapping.
4. Add signed metadata and stronger traceability fields.
