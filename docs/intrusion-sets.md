# SPUC Intrusion Sets

## Purpose

`spuc plan` composes ordered intrusion-set steps from abilities stored in the local catalog.
This is an MVP for defensive emulation planning, not a runtime orchestration engine.

## Model

Current intrusion-set schema:

- `schema_version`
- `intrusion_set_id`
- `name`
- `description`
- `confidence`
- `steps[]`
  - `id`
  - `ability_ref`
  - `platform`
  - `after` (optional)
  - `delay_seconds` (optional, reserved)
  - `timeout_seconds` (optional, reserved)

## Location

By default, intrusion-set manifests are stored under:

```text
<config_root>/intrusion_sets/
```

Default output format is YAML (`.yaml`) and it is fixed in this iteration for consistency.

## CLI

Build from explicit ability IDs:

```bash
spuc plan \
  --name "Validation intrusion set" \
  --platform linux \
  --executor spuc-agent \
  --ability abl-001 \
  --ability abl-002 \
  --order abl-002,abl-001 \
  --output ./intrusion_sets
```

Guided flow:

```bash
spuc plan --name "Validation intrusion set" --platform linux --guided
```

Filters over catalog candidates:

```bash
spuc plan \
  --name "Linux validation" \
  --platform linux \
  --search echo \
  --guided
```

## Guided Planner Console (Metasploit-style)

When `--guided` is enabled (or when using `plan` inside `explore`), SPUC opens:

```text
spuc (plan)>
```

When catalog view is active after `search` or `filter_by`, prompt changes to:

```text
spuc (plan @ catalog)>
```

Core commands:

- `help`
- `show`
- `set VARIABLE=value`
- `unset VARIABLE`
- `search <text>`
- `filter_by <field>=<value>`
- `list`
- `show_ability <id|index>`
- `select <id|index>`
- `unselect <id>`
- `reorder <id-or-index,...>`
- `build <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera>`
- `export <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera>`
- `back`

Important variables shown by `show`:

- `INTRUSION_SET_ID`
- `NAME` (required)
- `DESCRIPTION` (defaults to `intrusion set generated with SPUC`)
- `OUTPUT` (defaults to `<config_root>/intrusion_sets/spuc-intrusion-set-<platform>-<snake_case_name>.yaml`)
- `FORMAT` (`yaml`, fixed)
- `SHOW` (`summary,manifest` by default, configurable with `set SHOW=...`)
- `PLATFORM` (required for build; comma-separated list allowed)
- `CONFIDENCE` (default 70)

Display order is consistent in guided mode: variables description block, current variable values, one blank line, then selected abilities.

Dummy helpers for staged execution are supported:

- CLI: `--dummy-sleep <seconds>` and `--dummy-label <text>` (repeatable)
- Guided planner: `add_sleep <seconds>` and `add_label <text>`

`build` now requires an executor argument, for example:

```text
build spuc-agent
build bash
build powershell
build atomic-red-team
build mitre-caldera
```

`export` is an alias of `build` and writes the same manifest + artifacts:

```text
export spuc-agent
export bash
export powershell
export atomic-red-team
export mitre-caldera
```

For `spuc-agent`, SPUC runs validation before writing outputs and fails on inconsistencies.

`list` always enumerates all catalog abilities.

`search` and `filter_by` enter catalog view (same prompt), where typical flow is:

1. `list`
2. `show_ability <id|index>`
3. `select <id|index>`
4. `back`

If `NAME` or `PLATFORM` are missing when a guided planner starts, SPUC prompts for both values interactively.

You can change visible output sections directly in guided mode:

```text
set SHOW=summary,canonical,manifest
```

Allowed values: `summary`, `canonical`, `artifact`, `manifest`, `all`.

## Interactive (`console`)

Inside `spuc console`:

- `plan`
- opens the same planner console (`spuc (plan)>`)

The console uses `spuc (plan)>` in normal mode and `spuc (plan @ catalog)>` in catalog mode, keeping one blank line before/after each prompt for readability.

## Output Blocks

`plan` supports `--show` with one or more values:

- `summary`
- `canonical`
- `manifest`
- `artifact`
- `all`

Example:

```bash
spuc plan --name "Validation" --platform linux,windows --executor spuc-agent --ability abl-001 --show summary,manifest
```

## Build Artifacts

`plan` writes one manifest per selected platform and executor, plus one ability artifact per selected ability.

Default naming pattern:

- manifest: `spuc-intrusion-set-<platform>-<snake_case_name>-<executor>.yaml`
- ability artifact: `spuc-intrusion-set-<platform>-<snake_case_name>-<executor>-<ability_id>.<ext>`

## Limitations

- no real execution engine yet
- no advanced conditions, loops, waits, or branching
- ordering is linear (`after` links are auto-generated)
