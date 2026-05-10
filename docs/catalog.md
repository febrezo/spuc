# SPUC Catalog

## Purpose

Catalog operations are exposed through two top-level command families:

- `rules`
- `adversaries`

They are also available in `spuc console` under the Catalog section of help.

`rules` represent cataloged STIX rules plus their defensive emulation metadata.
`adversaries` represent saved planned manifests derived from catalog abilities.

## Location

SPUC resolves the catalog root from the user configuration directory:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/spuc`
- macOS: `$HOME/Library/Application Support/spuc`
- Windows: `%APPDATA%\\spuc`

Override with:

```bash
SPUC_CONFIG_DIR=/custom/path spuc ...
```

Underlying persisted data remains file-based:

- abilities: `<config_root>/abilities/*.json`
- activity log: `<config_root>/catalog/translation_activities.jsonl`
- adversary manifests: `<config_root>/intrusion_sets/*.{yaml,yml,json}`

## Command Shape

Both command families expose the same analyst-facing verbs:

- `list`
- `search`
- `show`
- `export`
- `edit`
- `delete`

## Rules

Search and list:

```bash
spuc rules list
spuc rules search
spuc rules search cmd.exe
spuc rules search "process:command_line" --limit 20
```

Show one rule by table index or `rule_id`:

```bash
spuc rules show 1
spuc rules show rule-1234abcd
```

Export one rule to emulation targets:

```bash
spuc rules export 1 --to spuc-agent --output ./artifacts
spuc rules export rule-1234abcd --to bash --to powershell --output ./artifacts
spuc rules export rule-1234abcd --to atomic-red-team --to mitre-caldera --output ./artifacts
```

Editable fields:

- `name`
- `description`
- `confidence`

Edit:

```bash
spuc rules edit 1 --name "Echo validation rule" --confidence 80
spuc rules edit rule-1234abcd --description "Updated analyst text"
```

Delete:

```bash
spuc rules delete 1
spuc rules delete rule-1234abcd
```

Deletion requires manual confirmation typed in the terminal.

`rules search` columns:

- `#`
- `RULE_ID`
- `NAME`
- `CONFIDENCE`
- `EMULABLE`
- `RULE`

`RULE` is always printed in full.

## Adversaries

Search and list:

```bash
spuc adversaries list
spuc adversaries search
spuc adversaries search validation
spuc adversaries search linux --limit 10
```

Show one adversary by table index or `adversary_id`:

```bash
spuc adversaries show 1
spuc adversaries show adversary-1740000000000
```

Export one adversary for an executor:

```bash
spuc adversaries export 1 --to spuc-agent --output ./out
spuc adversaries export adversary-1740000000000 --to bash --output ./out --show summary,artifact,manifest
spuc adversaries export adversary-1740000000000 --to atomic-red-team --output ./out --show summary,artifact,manifest
```

Editable fields:

- `name`
- `description`
- `confidence`

Edit:

```bash
spuc adversaries edit 1 --name "Linux validation adversary"
spuc adversaries edit adversary-1740000000000 --description "Updated plan"
```

Delete:

```bash
spuc adversaries delete 1
spuc adversaries delete adversary-1740000000000
```

Deletion requires manual confirmation typed in the terminal.

`adversaries search` columns:

- `#`
- `ADVERSARY_ID`
- `NAME`
- `CONFIDENCE`
- `STEPS`
- `PLATFORMS`
- `DESCRIPTION`

## Show Semantics

`show` accepts:

- the enumerated row index from the latest listing order
- the object id (`rule-...` / `adversary-...`)

For rules, `show` prints the rule body, confidence, emulability and observed catalog activity.

For adversaries, `show` prints the analyst-facing adversary id, the persisted STIX `intrusion_set_id` (`intrusion-set--<uuid>` for newly created plans, with legacy ids still accepted), platforms, confidence, description and referenced `ability_ref` ids.

## Export Semantics

`rules export` writes one exported artifact per selected emulation target.

`adversaries export` re-materializes the saved adversary through the same planning/export path used by `plan`, writing:

- manifest output
- one exported artifact per referenced ability

## Interactive (`console`)

Inside `spuc console`:

```text
rules
adversaries
```

`rules` opens a dedicated subprompt:

```text
spuc (rules)>
```

Available commands inside:

```text
list [limit=<n>]
search [text] [limit=<n>]
show [index|rule-id]
export <index|rule-id> to <spuc-agent[,bash,powershell,atomic-red-team,mitre-caldera]> [out=<dir>]
export <spuc-agent[,bash,powershell,atomic-red-team,mitre-caldera]> [out=<dir>]
edit <index|rule-id> [name=<text>] [description=<text>] [confidence=<0..100>]
delete <index|rule-id>
back
```

After `show`, the current selection is reflected in the prompt:

```text
spuc (rules @ rule-1234abcd)>
```

In that selected context, `export` can omit the id and uses the current rule.

`adversaries` opens the analogous subprompt:

```text
spuc (adversaries)>
```

Available commands inside:

```text
list [limit=<n>]
search [text] [limit=<n>]
show [index|adversary-id]
export <index|adversary-id> to <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera> [out=<dir>] [show=summary,artifact,manifest]
export <spuc-agent|bash|powershell|atomic-red-team|mitre-caldera> [out=<dir>] [show=summary,artifact,manifest]
edit <index|adversary-id> [name=<text>] [description=<text>] [confidence=<0..100>]
delete <index|adversary-id>
back
```

After `show`, the prompt becomes:

```text
spuc (adversaries @ adversary-1234abcd)>
```

In `console`, numeric indexes for `show/export/edit/delete` resolve against the latest `list`/`search` results for that object family. `back` first leaves the selected-object context and then returns to the main `spuc>` prompt.
