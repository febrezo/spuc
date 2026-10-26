# SPUC Catalog

## Purpose

SPUC keeps a local, file-based rules catalog built from translated STIX
patterns. Catalog operations are exposed through the web interface
(`spuc web`) and through the CLI `catalog` command family.

- `rules` represent cataloged STIX rules plus their translation metadata
  (TLP, PAP, TTP, observables, indicates, confidence).
- Translation activity is recorded in a separate append-only log so the
  grid can show per-target statuses.

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

- rules store: `<config_root>/catalog/rules.json`
- activity log: `<config_root>/catalog/translation_activities.jsonl`
- seeding marker: `<config_root>/catalog/rules.json.seeded`

## Command Shape

The `catalog` command family exposes:

- `catalog abilities` (deprecated alias kept for compatibility, lists rules)
- `catalog search <text>`
- `catalog translations`
- `catalog rules`

## Rules

Search and list:

```bash
spuc catalog rules
spuc catalog search cmd.exe
```

Show one rule by table index or `rule_id`:

```bash
spuc catalog rules show 1
```

## Rule Row Fields

- `RULE_ID` (STIX indicator id, `indicator--...`)
- `NAME`
- `CONFIDENCE`
- `RULE` (the source STIX pattern)

Translation statuses are derived only from visible translate activity rows.
Hidden legacy rows (if any) are never counted.

## Show Semantics

`show` accepts:

- the enumerated row index from the latest listing order
- the object id (`indicator--...`)

For rules, `show` prints the rule body, confidence, TLP/PAP, TTP,
observables, indicates and observed catalog activity.

## Interactive (`console`)

Inside `spuc console`:

```text
rules
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
back
```

After `show`, the current selection is reflected in the prompt:

```text
spuc (rules @ indicator--...)>
```

In `console`, numeric indexes for `show` resolve against the latest
`list`/`search` results for that object family. `back` first leaves the
selected-object context and then returns to the main `spuc>` prompt.

## Catalog persistence integrity (post-emulation)

`catalog/rules.json` is a local file-based rules store. Writes acquire an
exclusive `catalog/rules.json.lock` file lock and commit through a temporary
file in the same directory, followed by file synchronization and atomic rename.
On Unix, the parent directory is also synchronized. The lock file must not be
deleted during active use. Rust 1.89+ is required for standard-library file
locking. Concurrent SPUC processes should use a local filesystem with working
advisory file locks; network filesystems require separate qualification.

An unreadable or malformed existing rules store now causes rule operations
to fail rather than treating it as an empty store. Back up the directory and
repair the file before retrying; never delete `rules.json` to bypass errors.
The legacy abilities migration marker remains independent and must be tested
with representative legacy data before releasing an upgrade.
