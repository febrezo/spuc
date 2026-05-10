# Empty-State Testing (Fresh Catalog from Zero)

This guide resets SPUC state so web and CLI flows behave as if no local catalog data existed.

## Scope

The reset covers:

- file-based SPUC data under `<config_root>` (rules/abilities/adversaries/STIX objects/users/policies/logs)
- browser-only web state (custom payload catalog, learning progress, UI route/view preferences)

## 1) Resolve and inspect current config root

Linux default:

- `${XDG_CONFIG_HOME:-$HOME/.config}/spuc`

Optional override:

- `SPUC_CONFIG_DIR`

Inspect active path:

```bash
echo "SPUC_CONFIG_DIR=${SPUC_CONFIG_DIR:-<unset>}"
echo "SPUC_ROOT=${SPUC_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/spuc}"
ls -la "${SPUC_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/spuc}" 2>/dev/null || true
```

## 2) Stop running SPUC processes

Close any running `spuc`, `spuc web`, or `spuc-gui` sessions before cleanup.

## 3) Backup then remove file-based state

```bash
SPUC_ROOT="${SPUC_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/spuc}"
mkdir -p "$HOME/.cache/spuc-reset-backups"
if [ -d "$SPUC_ROOT" ]; then
  tar -C "$(dirname "$SPUC_ROOT")" -czf "$HOME/.cache/spuc-reset-backups/spuc-$(date +%Y%m%d-%H%M%S).tgz" "$(basename "$SPUC_ROOT")"
  rm -rf "$SPUC_ROOT"
fi
mkdir -p "$SPUC_ROOT"
```

Expected result:

- `abilities/`, `intrusion_sets/`, `catalog/`, `stix-objects.json`, `web_users.json`, and `web_oauth_policy.json` are absent until recreated by SPUC.

## 4) Clear browser localStorage for SPUC

Open SPUC in the browser, then DevTools Console, and run:

```js
[
  "spuc-web-custom-payloads",
  "spuc-web-learning-progress",
  "spuc-web-last-route",
  "spuc-web-rules-view-mode",
  "spuc-web-adversaries-view-mode",
  "spuc-web-locale",
  "spuc-web-theme",
  "spuc-web-welcome-dismissed"
].forEach((k) => localStorage.removeItem(k));
```

Notes:

- this step is required to validate payload and learning empty states correctly
- clearing `<config_root>` alone does not remove browser localStorage

## 5) Start SPUC in standalone mode

```bash
cargo run -q -- web --port 8090 --no-login --no-open
```

Open:

- `http://127.0.0.1:8090/`

## 6) Validation checklist (must look empty)

1. Rules route shows welcome/empty-state actions (new/import) and no catalog entries.
2. Emulation route shows empty adversary state and create action.
3. Payloads route shows empty payload catalog welcome state.
4. STIX Objects route shows empty catalog welcome state.
5. Learning route has no prior completion progress.

## 7) Minimal end-to-end smoke after reset

1. Create one STIX rule from Laboratory and save.
2. Confirm Rules route now switches from welcome to catalog.
3. Create one payload from Payloads.
4. Confirm Payloads route switches from welcome to table.
5. Create one adversary and save.
6. Confirm Emulation route now lists the created adversary.

## 8) Repeatable QA mode (isolated config root)

Use a disposable root per run:

```bash
export SPUC_CONFIG_DIR="$(mktemp -d /tmp/spuc-e2e-XXXXXX)"
cargo run -q -- web --port 8090 --no-login --no-open
```

When done:

```bash
rm -rf "$SPUC_CONFIG_DIR"
unset SPUC_CONFIG_DIR
```

This avoids touching your normal local catalog.