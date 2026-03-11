# Web Interface

Last updated: 2026-03-15

## Command

```bash
spuc
spuc web --port 8090 --admin-user admin --admin-password "change-me"
spuc web --port 8090 --no-login
```

`spuc` without subcommands starts standalone mode:
- with `desktop-tauri` feature enabled, it opens a native desktop window (no browser);
- otherwise it falls back to local web mode on `http://127.0.0.1:8090/` with `--no-login`.
- desktop build command: `cargo run --bin spuc --features desktop-tauri`
- Linux desktop prerequisites: WebKitGTK and JavaScriptCoreGTK development packages (`webkit2gtk-4.1` and `javascriptcoregtk-4.1` headers, or distro equivalent).

If `--admin-password` is omitted, SPUC generates a random 25-character administrator password and prints it in startup logs.

## Authentication modes

- Local login (username and password) backed by a local user store.
- `--no-login` mode for standalone local sessions: no login view, implicit administrator role, and logout hidden in UI.
- Optional Google/GitHub provider bootstrap from environment variables (authorization code callback flow enabled).
- OAuth providers must also be authorized by an administrator in `User management` before they can be used in the login screen.
- Login/start view uses centered layout with SPUC logo, app title/subtitle, login panel, and footer links (project, license, coded-with-love).
- In `--no-login`, the sidebar identity is presented as `Local user` (no admin credentials shown in UI text).

## OAuth provider bootstrap

Configure providers with environment variables:

- `SPUC_WEB_GOOGLE_CLIENT_ID`
- `SPUC_WEB_GOOGLE_CLIENT_SECRET`
- `SPUC_WEB_GOOGLE_REDIRECT_URI`
- `SPUC_WEB_GITHUB_CLIENT_ID`
- `SPUC_WEB_GITHUB_CLIENT_SECRET`
- `SPUC_WEB_GITHUB_REDIRECT_URI`

Typical local callback URIs:

- Google: `http://127.0.0.1:8090/api/login/oauth/google/callback`
- GitHub: `http://127.0.0.1:8090/api/login/oauth/github/callback`

When variables are not configured, provider buttons remain visible but disabled.

Even when configured, providers stay disabled until an admin authorizes each provider in `User management`.

## Web interface scope

`spuc web` is another presentation layer for the same defensive SPUC core and currently includes:

- Dashboard overview with KPIs and chart widgets.
- Dashboard includes additional telemetry charts for rule status distribution (`exact/lossy/unsupported`), emulation coverage by exporter counting only `exact/lossy` mappings (excluding `unsupported`), convertible-rule counts by group (`SIEM`/`IDS`/`Content`, any non-red target), and most frequent observable types present in cataloged rules.
- `Conversion quality` and `Convertible rules by group` widgets render as donut/pie-style charts for faster ratio reading.
- `Most used destinations` is restricted to defensive detection targets and includes dynamic `sigma-to-*` targets when `sigma` is available at startup.
- Home (`Inicio`) route is available above Overview and provides a centered welcome-view with stacked action rows (icon, title, short description) for Laboratory, Rules Catalog, Adversary Catalog, Learning, and Donate.
- Left sidebar navigation uses flat primary entries (no nested submenus): Laboratory, Rules, Emulation, and STIX Objects.
- Laboratory is promoted as a main sidebar item and appears above Rules.
- Clicking top-level `Rules`, `Emulation`, or `STIX Objects` opens a centered workspace chooser first; selecting a chooser action moves to the dedicated view and keeps sidebar highlighting in sync.
- Rules workspace starts with a welcome-view launcher (Laboratory, import rules from file, explore rules).
- Bulk rule import from file shows live progress (read phase and save phase) with a visible progress bar and counters.
- Rules search/catalog table is shown only in `explore` mode.
- Rules catalog sorting is controlled from clickable table headers (name, confidence, marking), without a separate sort combobox.
- Rules table supports multi-select bulk operations: delete selected, bulk update for TLP/PAP/confidence, `Select all`/`Deselect all`, and shift-range selection.
- Rules table shows TLP+PAP in a unified `Marking/Clasificación` column.
- STIX rule column is constrained to 25% of the available rules-table width.
- Rules table with per-target output/emulation status chips (`exact/lossy/unsupported`) and click-through detail popovers.
- Rules catalog keeps focused filtering by rule type (SIEM/IDS/Content), confidence, TLP/PAP and observable type.
- Rules catalog includes observable-type filtering and a dedicated observables column (e.g., `process`, `file`, `artifact`) persisted with rule metadata and reused for dashboard statistics.
- Rule metadata includes TLP/PAP comboboxes with normative colors and supports multiple `indicates` relations (STIX ID + object name), validated server-side and visualized with non-intrusive badges/listing in catalog and detail flows.
- STIX objects have a dedicated sidebar route with welcome chooser and catalog view (`id`, inferred `type`, `name`) aggregated from stored `indicates` relations; catalog table controls are consistent with other catalogs (`Select all`, `Enable bulk edit`, `Show/Hide columns`) and remain reusable from the `Create indicates relation` modal.
- `Create indicates relation` is restricted to selecting an existing STIX catalog object; STIX ID/name fields are read-only and shown for context only.
- New STIX objects are created from the dedicated STIX Objects workspace (`Create new object`), not from the relation modal.
- The relation modal includes a `+` shortcut in the top-right corner to open `Create new object` and then return to the same relation flow.
- Rules table includes an explicit STIX objects column that shows related `indicates` objects (e.g., `malware`) and a `+` action to append new relations.
- Emulable rules centralize export and detonation guidance directly inside the emulation detail modal (no separate export modal/button in the table column).
- Markdown-enabled textareas (rule lab metadata and adversary description) provide dual mode: `Edit` and `Preview`, defaulting to `Preview` when opened.
- Rules/emulation detail popovers default to a human-readable view, include copy/export actions for STIX/output snippets, and expose raw JSON in a dedicated tab.
- Rule and ability detail modals show conversion status in the top-right header, directly below the detection/emulation type badge.
- In detection rule detail, conversion status is shown only in the top-right status label and is not duplicated inside the conversion summary grid.
- Dynamic frontend labels (detail modal sections, rule counters, confirmations, advanced filter labels, and TLP/PAP/confidence tooltips) are localized through the same EN/ES i18n layer.
- Abilities catalog with platform/classification filters and export actions.
- Ability/adversary exports include `spuc-agent`, `bash`, `powershell`, `atomic-red-team`, and `mitre-caldera`.
- Laboratory with inline STIX highlighting (single editor), realtime syntax+compatibility checks shown under the editor, stacked compatibility bars, operator colorization, auto-pair insertion, contextual autocomplete (click/Tab), metadata controls above the editor, inline error panel, and a save button enabled only when syntax is valid.
- Rule laboratory analysis is fully reactive: syntax and compatibility are re-evaluated automatically on each input change (no explicit verify action required).
- Rule laboratory target list is dynamic: at startup SPUC probes `sigma` once, discovers compatible backend plugins from `sigma plugin list`, and adds them as `sigma-to-<backend>` compatibility rows.
- In Rule Lab compatibility rows, `Show output` is displayed only for non-`unsupported` entries that include generated output text.
- Adversaries catalog supports clickable header sorting (name, emulability confidence, TLP, PAP, steps, platforms), row-click open for detail/edit, and colored exporter-availability tags per adversary.
- Adversary confidence labels are presented as emulability confidence in catalog/planner contexts.
- Adversary creation is launched from a planner-style modal dialog: compact plan metadata, catalog ability filters, and explicit ordered step selection.
- Selecting an adversary from catalog opens the same planner widget in edit mode (name/description/confidence/steps), with `Save` visible but disabled until changes are detected, plus inline executor export selector/action.
- In adversary edit mode, modal title is bound to adversary name with inline pencil-edit control, and export controls are shown in the top-right header area.
- Adversary catalog uses a dismissible non-intrusive safety toast (`How to use adversaries safely`) persisted locally once closed.
- Adversary catalog uses auto-applied filters (search, single platform combobox, min emulability) and bulk operations consistent with rules: shift-range selection, select/deselect all, bulk edit for TLP/PAP/emulability confidence, and bulk delete.
- Adversary bulk metadata updates persist TLP/PAP values with each adversary and expose them in catalog API responses.
- Learning panel fed by challenge and guidance endpoints.
- Learning exercises run in an embedded STIX practice editor with realtime challenge validation, horizontal two-row challenge lanes, search + learning-path filters, hint-first UX, and completion counters.
- User Management panel for user creation, role/enabled edits, revocation, deletion, and password change.
- Destructive actions (bulk deletions and user deletion) use an in-app confirmation modal instead of browser-native confirmation popups.

## Localization

The web interface is localized in:

- English
- Spanish

Localization applies only to the web interface. CLI, console, and JSON-RPC output are intentionally unchanged.

## Persistence

The web interface reuses the same local files as the rest of SPUC:

- users: `<config_root>/web_users.json`
- OAuth provider authorization policy: `<config_root>/web_oauth_policy.json`
- abilities: `<config_root>/abilities/*.json`
- adversaries: `<config_root>/intrusion_sets/*.yaml`
- translation activity log: `<config_root>/catalog/translation_activities.jsonl`

## Notes

- The server binds to `127.0.0.1` only.
- Download links are generated per session by the local HTTP service.
- Sidebar menu is grouped by logical sections and supports mobile collapse/expand mode.
- The web UI is a lightweight built-in HTTP server and does not require frontend tooling.
