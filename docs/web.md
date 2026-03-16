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
When `--admin-password` is provided explicitly, SPUC keeps that credential synchronized for the configured admin user at startup.

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
- Rules explorer supports two compact modes (`cards` by default and `table`), selectable from left-side icon controls with tooltips.
- Rule cards enumerate observable types, place copy-rule as an inline icon next to STIX content, and keep per-target detection/emulation chips clickable.
- Clicking a target chip (from cards or table) opens a unified rule modal with dedicated tabs for `Detection rules` and `Emulation rules`, each listing target technologies, reliability context, output text, and an expandable `How to use this output` guide.
- In rule detail tabs, each target technology block is rendered as an accordion card with status-colored borders (`exact`/`lossy`/`unsupported`) for quick scanning.
- Rule detail technology accordions start collapsed by default and surface a compact summary preview (converter comments + first lines of output) directly in the collapsed header area.
- Summary previews use a subtle fade and `Ver más` hint when comments/output exceed preview length.
- Rule detail technology summaries include a compact confidence widget (0-100 style) for rule confidence and target reliability above converter comments.
- Output previews keep copy action visible in the summary; when no output exists a compact inline notice is shown instead of an expanded block.
- Rule technology accordions display converter comments as compact bullet lists and localize common converter notes/cause text to Spanish when UI locale is `es`.
- Rule technology command and reference-link guidance is shown directly inside each opened accordion body (no extra nested toggle required).
- Rule detail `Overview` includes direct `Edit rule` action that opens the selected STIX pattern in `Laboratory` prefilled fields (rule, metadata, TLP/PAP, confidence, TTP).
- Rule detail `Detection rules` and `Emulation rules` tabs include a wider split export control (button + inline target dropdown) at the bottom of each tab to avoid cramped labels.
- Rules workspace toolbar uses explicit Font Awesome icons for view mode, select all, bulk edit, column chooser, export selected, and delete selected actions.
- Rules bulk export uses two direct actions (`CSV` in green and `STIX` in yellow) that download immediately without intermediate preview dialogs.
- STIX Bundle export includes source STIX indicators, derived translated artifacts, `related-to` links to original patterns, and `indicates` links to related STIX entities when configured.
- Rules and adversaries toolbars include `Duplicate selected` actions to clone similar objects quickly.
- Rules catalog keeps focused filtering by rule type (SIEM/IDS/Content), confidence, TLP/PAP and observable type.
- Rules catalog includes observable-type filtering and a dedicated observables column (e.g., `process`, `file`, `artifact`) persisted with rule metadata and reused for dashboard statistics.
- Rule metadata includes TLP/PAP comboboxes with normative colors and supports multiple `indicates` relations (STIX ID + object name), validated server-side and visualized with non-intrusive badges/listing in catalog and detail flows.
- STIX objects have a dedicated sidebar route with welcome chooser and catalog view (`id`, inferred `type`, `name`) aggregated from stored `indicates` relations; catalog table controls are consistent with other catalogs (`Select all`, `Enable bulk edit`, `Show/Hide columns`) and remain reusable from the `Create indicates relation` modal.
- `Create indicates relation` is restricted to selecting an existing STIX catalog object; STIX ID/name fields are read-only and shown for context only.
- New STIX objects are created from the dedicated STIX Objects workspace (`Create new object`), not from the relation modal.
- The relation modal includes a `+` shortcut in the top-right corner to open `Create new object` and then return to the same relation flow.
- Rules table includes an explicit STIX objects column that shows related `indicates` objects (e.g., `malware`) and a `+` action to append new relations.
- Emulable rules centralize export and detonation guidance directly inside the emulation detail modal (no separate export modal/button in the table column).
- Emulation detail modal always keeps the export action visible for layout consistency; when no artifact can be produced the button is rendered disabled.
- Emulation detail modal shows runtime status only in the top-right header badge (not duplicated in the summary grid), matching detection detail behavior.
- Emulation detonation commands include the exact exported artifact filename so analysts can copy/paste them directly after download.
- Emulation detail hides detonation/docs/command guidance completely when no executable command applies to the selected export.
- Emulation detail lists `other available emulations` separately from the currently selected export target.
- Detection detail command snippets use the same exact exported filename that the modal download action will generate.
- Clicking a STIX rule row opens a structured detail modal that follows the same presentation style as target-conversion detail views.
- Markdown-enabled textareas (rule lab metadata and adversary description) provide dual mode: `Edit` and `Preview`, defaulting to `Preview` when opened.
- Rules/emulation detail popovers default to a human-readable view, include copy/export actions for STIX/output snippets, and expose raw JSON in a dedicated tab.
- Rule and ability detail modals show conversion status in the top-right header, directly below the detection/emulation type badge.
- In detection rule detail, conversion status is shown only in the top-right status label and is not duplicated inside the conversion summary grid.
- Dynamic frontend labels (detail modal sections, rule counters, confirmations, advanced filter labels, and TLP/PAP/confidence tooltips) are localized through the same EN/ES i18n layer.
- Abilities catalog with platform/classification filters and export actions.
- Ability/adversary exports include `spuc-agent`, `bash`, `powershell`, `atomic-red-team`, and `mitre-caldera`.
- Laboratory with inline STIX highlighting (single editor), realtime syntax+compatibility checks shown under the editor, stacked compatibility bars, operator colorization, auto-pair insertion, contextual autocomplete (click/Tab), metadata controls above the editor, inline error panel, and autosave for valid rule states.
- Rule laboratory analysis is fully reactive: syntax and compatibility are re-evaluated automatically on each input change (no explicit verify action required).
- Rule Lab persists changes automatically when syntax is valid (manual save control hidden).
- Rule Lab and rule detail modal include `Copy LLM prompt` actions that generate deterministic structured prompts from existing rule metadata (context, observables, indicators, conversion statuses, emulation capability, current STIX pattern, and task).
- Rule laboratory target list is dynamic: at startup SPUC probes `sigma` once, discovers compatible backend plugins from `sigma plugin list`, and adds them as `sigma-to-<backend>` compatibility rows.
- In Rule Lab compatibility rows, `Show output` is displayed only for non-`unsupported` entries that include generated output text.
- Adversaries catalog supports clickable header sorting (name, emulability confidence, TLP, PAP, steps, platforms), row-click open for detail/edit, colored exporter-availability tags per adversary, and the same cards/table plus column-visibility controls used in the rules catalog.
- Rule and adversary confidence values in catalog and detail views are rendered as horizontal color bars instead of plain numeric labels.
- Adversary creation/editing uses a planner modal with autosave, ordered step selection, and a dedicated ability-picker modal instead of always-on catalog list.
- Adversary creation requires selecting a destination platform; ability catalog filtering is auto-locked to that platform by default.
- The adversary ability picker includes direct creation for dummy abilities (`sleep_seconds` and `execution_label`) so synthetic pacing/label steps can be selected alongside cataloged abilities.
- Adversary modal header shows emulable platforms and an export split control (button + target combobox).
- Adversary export now includes an `Operacional` action that downloads a target-specific runner/config artifact (`*-operational.*`) to execute the full ordered ability chain per emulator.
- Adversary exportability is re-evaluated immediately when selected abilities change so inline export targets stay in sync.
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
