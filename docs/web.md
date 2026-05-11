# Web Interface

Last updated: 2026-03-15

## Command

```bash
spuc
spuc web --port 8090 --admin-user admin --admin-password "change-me"
spuc web --port 8090 --no-login
spuc web --port 8090 --no-login --no-open
```

`spuc` without subcommands starts standalone mode:
- it falls back to local web mode on `http://127.0.0.1:8090/` with `--no-login`.
- `spuc web` binds to `127.0.0.1` and exposes `GET /healthz` for sidecar readiness checks.
- `spuc web` opens the system browser by default; use `--no-open` when another shell, desktop wrapper, or test harness will load the URL.
- `spuc-gui` starts `spuc web --no-login --no-open` on an available localhost port, marks the embedded web URL with `spuc-mode=gui`, shows a centered SPUC loading screen while the sidecar becomes ready, and then shows it in a native Tauri window titled `SPUC: A behavioural IOC mapping lab` or the Spanish equivalent.
- `spuc-gui` reads `SPUC_LOCALE`, `LC_ALL`, `LC_MESSAGES`, or `LANG` to choose the native window title language at startup and passes that default locale to the embedded web UI. Browser mode uses the browser language when no saved language preference exists, and the page title stays synchronized with the language preference stored in `Settings`.
- In `spuc-gui`, local SPUC navigation remains inside the webview and external links open in the system browser.
- If `spuc-gui` cannot start the `spuc` sidecar, startup fails fast with guidance to build `spuc`, place it beside `spuc-gui`/in `PATH`, or set `SPUC_SERVER_BIN`.
- Desktop release builds keep both `crates/spuc-gui/icons/icon.png` and `crates/spuc-gui/icons/icon.ico`; the `.ico` asset is required by Tauri when compiling the Windows resource file.
- desktop build command: `cargo run -p spuc-gui`
- Linux desktop prerequisites: WebKitGTK, JavaScriptCoreGTK, GTK and GLib development packages.
- Fedora: `sudo dnf install glib2-devel gtk3-devel webkit2gtk4.1-devel javascriptcoregtk4.1-devel libappindicator-gtk3-devel librsvg2-devel libxdo-devel pkgconf-pkg-config`.
- Ubuntu/WSL: install `libwebkit2gtk-4.1-dev`, `libjavascriptcoregtk-4.1-dev`, `libgtk-3-dev`, `libglib2.0-dev`, `libappindicator3-dev`, `librsvg2-dev`, `libxdo-dev`, and `pkg-config`.

If `--admin-password` is omitted, SPUC generates a random 25-character administrator password and prints it in startup logs.
When `--admin-password` is provided explicitly, SPUC keeps that credential synchronized for the configured admin user at startup.

## Authentication modes

- Local login (username and password) backed by a local user store.
- `--no-login` mode for standalone local sessions: no login view, implicit administrator role, a two-phase branded entry gate, and logout hidden in UI.
- Optional Google/GitHub provider bootstrap from environment variables (authorization code callback flow enabled).
- OAuth providers must also be authorized by an administrator in `Settings` before they can be used in the login screen.
- Google/GitHub login buttons are disabled in the static login view and become enabled only after bootstrap confirms that the provider is configured and authorized.
- Login/start view uses centered layout with SPUC logo, app title/subtitle, login panel, and a fixed bottom footer with `Coded with ❤️ by febrezo`, GitHub project, and `Licencia: Server Side Public License`.
- In `--no-login`, the sidebar identity stays neutral and the app opens through the branded gate first; `Settings` remains available and includes administrator sections because the local session resolves to the bootstrap administrator.

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

Even when configured, providers stay disabled until an admin authorizes each provider in `Settings`.

## Web interface scope

`spuc web` is another presentation layer for the same defensive SPUC core and currently includes:

- Dashboard overview with KPIs and chart widgets.
- Dashboard includes additional telemetry charts for rule status distribution (`exact/lossy/unsupported`), emulation coverage by exporter counting only `exact/lossy` mappings (excluding `unsupported`), convertible-rule counts by group (`SIEM`/`IDS`/`Content`, any non-red target), and most frequent observable types present in cataloged rules.
- `Conversion quality` and `Convertible rules by group` widgets render as donut/pie-style charts for faster ratio reading.
- `Most used destinations` is restricted to defensive detection targets and includes dynamic `sigma-to-*` targets when `sigma` is available at startup.
- Home (`Inicio`) route is available above Overview and provides a centered welcome-view with stacked action rows (icon, title, short description) for Laboratory, Rules Catalog, Adversary Catalog, Learning, and Donate.
- In no-login mode, the web UI keeps a two-phase start: it first shows a branded SPUC presentation gate with logo and an explicit `Enter SPUC` / `Entrar en SPUC` action; only after that action does the standard app shell open on Home.
- Sidebar footer exposes compact `About SPUC` and support actions that open a polished `Acerca de SPUC` dialog with project metadata, version, repository/license/releases/docs links, license/credits, and integrated donation method selection with centered Monero, Bitcoin, and GitHub Sponsors cards.
- In the `About SPUC` donation cards, crypto addresses are rendered in a stable single-line readonly text field so the card height does not change between methods.
- `Settings` is always visible in the sidebar and now uses a 3-tab layout: `Personal settings`, `Application settings`, and `User management`.
- `Settings` replaces the old top-right language/theme controls, so the header now keeps only navigation, session identity and logout.
- In `Personal settings`, account ID is read-only, display-name/language/theme remain editable, and `Change password` is hidden entirely in `--no-login` mode.
- `Application settings` centralizes Sigma JSON-RPC endpoint/token plus default language/theme/TOTP policy for new users; in `--no-login` mode, identity-related defaults and external login provider controls stay visible but disabled.
- External OAuth providers (Google/GitHub) are configured through a dedicated provider dialog launched from the `Configure` action in `Application settings`.
- `User management` keeps the users table plus filter controls and create-user modal; this tab is visible but disabled in `--no-login` mode.
- In login-enabled sessions, user-management actions include role/status updates, password reset, deletion, and a per-user TOTP policy toggle field.
- Sidebar footer uses a single `About SPUC` action that opens the same dialog with project metadata, documentation links, and donation method selection.
- Donation media placeholders and the official GitHub Invertocat asset are embedded from `kb/assets/` and served on:
	- `/assets/donate-bitcoin.png` (Bitcoin QR)
	- `/assets/donate-monero.png` (Monero QR)
	- `/assets/logo-bitcoin.png` (Bitcoin logo)
	- `/assets/logo-monero.png` (Monero logo)
	- `/assets/logo-github.png` (GitHub Sponsors logo)
- Left sidebar navigation uses flat primary entries (no nested submenus): Laboratory, Rules, Emulation, and STIX Objects.
- Laboratory is promoted as a main sidebar item and appears above Rules.
- Clicking top-level `Rules` now opens the catalog explorer directly (no intermediate chooser view).
- Clicking top-level `Emulation` now opens the adversaries explorer directly (no intermediate chooser view).
- The sidebar now includes a direct `Payloads` entry so reusable payloads can be explored outside the adversary editor.
- When `Rules`, `Payloads`, or `STIX objects` have no catalog entries yet, the route shows a centered localized welcome/empty-state card instead of an empty table shell.
- `Rules` now keeps that guided empty-state card visible whenever the catalog is empty, avoiding the intermediate empty grid/table flash.
- In `Rules`, the same guided empty-state is also shown when active search/filters leave zero visible entries (`0/0`) so analysts always get next-step actions instead of a dead-end table.
- In `STIX objects` empty state, the official reference URL is attached directly to the `standard/estándar oficial` wording in the helper sentence.
- These centered empty-state cards use the same wider dialog treatment and uniform stacked CTA sizing so primary/secondary actions stay visually consistent even when labels wrap.
- `Payloads` keeps a centered welcome card when no reusable payloads exist yet, with direct actions to create a payload or open the project documentation; once payloads exist, the route switches to a catalog layout with top-right icon actions (`New payload`, `Delete selected`), expandable rows, and column headers for payload, type, runners, and actions.
- Newly created adversaries are persisted as STIX intrusion-set objects and now use `intrusion-set--<uuid>` identifiers in saved manifests and API responses.
- Adversary `Detail` and `Edit` now open a dedicated central workspace view (no modal/backdrop), with a single header containing back navigation, title/subtitle, and context actions.
- Emulation workspace includes a dedicated `Custom payloads` view to search, preview, create, remove, and reuse payloads before planning adversaries.
- The `Payloads` route renders an accordion-table hybrid catalog with row selection, a right-side actions column, inline detail expansion (`ID`, description, and payload content in a scrollable code block), and multi-select filters for payload type and runner.
- Adversary editor header is simplified to three actions: `Back to list`, `Plan adversary`, and `Export adversary`.
- Adversary summary fields are directly editable and persist on blur with subtle bottom toast confirmation.
- Adversary export in editor header only enables compatible runners for the current step chain; if no exporter is compatible, export is disabled with explanatory tooltip.
- Adversary planning uses a two-zone editable view: an ordered step sequence on the left and a wider right-side panel for selected-step details plus add-behavior controls.
- The flow controls open modal pickers for catalog abilities and custom payloads, plus a modal form for creating a new payload before adding it to the current plan.
- The flow header also shows a `Number of steps:` label next to the live count badge, and the ordered step list uses a 2x2 action cluster for move/details/remove controls.
- The JSON tab was removed from the adversary detail workflow to keep the interface focused on summary, planning, and export readiness.
- Rules explorer exposes quick icon actions to open `Laboratory` (new rule) and import STIX-pattern rule files.
- Bulk rule import from file shows live progress (read phase and save phase) with a visible progress bar and counters.
- Rules search/catalog table loads immediately in the default Rules route.
- Rules filters are collapsed by default and expand via a top-right filter icon using a revealer-style animated panel over the table area.
- Rules catalog sorting is controlled from clickable table headers (name, confidence, marking), without a separate sort combobox.
- Rules table supports multi-select bulk operations: delete selected, bulk update for TLP/PAP/confidence, `Select all`/`Deselect all`, and shift-range selection.
- Rules table shows TLP+PAP in a unified `Marking/Clasificación` column.
- STIX rule column is constrained to 25% of the available rules-table width.
- Rules table with per-target output/emulation status chips (`exact/lossy/unsupported`) and click-through detail popovers.
- Rules explorer supports two compact modes (`cards` by default and `table`), selectable from left-side icon controls with tooltips.
- Rule cards show STIX `indicator--...` IDs across the full header width below TLP/PAP markings, compact observable/STIX-object counters with hover detail, place copy-rule as an inline icon next to STIX content, and keep per-target detection/emulation chips clickable.
- Rule cards do not show an aggregate compatibility label; exact/lossy/unsupported detail is reserved for the detection/emulation breakdowns.
- Rule cards label the aggregate conversion state as compatibility, and target chips use compact exporter labels such as `atomic-red`.
- Clicking a target chip (from cards or table) opens a unified rule modal with dedicated tabs for `Detection rules` and `Emulation rules`, each listing target technologies, status, rule confidence, conversion confidence, output text, and an expandable `How to use this output` guide.
- In rule detail tabs, each target technology block is rendered as an accordion card with status-colored borders (`exact`/`lossy`/`unsupported`) for quick scanning.
- Rule detail technology accordions start collapsed by default and keep collapsed headers limited to status, rule confidence and conversion confidence.
- Rule detail technology descriptions, converter comments, output text, copy actions and usage guidance are shown only after expanding the accordion.
- Rule technology accordions display converter comments as compact bullet lists and localize common converter notes/cause text to Spanish when UI locale is `es`.
- Rule technology command and reference-link guidance is shown directly inside each opened accordion body (no extra nested toggle required).
- Rule detail `Overview` includes direct `Edit rule` action that opens the selected STIX pattern in `Laboratory` prefilled fields (rule, metadata, TLP/PAP, confidence, and related STIX objects).
- Rule detail `Overview` keeps TLP and PAP aligned as a paired marking block, and detail dialogs close from the top-right `X` control instead of a bottom-left cancel action.
- Rule detail `Overview` lists mentioned observable types and shows related STIX objects as compact relation cards.
- Rule detail header now shows the rule name with the `indicator--...` ID directly underneath in monospaced style, avoiding duplicate name/ID blocks inside the summary card.
- Rule detail `Detection rules` and `Emulation rules` tabs include a wider split export control (button + inline target dropdown) at the bottom of each tab to avoid cramped labels.
- Rules workspace toolbar uses explicit Font Awesome icons for view mode, select all, bulk edit, column chooser, export selected, and delete selected actions.
- Rules bulk export uses two direct actions (`CSV` in green and `STIX` in yellow) that download immediately without intermediate preview dialogs.
- STIX Bundle export includes source STIX indicators, derived translated artifacts, `related-to` links to original patterns, and `indicates` links to related STIX entities when configured.
- Rules and adversaries toolbars include `Duplicate selected` actions to clone similar objects quickly.
- Rules catalog keeps focused filtering by rule type (SIEM/IDS/Content), confidence, TLP/PAP and observable type.
- Rules catalog includes observable-type filtering and a dedicated observables column (e.g., `process`, `file`, `artifact`) persisted with rule metadata and reused for dashboard statistics.
- Rule metadata includes TLP/PAP comboboxes with normative colors and supports multiple `indicates` relations (STIX ID + object name), validated server-side and visualized with non-intrusive badges/listing in catalog and detail flows.
- STIX objects are presented as an `STIX objects` catalog: when no objects exist, the route stays in a centered welcome state with `Create new STIX object` and `Import STIX objects`, plus an inline reference link to the STIX standard in the description; once objects exist, it switches directly to the catalog table.
- The STIX objects catalog view (`id`, inferred `type`, `name`) is aggregated from stored `indicates` relations; catalog table actions keep icon-only controls with localized tooltips (`Create`, `Export selected`, `Delete selected`) aligned at the top-right, row click expands a full-details accordion per object, and the catalog avoids duplicate section headings.
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
- Laboratory with inline STIX highlighting (single editor), realtime syntax+compatibility checks shown under the editor, stacked compatibility bars, operator colorization, auto-pair insertion, contextual autocomplete (click/Tab), and inline error panel.
- Rule laboratory analysis is fully reactive: syntax and compatibility are re-evaluated automatically on each input change (no explicit verify action required).
- Rule Lab opens in playground-first mode (no metadata form visible by default).
- Saving from Rule Lab is manual: the top-right `Save Rule` action opens a dialog with rule title, description, TLP, and STIX-related-object combobox before persisting. When a catalog rule is opened for editing, the lab and save dialog show an explicit existing-rule editing banner.
- Rule Lab save dialog and relation labels are fully localized in English and Spanish, including the `Related STIX objects` block and empty state.
- Rule Lab save and STIX bundle export actions are grouped together as top-right icons with tooltips; save stays disabled until STIX pattern syntax is valid.
- Empty STIX editor state remains neutral (no error styling/message) until content is provided.
- Empty laboratory compatibility state stays compact with a single short empty-pattern message.
- Rule Lab and rule detail modal include `Copy LLM prompt` actions that generate deterministic structured prompts from existing rule metadata (context, observables, indicators, conversion statuses, emulation capability, current STIX pattern, and task).
- Rule laboratory target list is dynamic: at startup SPUC probes `sigma` once, discovers compatible backend plugins from `sigma plugin list`, and adds them as `sigma-to-<backend>` compatibility rows.
- In Rule Lab compatibility rows, `Show output` is displayed only for non-`unsupported` entries that include generated output text.
- Adversaries catalog supports clickable header sorting (name, emulability confidence, TLP, PAP, steps, platforms), row/card-click editing, explicit `View details` actions, colored exporter-availability tags per adversary, and the same cards/table plus column-visibility controls used in the rules catalog.
- Rule and adversary confidence values in catalog and detail views are rendered as horizontal color bars instead of plain numeric labels.
- Adversary creation/editing opens as a central builder view inside Emulation, with top-level navigation back to the list, progressive Plan and Validate/Export sections, ordered step selection, and a dedicated ability-picker modal.
- Adversary creation requires selecting a destination platform; ability catalog filtering is auto-locked to that platform by default.
- The adversary ability picker includes direct creation for dummy abilities (`sleep_seconds` and `execution_label`) so synthetic pacing/label steps can be selected alongside cataloged abilities.
- The adversary builder can add custom payload steps as catalog-compatible abilities with `custom_payload` action metadata; SPUC stores and exports them as explicit lab-runner artifacts but does not execute payloads from the web UI.
- Custom payload creation now happens in a dedicated modal form, and adding an existing payload or a freshly created one returns to the same flow view with a saved-toast confirmation.
- Custom payload runners are modeled as extensible metadata (`bash`, `powershell`, `python`, `javascript`, `rubber-ducky`, `spuc-agent`) so future `spuc-agent` runners can validate/execute them in authorized labs without changing existing adversary manifests.
- Adversary modal header shows emulable platforms and an export split control (button + target combobox).
- Adversary export now includes an `Operacional` action that downloads a target-specific executable artifact per emulator to execute the full ordered ability chain.
- Adversary exportabno longer shows the old safety tutorial toast; the workflow now starts directly in the catalog/editor views
- The adversaries workspace uses a dismissible non-intrusive safety toast (`How to use adversaries safely`) persisted locally once closed.
- The adversaries workspace uses auto-applied filters (search, single platform combobox, min emulability) and bulk operations consistent with rules: shift-range selection, select/deselect all, bulk edit for TLP/PAP/emulability confidence, and bulk delete.
- Adversary bulk deletion uses the in-app confirmation dialog instead of browser-native confirm UI.
- When no adversaries exist yet, Emulation shows a centered empty-state message with a primary action to create the first adversary.
- Adversaries explorer includes a dedicated help action that explains how to run an agent test flow in a defensive lab.
- Adversary bulk metadata updates persist TLP/PAP values with each adversary and expose them in catalog API responses.
- Learning panel fed by challenge and guidance endpoints.
- Learning exercises run in an embedded STIX practice editor with realtime challenge validation, compact learning-path progress chips, grouped exercise rows, search + learning-path filters, hint-first UX, and completion counters.
- Learning toolbar controls use overflow-safe search, path and progress areas so `Solo pendientes`/`Only pending` and completion counts remain readable without overlap.
- Learning progress is persisted locally in browser storage (completed exercises and active learning filters), and restored on next visit.
- User Management panel for user creation, role/enabled edits, revocation, deletion, and password change.
- Destructive actions (bulk deletions and user deletion) use an in-app confirmation modal instead of browser-native confirmation popups, with verb-specific destructive buttons (`Delete rules`, `Delete adversaries`, etc.) grouped together on the right side of the footer.
- Shared comboboxes (`select`) use a compact project-wide style, and simple single-value selects are progressively enhanced into SPUC-styled dropdowns with a custom trigger and menu; `multiple` selectors stay as listboxes with their own compact treatment so filters do not visually dominate the workspace.
- Adversary creation starts with a compact modal for minimum metadata, then continues in the main builder view once the analyst confirms the draft; confidence is tuned later from the main overview with a slider.

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
- STIX object catalog: `<config_root>/stix-objects.json`
- translation activity log: `<config_root>/catalog/translation_activities.jsonl`

Web-only state in browser storage (not in `<config_root>`):

- custom payload catalog: `spuc-web-custom-payloads`
- learning progress and filters: `spuc-web-learning-progress`
- last route and view preferences: `spuc-web-last-route`, `spuc-web-rules-view-mode`, `spuc-web-adversaries-view-mode`

## Notes

- The server binds to `127.0.0.1` only.
- Download links are generated per session by the local HTTP service.
- Sidebar menu is grouped by logical sections and supports mobile collapse/expand mode.
- The web UI is a lightweight built-in HTTP server and does not require frontend tooling.
- For reproducible QA from an empty catalog baseline, follow `docs/empty-state-testing.md`.
