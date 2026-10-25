# Web Interface

Last updated: 2026-03-15

## Command

```bash
spuc
spuc web --host 127.0.0.1 --port 8090 --admin-user admin --admin-password "change-me"
spuc web --host 0.0.0.0 --port 8090 --admin-user admin --admin-password "change-me" --no-open
spuc web --port 8090 --no-login
spuc web --port 8090 --no-login --no-open
```

`spuc` without subcommands starts standalone mode:
- it falls back to local web mode on `http://127.0.0.1:8090/` with `--no-login`.
- `spuc web` binds to `127.0.0.1` by default; use `--host 0.0.0.0` when running inside Docker or another container runtime. It also exposes `GET /healthz` for sidecar readiness checks.
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
- CLI-only release targets remain `x86_64-unknown-linux-musl` and `armv7-unknown-linux-gnueabihf`; those archives intentionally omit `spuc-gui`.

If `--admin-password` is omitted, SPUC generates a random 25-character administrator password and prints it in startup logs.
When `--admin-password` is provided explicitly, SPUC keeps that credential synchronized for the configured admin user at startup.
For connector-first deployments, `SPUC_ADMIN_API_TOKEN` can bootstrap a fixed administrator API token from the environment. SPUC stores only its hash in `web_user_api_tokens.json`; changing the environment value rotates the same bootstrap token record on the next start, and removing the variable revokes that environment-managed record.

## Docker Compose

The repository root includes `docker-compose.yml` for local containerized deployment:

```bash
cp .env.example .env
docker compose up --build
```

Compose starts:

- `spuc web --host 0.0.0.0 --port 8090 --no-open`
- persistent file-backed state on `/data` through the `spuc_data` named volume
- optional OAuth bootstrap via `SPUC_WEB_GOOGLE_*` and `SPUC_WEB_GITHUB_*`
- optional remote Sigma JSON-RPC integration via `SIGMA_RPC_URL` and `SPUC_SIGMA_RPC_TOKEN`

Published host address and port are controlled with:

- `SPUC_BIND_ADDRESS`
- `SPUC_HOST_PORT`

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
- `Conversion quality` and `Convertible rules by group` widgets render as donut/pie-style charts for faster ratio reading.
- `Most used destinations` is restricted to defensive detection targets and includes dynamic `sigma-to-*` targets when `sigma` is available at startup.
- In no-login mode, the web UI keeps a two-phase start: it first shows a branded SPUC presentation gate with logo and an explicit `Enter SPUC` / `Entrar en SPUC` action; only after that action does the standard app shell open on Home.
- The gate Start/Enter action uses both delegated action routing and a direct button click binding as a fallback, so entering the app remains available even if later UI handlers fail during boot.
- Sidebar footer exposes compact `About SPUC` and support actions that open a polished `Acerca de SPUC` dialog with project metadata, version, repository/license/releases/docs links, license/credits, and integrated donation method selection with centered Monero, Bitcoin, and GitHub Sponsors cards.
- In the `About SPUC` donation cards, crypto addresses are rendered in a stable single-line readonly text field so the card height does not change between methods.
- `Settings` is always visible in the sidebar and now uses a 3-tab layout: `Personal settings`, `Application settings`, and `User management`.
- In personal settings, the first accordion is `Profile settings` / `Configuración del perfil` and groups display-name, password, and TOTP controls; the profile save action stays disabled until the analyst changes profile fields.
- The personal OpenCTI/local-source accordion is labeled `Document management` / `Gestión documental`, uses `Information repository` / `Repositorio de información` as the source selector label, and only reveals the extra OpenCTI fields when that repository is selected.
- `Settings` replaces the old top-right language/theme controls, so the header now keeps only navigation, session identity and logout.
- In `Personal settings`, account ID is read-only, display-name/language/theme remain editable, and `Change password` is hidden entirely in `--no-login` mode.
- `Personal settings` includes personal API token management (create, rotate, revoke), and this section is available in `--no-login` because the session resolves to the bootstrap admin principal.
- OpenCTI personal settings keep the saved API key unless a new non-empty key is provided explicitly in the API key field.
- OpenCTI-specific configuration fields (enable toggle, endpoint, API key, connection test) are only shown when `STIX catalog source` is set to `OpenCTI`.
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
- Laboratory is promoted as a main sidebar item and appears above Rules.
- Clicking top-level `Rules` now opens the catalog explorer directly (no intermediate chooser view).
- `Rules` now keeps that guided empty-state card visible whenever the catalog is empty, avoiding the intermediate empty grid/table flash.
- In `Rules`, the same guided empty-state is also shown when active search/filters leave zero visible entries (`0/0`) so analysts always get next-step actions instead of a dead-end table.
- In `STIX objects` empty state, the official reference URL is attached directly to the `standard/estándar oficial` wording in the helper sentence.
- These centered empty-state cards use the same wider dialog treatment and uniform stacked CTA sizing so primary/secondary actions stay visually consistent even when labels wrap.
- The flow header also shows a `Number of steps:` label next to the live count badge, and the ordered step list uses a 2x2 action cluster for move/details/remove controls.
- Rules explorer exposes quick icon actions to open `Laboratory` (new rule) and import STIX-pattern rule files.
- Bulk rule import from file shows live progress (read phase and save phase) with a visible progress bar and counters.
- Rules search/catalog table loads immediately in the default Rules route.
- Rules filters are collapsed by default and expand via a top-right filter icon using a revealer-style animated panel over the table area.
- Rules catalog sorting is controlled from clickable table headers (name, confidence, marking), without a separate sort combobox.
- Rules table supports multi-select bulk operations: delete selected, bulk update for TLP/PAP/confidence, `Select all`/`Deselect all`, and shift-range selection.
- Rules table shows TLP+PAP in a unified `Marking/Clasificación` column.
- STIX rule column is constrained to 25% of the available rules-table width.
- Rules explorer supports two compact modes (`cards` by default and `table`), selectable from left-side icon controls with tooltips.
- Rule cards label the aggregate conversion state as compatibility, and target chips use compact exporter labels such as `Cytomic` and `atomic-red`.
- In rule detail tabs, each target technology block is rendered as an accordion card with status-colored borders (`exact`/`lossy`/`unsupported`) for quick scanning.
- Rule detail technology accordions start collapsed by default and keep collapsed headers limited to status, rule confidence and conversion confidence.
- Rule detail technology descriptions, converter comments, output text, copy actions and usage guidance are shown only after expanding the accordion.
- Rule technology accordions display converter comments as compact bullet lists and localize common converter notes/cause text to Spanish when UI locale is `es`.
- Rule technology command and reference-link guidance is shown directly inside each opened accordion body (no extra nested toggle required).
- Rule detail `Overview` includes direct `Edit rule` action that opens the selected STIX pattern in `Laboratory` prefilled fields (rule, metadata, TLP/PAP, confidence, and related STIX objects).
- Rule detail `Overview` keeps TLP and PAP aligned as a paired marking block, and detail dialogs close from the top-right `X` control instead of a bottom-left cancel action.
- Rule detail `Overview` lists mentioned observable types and shows related STIX objects as compact relation cards.
- Rule detail header now shows the rule name with the `indicator--...` ID directly underneath in monospaced style, avoiding duplicate name/ID blocks inside the summary card.
- Rules workspace toolbar uses explicit Font Awesome icons for view mode, select all, bulk edit, column chooser, export selected, and delete selected actions.
- Rules bulk export uses two direct actions (`CSV` in green and `STIX` in yellow) that download immediately without intermediate preview dialogs.
- STIX Bundle export includes source STIX indicators, derived translated artifacts, `related-to` links to original patterns, and `indicates` links to related STIX entities when configured.
- Rules catalog keeps focused filtering by rule type (SIEM/IDS/Content), confidence, TLP/PAP and observable type.
- Rules catalog includes observable-type filtering and a dedicated observables column (e.g., `process`, `file`, `artifact`) persisted with rule metadata and reused for dashboard statistics.
- Rule metadata includes TLP/PAP comboboxes with normative colors and supports multiple `indicates` relations (STIX ID + object name), validated server-side and visualized with non-intrusive badges/listing in catalog and detail flows.
- STIX objects are presented as an `STIX objects` catalog: when no objects exist, the route stays in a centered welcome state with `Create new STIX object` and `Import STIX objects`, plus an inline reference link to the STIX standard in the description; once objects exist, it switches directly to the catalog table.
- The STIX objects catalog view (`id`, inferred `type`, `name`) is aggregated from stored `indicates` relations; catalog table actions keep icon-only controls with localized tooltips (`Create`, `Export selected`, `Delete selected`) aligned at the top-right, row click expands a full-details accordion per object, and the catalog avoids duplicate section headings.
- `Create indicates relation` is restricted to selecting an existing STIX catalog object; STIX ID/name fields are read-only and shown for context only.
- New STIX objects are created from the dedicated STIX Objects workspace (`Create new object`), not from the relation modal.
- The relation modal includes a `+` shortcut in the top-right corner to open `Create new object` and then return to the same relation flow.
- Rules table includes an explicit STIX objects column that shows related `indicates` objects (e.g., `malware`) and a `+` action to append new relations.
- Detection detail command snippets use the same exact exported filename that the modal download action will generate.
- Clicking a STIX rule row opens a structured detail modal that follows the same presentation style as target-conversion detail views.
- In detection rule detail, conversion status is shown only in the top-right status label and is not duplicated inside the conversion summary grid.
- Dynamic frontend labels (detail modal sections, rule counters, confirmations, advanced filter labels, and TLP/PAP/confidence tooltips) are localized through the same EN/ES i18n layer.
- Laboratory with inline STIX highlighting (single editor), realtime syntax+compatibility checks shown under the editor, stacked compatibility bars, operator colorization, auto-pair insertion, contextual autocomplete (click/Tab), and inline error panel.
- Rule laboratory analysis is fully reactive: syntax and compatibility are re-evaluated automatically on each input change (no explicit verify action required).
- Rule Lab opens in playground-first mode (no metadata form visible by default).
- Saving from Rule Lab is manual: the top-right `Save Rule` action opens a dialog with rule title, description, TLP, and STIX-related-object combobox before persisting. When a catalog rule is opened for editing, the lab and save dialog show an explicit existing-rule editing banner.
- Rule-save feedback uses a non-blocking ephemeral toast with manual close (`x`) and auto-dismiss; successful and failed save attempts are rendered with distinct visual styles and messages.
- Rule Lab save dialog and relation labels are fully localized in English and Spanish, including the `Related STIX objects` block and empty state.
- Rule Lab save and STIX bundle export actions are grouped together as top-right icons with tooltips; save stays disabled until STIX pattern syntax is valid.
- Empty STIX editor state remains neutral (no error styling/message) until content is provided.
- Empty laboratory compatibility state stays compact with a single short empty-pattern message.
- Rule laboratory target list is dynamic: at startup SPUC probes `sigma` once, discovers compatible backend plugins from `sigma plugin list`, and adds them as `sigma-to-<backend>` compatibility rows.
- In Rule Lab compatibility rows, `Show output` is displayed only for non-`unsupported` entries that include generated output text.
- Learning panel fed by challenge and guidance endpoints.
- Learning exercises run in an embedded STIX practice editor with realtime challenge validation, compact learning-path progress chips, grouped exercise rows, search + learning-path filters, hint-first UX, and completion counters.
- Learning toolbar controls use overflow-safe search, path and progress areas so `Solo pendientes`/`Only pending` and completion counts remain readable without overlap.
- Learning progress is persisted in browser storage per tab/window session (completed exercises and active learning filters), with fallback support for previously stored local data.
- User Management panel for user creation, role/enabled edits, revocation, deletion, and password change.
- Shared comboboxes (`select`) use a compact project-wide style, and simple single-value selects are progressively enhanced into SPUC-styled dropdowns with a custom trigger and menu; `multiple` selectors stay as listboxes with their own compact treatment so filters do not visually dominate the workspace.

## Localization

The web interface is localized in:

- English
- Spanish

Localization applies only to the web interface. CLI, console, and JSON-RPC output are intentionally unchanged.

## Persistence

The web interface reuses the same local files as the rest of SPUC:

- users: `<config_root>/web_users.json`
- OAuth provider authorization policy: `<config_root>/web_oauth_policy.json`
- STIX object catalog: `<config_root>/stix-objects.json`
- translation activity log: `<config_root>/catalog/translation_activities.jsonl`

Web-only state in browser storage (not in `<config_root>`):

- learning progress and filters (session-scoped per tab/window): `spuc-web-learning-progress`
- last route (session-scoped per tab/window): `spuc-web-last-route`

## Notes

- The server binds to `127.0.0.1` by default in local mode; container deployments should set `--host 0.0.0.0`.
- Download links are generated per session by the local HTTP service.
- Sidebar menu is grouped by logical sections and supports mobile collapse/expand mode.
- The web UI is a lightweight built-in HTTP server and does not require frontend tooling.
- For reproducible QA from an empty catalog baseline, follow `docs/empty-state-testing.md`.


- SPUC now focuses on translating STIX patterns to detection targets and
  on the rules catalog workflow (TLP/PAP, TTP, observables, indicates).
  LLM/agent-assisted feature.

## Changelog - 2026-10-22: adversary surface removed

- The `spuc emulate` command, the adversary and payload web views, and the
  underlying engine were removed.
- SPUC now focuses on translating STIX patterns to detection targets and on
  the rules catalog workflow (TLP/PAP, TTP, observables, indicates).
- The web UI no longer exposes adversaries, payloads, abilities, or the
  emulation detail tab; rule rows carry translation statuses only.
- Guided adversary analysis may return later as a strictly defensive,
  LLM/agent-assisted feature.

## October 2026 legacy web cleanup (Stage 5B2a)

SPUC no longer exposes adversary, payload or emulation execution workflows.
Stage 5B2a removes eight unreferenced, module-private JavaScript functions
that were part of the retired web interface; it does not change detection rule
CRUD, the CLI, or persisted data formats. Historical abilities-to-rules seeding
remains in `src/catalog/rules.rs` for one-way migration of older catalogs.
Remaining legacy handlers, state, CSS and translation strings require separate
reference analysis and regression testing before removal. This cleanup is not a
security certification or a release gate by itself.

## October 2026 legacy web cleanup (Stage 5B2b)

Stage 5B2b removes three additional module-private and unreferenced legacy
functions: `renderEmulationDetonationGuide`, `adversaryFormSignature`, and
`mountAdversaryEditorSurface`. This is a narrow follow-up to Stage 5B2a,
not a complete deletion of retired JS, CSS, or state. The historical
abilities-to-rules migration remains unchanged. Existing rule CRUD and
translation paths must continue to pass the browser and Rust regression gates.

## October 2026 legacy event surface cleanup (Stage 5F1)

Stage 5F1 removes the retired delegated click/change action branches for
adversary/ability/payload/emulation controls and four now-unreachable row/card
listeners. A Chromium browser test injects stale retired actions and asserts
that they cause neither legacy API calls nor browser exceptions. It preserves
rules, STIX objects, Learning, Settings, and the historical abilities-to-rules
one-way migration in `src/catalog/rules.rs`.

**This is not complete dead-code removal.** Legacy presentation generators,
helpers, `store.js` state and styles remain for dependency review, and the
24 prior HTTP endpoint literals have not all been deleted in this stage.
The automated checks prove browser behavior for tested synthetic scenarios,
not complete absence of reachable legacy code. Production GitHub Actions
execution and authorised historical dataset migration remain separate gates.

### Stage 5F2a — retirada de funciones sin llamadores

Se han eliminado 30 declaraciones de funciones locales del módulo `boot.js` para acciones de adversarios, abilities, payloads y emulación retiradas. La comprobación de dependencias se limita a las referencias textuales del módulo y otros archivos web; por sí sola no demuestra ausencia universal de invocación dinámica. Se conservan sin modificaciones los manejadores vigentes, `store.js`, `app.css`, las APIs y la migración histórica de abilities a reglas en `src/catalog/rules.rs`.

La aplicación de esta poda requiere superar previamente compilación, formato, Clippy, tests Rust y Chromium (navegación, CRUD, persistencia e inyección de acciones legacy) sobre una copia aislada. Ninguna validación local sustituye a la ejecución remota de CI ni a una prueba de migración con una copia autorizada de datos históricos.


### Seguimiento de poda legacy — Gate 5F2b (2026-10-25)

Eliminadas once funciones JavaScript de adversarios/abilities/payloads sin referencias nominales tras la poda 5F2a, verificadas mediante declaraciones de función de nivel superior y comprobación de tokens. Se mantienen `store.js`, estilos CSS, rutas, pruebas E2E, y el mecanismo `legacy_abilities` de migración histórica. No se infiere que el resto del código legacy sea inalcanzable: quedan pendientes análisis de dependencias y regresiones. La aplicación de este cambio exige pruebas Rust/Clippy/Chromium adversarial en Docker.
