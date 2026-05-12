# Current Decisions

Last updated: 2026-03-15

## Repository Truth

- Repository files are authoritative over chat context.
- Operational context is anchored through `AGENTS.md` + this document.

## KB Layout

- `kb/standards/`: immutable standards artifacts.
  - `STIXPattern.g4`
  - `stix-v2.1-cs01.html`
- `kb/guides/`: analyst interpretation guides (EN/ES).
- `kb/assets/`: diagrams and sample/generated files.

## Safety and Scope

- SPUC remains defensive-only.
- No offensive payload execution or fake execution semantics.
- Intrusion-set support is manifest construction, not orchestration runtime.
- STIX parser entrypoint is strict (`SOI..EOI`): inputs with trailing/partial garbage are rejected instead of being partially parsed.
- STIX normalization scope accepts `file:mime_type` as a valid STIX 2.1 path (target support remains emitter-dependent and may still resolve to `unsupported`).

## Ability Contract

- Canonical ability contract: JSON, schema-versioned.
- Current schema version: `1.0`.
- `spuc-agent validate` fails on unsupported/missing schema version.
- Emulation exporters are organized under `src/emulation/agents/`:
  - `spuc_agent.rs`
  - `bash.rs`
  - `powershell.rs`
  - `atomic_red_team.rs`
  - `mitre_caldera.rs`
- Materializable observable subset in current iteration:
  - `process:command_line`
  - `process:name`
  - `process:cwd`
  - `file:name`
  - `file:size`
  - `artifact:payload_bin` (string/regex payload synthesis)
  - `directory:path`
  - `windows-registry-key:key`
  - `windows-registry-key:number_of_subkeys`
  - `windows-registry-key:values[*].name`
  - `windows-registry-key:values[*].data`
  - `windows-registry-key:values[*].data_type` (`REG_SZ`/`REG_DWORD`)
  - `network-traffic:dst_ref.value`
  - `network-traffic:dst_ref.type`
  - `network-traffic:dst_port`
  - `network-traffic:protocols`
  - `domain-name:value`
- `file:hashes.*`, hex payload literals (`artifact:payload_bin = h'...'`), process metadata (`pid/created_time/is_hidden`), network source-side fields and file/directory temporal metadata are intentionally rejected for executable materialization in this iteration.

## Catalog Persistence

- File-based catalog under config root:
  - `<config_root>/abilities/*.json`
- Config root resolution:
  - Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/spuc`
  - macOS: `$HOME/Library/Application Support/spuc`
  - Windows: `%APPDATA%\\spuc`
  - override via `SPUC_CONFIG_DIR`

## Intrusion Set Persistence

- Intrusion-set manifests default to YAML and are generated per platform + executor:
  - `<config_root>/intrusion_sets/spuc-intrusion-set-<platform>-<snake_case_name>-<executor>.yaml`
- Build also writes executor artifacts per ability in the same directory.
- Manifest format is intentionally fixed to YAML in current interactive workflow.

## Interactive UX

- Browser/server entry: `spuc web` (`spuc-cli` crate), localhost-only.
- Desktop entry: `spuc-gui` (Tauri app) running `spuc web` as sidecar, with localized native title and initial web locale selected from environment locale.
- Shared reusable library package: repository root crate `spuc-core` (library name `spuc`).

## CLI Source Layout

- `src/main.rs` is intentionally thin and only parses CLI + delegates to the app runner.
- `src/core/` is the technical-core namespace for parsing/IR/normalization/emission modules.
- `src/domain/` is the product-domain namespace (`catalog`) and domain-facing integrations.
- `src/app/run.rs` centralizes top-level dispatch without embedding command logic.
- `src/app/services/` hosts shared application cases reusable across interfaces.
- `src/commands/` contains command-domain adapters (`translate`, `emulate`, `jsonrpc`, `web`, `version`), plus legacy/internal modules reused by non-CLI flows.
- `src/catalog/` remains the implementation unit for catalog operations, exposed through `src/domain/`.
- `src/tui/` contains interactive console/repl helpers and prompt handling.
- `src/ui/` contains banner/color/terminal rendering helpers shared by commands.
- `src/web/` contains the localized web interface, web API and lightweight HTTP server adapters.

## Shared Application Services

- Translation compatibility/evaluation is consolidated under `src/app/services/translation.rs`.
- `jsonrpc` and web compatibility endpoints call the same translation service to avoid duplicated business logic.

## Internal Command APIs

- Command entrypoints prefer small option structs over long positional argument lists:
  - `TranslateOptions`
  - `EmulateOptions`
  - `CampaignOptions`
- Internal command/module boundaries prefer slices (`&[T]`) instead of `&Vec<T>`.
- Borrowed filesystem inputs prefer `&Path` over `&PathBuf` unless ownership is required.
- Shared rule loading flows use `RuleInput` to keep inline rules and optional file input together.

## Translation Activity Tracking

- Every `translate` and `emulate` execution records activity in catalog log:
  - `<config_root>/catalog/translation_activities.jsonl`
- Dual-flow is always active:
  - `translate` shows only translation output but also evaluates emulation convertibility in background.
  - `emulate` shows only emulation output but also evaluates translation convertibility in background.
- Background dual-flow activity is cache-aware:
  - cache key = `rule_hash` (normalized rule + engine version)
  - use `--refresh` to force recomputation
- Ability persistence uses upsert-by-rule (`source_pattern`) to avoid duplicated ability files for the same rule.
- Catalog exploration for adversaries is available through the web interface.
- Payloads now follow the same two-stage pattern as STIX objects: centered welcome card first, then a STIX-like table catalog with icon actions and edit support after at least one payload exists.

## Output Modes

- Multi-block output rendering is supported through:
  - `summary`
  - `canonical`
  - `artifact`
  - `manifest`
  - `all`
- Blocks are color-separated and can be shown together in one run.
- Sigma OR branches are emitted as a single Sigma rule with multiple selections and one combined detection condition (no multi-document `---` split for the same input indicator).
- `sigma` availability/dynamic backend discovery is persisted in local config cache (`<config_root>/sigma/runtime.json`).
- First execution performs discovery and stores cache; subsequent runs reuse cache to avoid repeated startup latency.
- Manual refresh is explicit through `spuc sigma update-config`.

## Known Limitations

- No intrusion-set execution engine yet.
- No advanced branching/conditions/wait engines in intrusion-set planning.
- Ability generation scope is conservative and supports a subset of observables.

## Web Interface

- Running `spuc` with no command launches local no-login web mode on `http://127.0.0.1:8090/`.
- `spuc web` runs a localhost-only HTTP interface, opens the system browser by default, supports `--no-open` for embedded/sidecar use, and exposes `GET /healthz` for readiness checks.
- `spuc-gui` wraps the web UI in a native window titled `SPUC: A behavioural IOC mapping lab` or the Spanish equivalent, starts `spuc web --no-login --no-open` on an available localhost port, marks the embedded URL with `spuc-mode=gui`, shows a local loading screen until `/healthz` is ready, passes its detected system locale to the embedded web UI, and manages sidecar lifecycle.
- `spuc-gui` keeps local SPUC navigation in the webview and opens external links in the system browser.
- If the GUI cannot start the `spuc` sidecar, it exits before opening the window and reports how to build or point `SPUC_SERVER_BIN` at the CLI binary.
- The web interface is localized in English and Spanish only.
- Authentication supports local username/password users persisted in `web_users.json`.
- Google/GitHub sign-in uses authorization-code callback flow with environment bootstrap plus explicit admin authorization flags per provider.
- Frontend JavaScript now uses native ES modules served by the existing web server: `app.js` is a minimal entry wrapper that imports `boot.js`, with incremental extraction modules for `api-client.js`, `store.js`, `action-registry.js`, `ui/*`, and `features/rules/*`.
- The STIX objects catalog uses a left-aligned text search field, right-aligned icon-only bulk actions, and a compact disclosure that only shows ID plus markdown description; the pencil button reopens the upsert modal for the selected object.
- `spuc web --no-login` is supported for local standalone mode (implicit admin principal, no logout, branded two-phase entry gate, and `Settings` still available for local administration).
- Login/start view is centered and branded with the SPUC logo, app title/subtitle and multi-row footer attribution for coded-with-love, project and license links.
- In no-login sessions, the web UI first shows a branded project presentation gate with the SPUC logo and an explicit `Enter SPUC` / `Entrar en SPUC` action; the standard app shell loads only after that confirmation.
- The app shell sidebar keeps only the SPUC logo/name and navigation; product tagline text is intentionally omitted there.
- Theme and locale selection are now part of the dedicated `Settings` route instead of the top-right header controls.
- `Settings` is a first-class route for every user; administrator-only subsections inside it cover runtime defaults, OAuth provider authorization and local user management.
- The web interface reuses the same local catalog and intrusion-set persistence as CLI/console flows.
- Web-only payload catalog and learning progress are browser-local (`localStorage`) and are intentionally separate from `<config_root>` file persistence.
- Cataloged rule rows are represented in UI/API as STIX Indicator IDs (`indicator--...`) because saved rules model source STIX indicator patterns.
- Newly created adversary plans persist `intrusion_set_id` using STIX intrusion-set object identifiers (`intrusion-set--<uuid>`), while legacy `intrusion-set-...` ids remain readable for backward compatibility.
- Analyst catalog routes align populated result views to the top; only true empty/welcome states use centered workspace cards. Payload catalog search shows all saved payloads when the search field is empty.
- Adversary creation starts from name + description only and immediately persists an empty editable plan; target platform remains optional and is derived later from selected abilities/payload abilities unless the advanced editor explicitly sets it. Payloads added to adversary flows are materialized into catalog abilities before adversary persistence.
- Payload creation modals use neutral cancel actions, primary create/save actions, require name + description + content before enabling save, and syntax-highlight payload content according to the selected payload type where supported.
- The payload catalog uses the same table pattern as other populated catalogs: search and global actions remain in the top toolbar, saved payloads render as one real table row per payload by default, and filters only narrow the already visible result set.
- The web sidebar keeps navigation section spacing compact enough for common workspaces to stay visible while preserving section separators and readable item targets.
- Populated catalog result containers for rules, adversaries, payloads and STIX objects stretch to the available workspace height for consistent screen framing; centered empty/help/welcome cards keep their natural centered layout.
- Exercises use a compact training dashboard layout: introduction and controls stay in a short top band, learning paths are compact filter chips, and exercise groups render in a responsive grid so future formations can be added without creating wide empty gaps.
