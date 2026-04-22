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

- Browser/server entry: `spuc web` (`spuc-server` crate), localhost-only.
- Desktop entry: `spuc-desktop` (Tauri app) running `spuc web` as sidecar.
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
- `spuc web` runs a localhost-only HTTP interface and exposes `GET /healthz` for sidecar readiness checks.
- `spuc-desktop` wraps the web UI in a native window and manages sidecar lifecycle.
- The web interface is localized in English and Spanish only.
- Authentication supports local username/password users persisted in `web_users.json`.
- Google/GitHub sign-in uses authorization-code callback flow with environment bootstrap plus explicit admin authorization flags per provider.
- `spuc web --no-login` is supported for local standalone mode (implicit admin principal, no logout).
- Login/start view is centered and branded with the SPUC logo, app title/subtitle and footer links for project/license attribution.
- The web interface reuses the same local catalog and intrusion-set persistence as CLI/console flows.
