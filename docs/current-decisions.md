# Current Decisions

Last updated: 2026-10-23

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
- STIX parser entrypoint is strict (`SOI..EOI`): inputs with trailing/partial garbage are rejected instead of being partially parsed.
- STIX normalization scope accepts `file:mime_type` as a valid STIX 2.1 path (target support remains emitter-dependent and may still resolve to `unsupported`).

## Catalog Persistence

- File-based rules catalog under the config root:
  - `<config_root>/catalog/rules.json` — translation-owned rules store (JSON array of `PersistedRule`).
  - `<config_root>/catalog/translation_activities.jsonl` — append-only activity log (one JSON object per line).
  - `<config_root>/catalog/rules.json.seeded` — durable marker for the one-time legacy seeding.
- Canonical rule id: `mint_rule_indicator_id(pattern)` (deterministic FNV-1a, uuid-shaped, toolchain-independent).
- Persisted rule fields mirror exactly the rule metadata codec (description, tlp, pap, ttp, target_platform, observables, indicates, indicates_list, rule_confidence, name, source_pattern, indicator_id) — no invented fields.
- Legacy `abilities/*.json` files are read-only inputs for the one-time seeding; they are never modified or deleted by SPUC.
- Seeding runs once (guarded by the marker) and never resurrects a rule that was deleted afterwards.

## Config Root Resolution

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/spuc`
- macOS: `$HOME/Library/Application Support/spuc`
- Windows: `%APPDATA%\\spuc`
- override via `SPUC_CONFIG_DIR`

## Data Retention

- Rules and activities are file-based and persist across runs.
- Deleting a rule purges only its visible translate activity rows; hidden legacy rows and the abilities directory (if present) are left untouched.
- Seeding is idempotent and durable: a dropped rule does not reappear from a legacy scan.

## Interactive UX

- Browser/server entry: `spuc web` (`spuc-cli` crate), localhost-only by default.
- Desktop entry: `spuc-gui` (Tauri app) running `spuc web` as sidecar.
- Shared reusable library package: repository root crate `spuc-core` (library name `spuc`).

## CLI Source Layout

- `crates/spuc-cli/` is the compiled CLI entry (`spuc` binary); the root `src/main.rs` was removed.
- `src/app/run.rs` centralizes top-level dispatch without embedding command logic.
- `src/app/services/` hosts shared application cases reusable across interfaces (translation evaluation).
- `src/commands/` contains command-domain adapters (`translate`, `verify`, `jsonrpc`, `web`, `version`, `sigma`, `learn`).
- `src/catalog/` is the implementation unit for catalog operations, exposed through `src/domain/`.
- `src/ui/` contains banner/color/terminal rendering helpers shared by commands.
- `src/web/` contains the localized web interface, web API and lightweight HTTP server adapters.

## Shared Application Services

- Translation compatibility/evaluation is consolidated under `src/app/services/translation.rs`.
- `jsonrpc` and web compatibility endpoints call the same translation service to avoid duplicated business logic.

## Translation Activity Tracking

- Every `translate` execution records activity in the catalog log:
  - `<config_root>/catalog/translation_activities.jsonl`
- Rule Lab save evaluates the rule across all detection targets and records visible translate activity rows (no emulation, no ability files).
- Background dual-flow and `--refresh` were removed together with the emulation surface.

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

## Release Packaging

- GitHub release archives for Unix targets derive the version from the root `Cargo.toml` and must be emitted as `spuc-v<version>-<target>.tar.gz`.
- Windows release archives follow the same versioned naming pattern with `.zip` suffix.
- Every release archive includes `spuc`; desktop-capable release targets also include `spuc-gui` in the same standard archive.
- Current CLI-only release targets are `x86_64-unknown-linux-musl` and `armv7-unknown-linux-gnueabihf`.

## Known Limitations

- No intrusion-set execution engine.
- No advanced branching/conditions/wait engines in intrusion-set planning (intrusion sets were removed with the emulation surface).
- Translation coverage is conservative and supports a subset of observables per target.

## Web Interface

- Running `spuc` with no command launches local no-login web mode on `http://127.0.0.1:8090/`.
- `spuc web` binds to `127.0.0.1` by default, accepts `--host` for explicit bind changes such as Docker/Compose, opens the system browser by default, supports `--no-open` for embedded/sidecar use, and exposes `GET /healthz` for readiness checks.
- `spuc-gui` wraps the web UI in a native window, starts `spuc web --no-login --no-open` on an available localhost port, and manages sidecar lifecycle.
- Root `docker-compose.yml` is the canonical container entry for the repository and runs `spuc web --host 0.0.0.0 --port 8090 --no-open` with persisted `/data` state.
- MCP exposure is adapter-based in current iteration: `spuc jsonrpc` is the backend contract and external MCP adapters bridge MCP tool calls to `/rpc`.
- The web interface is localized in English and Spanish only.
- Authentication supports local username/password users persisted in `web_users.json`.
- Container deployments can bootstrap one fixed administrator API token from `SPUC_ADMIN_API_TOKEN`.
- Google/GitHub sign-in uses authorization-code callback flow with environment bootstrap plus explicit admin authorization flags per provider.
- Frontend JavaScript now uses native ES modules served by the existing web server.
- The STIX objects catalog uses a left-aligned text search field, right-aligned icon-only bulk actions, and a compact disclosure that only shows ID plus markdown description.
- `spuc web --no-login` is supported for local standalone mode (implicit admin principal, no logout, branded two-phase entry gate, and `Settings` still available for local administration).
- The web interface reuses the same local catalog and rule persistence as CLI flows.
- Rule Lab save metadata exposes both TLP and PAP selectors before persisting STIX indicator rules.
- Web-only learning progress is browser-local (`localStorage`) and is intentionally separate from `<config_root>` file persistence.
- Cataloged rule rows are represented in UI/API as STIX Indicator IDs (`indicator--...`) because saved rules model source STIX indicator patterns.

## Emulation Removed (2026-10)

The `spuc emulate` command, the adversary/payload web surface and the
underlying emulation engine were removed in October 2026. SPUC now
focuses on translating STIX patterns to detection targets and on the
rules catalog workflow. Guided adversary analysis may return later as a
strictly defensive, LLM/agent-assisted feature.