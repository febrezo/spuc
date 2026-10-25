# Design: Remove Adversary Emulation — Limit SPUC to Rule Translation and Conversion

- Date: 2026-10-22
- Status: Draft for approval
- Decided with: project owner (2026-10-22 session)
- Inputs: adversarial repository analysis (inventory, coupling map, risks; see Appendix A), repository docs, live CLI/config probes.

## 1. Intent and the Why

It is 2026. SPUC's hand-rolled adversary-emulation pipeline (abilities, emulators, `spuc-agent`, intrusion-set planning) is no longer how emulated adversaries will be produced: they will be generated externally with LLMs and agent tooling. The emulation code inside SPUC is a maintenance liability in a product whose real value here is **STIX pattern safety, translation to detection targets, and rule conversion**.

The owner's direction: **remove the emulation user surface now** (not advisory deprecation), keep translation and rule conversion, build no replacement in this iteration, publish no release in this iteration.

Line-level adversarial analysis of the repo surfaced one blocker: the web rules catalog currently **persists through the emulation engine** (`persist_rule_entry` calls `emulate::run`; rule metadata is encoded into ability `description` strings). Therefore removal must be staged: **translation gets its own rules store first**, then the emulation surface is cut.

## 2. Goals

1. **CLI surface** becomes: `translate`, `verify`, `sigma`, `jsonrpc`, `web`, `version`, `help`. No `emulate`, no emulation targets, no emulate-only flags.
2. **Binary surface** becomes: `spuc` (+ `spuc-gui` desktop). No `spuc-agent` binary (crate binaries, Dockerfile, CI build matrix, release archives, README packaging claims).
3. **Web surface** loses: `Adversaries`, `Payloads`, ability/adversary endpoints, emulation columns/tabs in the rules grid, emulation KPIs on the dashboard, adversary entries on Home welcome actions. Keeps: Home, Dashboard (redefined KPIs), Rule Lab, Rules, STIX Objects, Learning (minus the adversary-build info block), Settings — and the established web modal footer convention (left `Cancelar`/red, right primary action).
4. **Translation persistence is independent of emulation**: a translation-owned rules store; the dual-flow (translate secretly upserts abilities + hidden emulate activities) is removed; visible translate activity recording stays; `translation_activities.jsonl` path and JSON row compatibility are preserved.
5. Every slice updates **tests and docs in the same iteration** (AGENTS.md rules); final state leaves no docs describing removed commands as current.
6. Immutable artifacts untouched: `kb/standards/*`, `kb/guides/GUIDE_EN.md`, `kb/guides/GUIDE_ES.md` (grep-verified: no emulation content).
7. The untracked `payloads/` corpus is **out of scope and untouched** (seed material for the future LLM/agent approach; uncommitted by choice).

## 3. Non-Goals

- No LLM/agent adversary-generation capability is built now.
- No release, tag, or publication in this iteration.
- No UX redesign beyond emulation removal; no changes to translate/verify/sigma/jsonrpc semantics (statuses, confidence, fidelity model stay).
- No destructive cleanup of user data on disk.
- No refactor of unrelated code beyond what removal requires (duplicated legacy helpers die only if they are emulation/legacy arms already unreachable).

## 4. Anti-Goals (what would make this a failure)

- **Breaking rule save/list/edit/delete, rule metadata, or bundle export in the web.** Rules persistence must not depend on ability artifacts after this work.
- **Losing previously saved rule metadata** (name, description, TLP, PAP, TTP, confidence, observables, `indicates` relations) during migration.
- **Honesty failures**: dead UI tabs/columns, dead endpoints, stale CLI flags, or docs still advertising removed commands.
- **Docs/tests lagging**: any slice that deletes behavior without updating its tests/docs in the same slice.

## 5. Constraints

- AGENTS.md engineering rules: small, coherent, testable slices; no broad refactor beyond the directed change; CLI behavior changes documented.
- Defensive-only posture unchanged.
- Repo currently carries small in-flight owner work (paginated assets labels, i18n Cytomic strings, Rule Lab TLP/PAP metadata, docs tweaks, new `payloads/` dir): preserve and build on it; never revert it.

## 6. Decided with the Owner

| Decision | Value |
|---|---|
| Deprecation level | **Removal now** (no advisory phase) |
| Scope | (a) CLI `emulate` + emulation targets; (b) intrusion-set planning (`plan` + web adversary planning); (c) `spuc-agent` + ability contract/catalog of abilities; (d) Web adversaries + payloads |
| `payloads/` corpus | Intact, untracked, out of scope |
| Learning section | Keep the 15 STIX-pattern challenges; remove only the adversary-build info block |
| On-disk legacy data | `abilities/*.json`, `intrusion_sets/*`, hidden emulate history rows: stay on disk, are not deleted by SPUC, and stop being used by the rules surface |
| Replacement | Not built now (future external LLM/agent approach) |
| Release | None in this iteration |

## 7. Decided by Engineer (flagged for owner veto)

1. **Rules store**: new translation-owned file `<config_root>/catalog/rules.json` — a JSON array keyed by synthetic STIX indicator id (`indicator--<uuid>`, same minting rule as today). Fields for the encoded metadata decoded from legacy ability descriptions: name, description, tlp, pap, ttp, rule_confidence, observables, indicates, source pattern. Serde-tolerant (skip unknown fields; tolerate missing ones) in the same style as existing persisted stores.
2. **Migration**: on first rules-store load, seed from legacy `abilities/*.json` using the current decode semantics (unchanged code semantics, relocated); idempotent by indicator id; legacy ability files are never written or deleted afterwards. This is read-legacy → seed-new → ignore-legacy: no in-place format rewrite of user data.
3. **Activities**: relocation of the `TranslationActivity` record/list/delete logic out of `src/emulation/catalog.rs` into the catalog namespace; same JSONL file (`<config_root>/catalog/translation_activities.jsonl`) and serde row compatibility. Dual-flow hidden rows cease; readers stop using `command != translate` rows for status derivation.
4. **Output renderer relocation**: `OutputBlock`/`OutputSection`/`resolve_output_blocks` move out of `src/emulation/output.rs` (translate and catalog still render multi-block output; verified usages in `src/commands/common.rs`, `src/catalog/mod.rs`). Behavior-neutral relocation.
5. **CLI**: `Commands::Emulate`, `AbilityTarget`, emulate-only `--export csv` branch die. On `translate`: remove `--refresh` (its meaning died with the dual-flow cache); keep `--mode`, keep `--ttp` with corrected help text (rule metadata for detection output, not "emulation artifacts"). Visible translate activity recording semantics unchanged (record per run/target).
6. **Status model**: `emulation_statuses` / `emulable` disappear from rows, APIs and UI. The rules grid shows translation statuses only (derived from visible translate activities, as today's visible rows already do).
7. **Dashboard KPIs** redefinition (translation-only): rules total, converted-target distribution, runtime-status distribution. `emulation_coverage`, `abilities_total`, `adversaries_total` die.
8. **Modules to delete** (emulation/legacy arms): `src/emulation/*` (ability, agents/*, campaign, materialize, validate, export, output after relocation, catalog after activity relocation), `src/commands/plan.rs` console internals, `src/commands/emulate.rs`, `build_ability_from_rule` + dual-flow helpers in `src/commands/common.rs`, `src/tui/*` + `src/commands/console.rs` + `rustyline` dep, `src/commands/adversaries.rs`, `src/commands/rules.rs` shims, orphaned `src/main.rs` plus its harness-only re-exports in `src/app/run.rs`, `legacy-cli-tests` feature and `tests/campaign_catalog_cli.rs`.
9. **Tests**: delete `tests/ability_cli.rs`, `tests/spuc_agent_cli.rs`, feature-gated campaign tests, adversary/dummy web-API unit tests, emulation DOM pins in `src/web/assets.rs`. Add/update: rules-store migration test (legacy ability → seeded rule with decoded metadata), direct `persist_rule_entry` tests, `tests/cli_examples.rs` (help list without `emulate`; `emulate` listed among rejected commands), activity-recording test asserting no abilities/hidden rows are written anymore.
10. **Docs**: README rewrite (flowchart, usage, help sample, packaging, drop "Available Emulation Targets" and emulation workflow claims); `docs/abilities.md` and `docs/intrusion-sets.md` deleted; `docs/ability-roadmap.md` and `docs/intrusion-set-roadmap.md` deleted; `docs/catalog.md` rewritten for rules/translations; `docs/current-decisions.md` Ability/Persistence/Intrusion/dual-flow sections rewritten + build-layout truth (`crates/spuc-cli` is the entrypoint); `docs/deployment.md` and `docs/web.md` de-emulated (append changelog note for the removal); `AGENTS.md` Project Intent + Working Workflow + docs list rewritten; `examples/workflow/` emulation samples deleted or replaced by a translation-only sample; a short "Emulation removed (2026-10)" note in README/current-decisions pointing to the future LLM/agent approach. `spuc web` help one-liner rewritten.
11. **Rules-grid row source is preserved, not redesigned.** The Rules page keeps today's composition: `rules.json` saved entries ∪ unsaved patterns derived from visible `translate` activity rows (with minus emulation statuses). Unsaved rows may keep being deleted (purge visible rows); saved-row delete removes the entry and purges that pattern's visible activity rows. Rationale: the owner directed emulation removal, not a rules-page redesign; AGENTS.md says preserve behavior unless intentionally changed.
12. **Deterministic rule ids**: the canonical id scheme for all rows going forward is the FNV hash over the raw (trimmed) pattern — the scheme already used today as fallback — replacing the dual-flow-derived `DefaultHasher` scheme, which dies with the dual-flow. Ids are presentation keys minted per-read (they are not persisted references; indicates/stix-object joins bind object ids stored inside rules, so id-scheme switch does not break joins).
13. **Migration seed discriminator**: a legacy ability becomes a rules-store entry **iff** its `description` successfully decodes as web-save rule metadata (the `encode/decode` pair). Abilities without encoded metadata (dual-flow-generated defaults, `spuc-agent` style exports), `abl-dummy-*` plan dummies and adversary custom-payload abilities produce no rule entries (they never appeared in the grid).
14. **Seed trigger semantics**: legacy seeding runs once, guarded by a persisted marker (marker file under `<config_root>/catalog/` recorded after a successful seed; crash-safe retry allowed before the marker exists). Idempotent-by-id only covers the pre-marker window. After the marker, deleting `rules.json` does NOT resurrect rules from legacy ability files (documented behavior; rule-entry deletion is durable).

## 8. Left to the Builder

- Exact module placement/naming for relocated output and activity code (conventions: `src/ui` vs `src/commands`, catalog namespace) — decisions marked in code comments.
- Confirm the compilation boundary: after relocating, `src/commands/common.rs`, translate, catalog and web must compile with `src/emulation/` deleted entirely; any lingering reference is a defect to surface, not to paper over.
- Verify no emulation content remains: `grep -ri emul src/` finds nothing (aside from unrelated words) and `spuc help` matches the target command list.
- Keep every surviving slice compiling and `cargo test` green; reports may reduce CLI/JSON-RPC/web unit tests only to the extent pinned behavior genuinely dies.
- Discover-and-document (not silently fix) the pre-existing latent bug in the fallback rule-save path (non-emulable rules persisted without metadata) — superseded by the new direct rules store, note it in changelog.

## 9. Suggested Slice Order (per AGENTS small-slices rule)

1. **Slice A — translation-owned rules store + activity/output relocations.** New rules store, legacy seeding, dual-flow removal from `translate`.
2. **Slice B — CLI cut.** Remove `emulate` command/flags, `--refresh`, `--ttp` text fix, `spuc web` one-liner, `spuc-agent` binary from crate workspace, Dockerfile, CI workflows, release packaging.
3. **Slice C — code deletion.** Emulation modules, plan/console/TUI/shims/orphan main, feature-gated tests, duplicated legacy helpers.
4. **Slice D — web cut.** Nav/routes/views/endpoints/dialogs, rules grid columns/tab, dashboard KPIs redefinition, Learning block, i18n prune (both locales), DOM-pinned tests updated.
5. **Slice E — docs + cleanup.** README, docs set, AGENTS.md, examples, deprecation note, final `grep` hygiene passes.

Each slice: compile + tests green + docs touched in-line where behavior changes.

## Appendix A — Coupling Map (from the adversarial analysis)

Key verified facts (file:line from analysis run at 2026-10-22):

- Rules persistence through emulation: `src/web/api.rs:4697-4764` (`persist_rule_entry` → `emulate::run`), metadata encoding in ability `description` (`api.rs:6075+`, used `4629-4637`), fallback to `translate::run` (`api.rs:4724-4745`).
- Dual-flow: `src/commands/common.rs:146-234` (`translate_rules` → `sync_hidden_emulation_from_translate:556-606` upserts Ability at line 569, hidden emulate rows 579-603), `emulate_rules:236-412` (`sync_hidden_translation_from_emulate:609-675`), cache key `rule_hash + DUAL_FLOW_ENGINE_VERSION` (`common.rs:28-29`, `540-553`), `has_cached_activity` (`src/emulation/catalog.rs:241-270`). Empirical: one `translate --to kql` on a clean root produced 1 ability file + 1 visible translate row + 7 hidden emulate rows.
- Catalog duality: `src/catalog/mod.rs:63-69` merges abilities + activities + intrusion sets; rule fields from ability JSON (`177-243`); `emulable` via 5-exporter dry-run (`766-771`); rule ids via `catalog_indicator_id:794-830`; delete path removes ability + history (`716-738`).
- Web emulation-only endpoints: `/api/abilities*` (`api.rs:5107-5429`), `/api/adversaries*` (`5454-5686` incl. full planning pipeline per row at `6438-6463`), bootstrap counters (`2595-2599`), dashboard emulation KPIs (`3614-3699`), learning adversary block (`6691-6697`).
- CLI truth: commands live in `src/cli.rs` (`spuc help` shows `emulate jsonrpc translate verify version sigma web help`); `plan`, `explore`, `catalog ...` are already rejected by the compiled CLI and pinned by `tests/cli_examples.rs:91-111`. `spuc-agent` binary: `crates/spuc-cli/Cargo.toml:9-12`, built from `src/emulation/agents/spuc_agent_cli.rs`.
- Dead code carried by the build: `src/main.rs` is not a compiled target (verified via `cargo metadata`); `src/tui/mod.rs` (1731 lines) unreachable; `plan.rs` console internals (~2400 lines) unreachable except `export_saved_adversary` (`231-277`) used by the web API; `commands/console.rs`, `commands/adversaries.rs`, `commands/rules.rs` shims; `rustyline` dep exists solely for the TUI; duplicated `resolve_output_blocks`/`default_campaign_show`/`show_output_value` in `plan.rs:52-126`, `common.rs:685-758`, `src/app/run.rs:121-133` (re-export constructed for orphaned `main.rs` tests).
- Packaging/CI: `Dockerfile:10,34`; `.github/workflows/release.yml:126,144`; `.github/workflows/ci.yml:95-109`; README packaging claims (`:96,:200,:253`).
- i18n surface to prune: `src/web/i18n.rs` ≈406 `adversar*` keys, ≈80 ability/emulation keys, ≈112 payload keys (EN+ES).
- Guides: `kb/guides/GUIDE_EN.md` / `GUIDE_ES.md` contain **no** emulation/catalog/planner content — untouched by design.
- Existing docs already untruthful (to fix in-line): `AGENTS.md:53-68` (records removed commands as current workflow), `docs/current-decisions.md:82` (asserts `src/main.rs` is the thin entry; the compiled entry is `crates/spuc-cli`), `docs/catalog.md:35-243` (documents removed CLI verbs and console grammar), `examples/workflow/README.md` (documents the already-removed `spuc console` grammar).

## Appendix B — Data Retention Contract (post-removal)

| Path | Contains | Fate |
|---|---|---|
| `<config_root>/catalog/rules.json` | New translation-owned rules store | Created by Slice A; source of truth afterwards |
| `<config_root>/abilities/*.json` | Legacy abilities (incl. rule metadata in descriptions) | Read once for seeding; thereafter ignored; never deleted or written by SPUC |
| `<config_root>/intrusion_sets/*` | Legacy adversary manifests + artifacts | Ignored by SPUC; never deleted by SPUC |
| `<config_root>/catalog/translation_activities.jsonl` | Activity history (translate-visible + legacy hidden emulate rows) | Path/format preserved; legacy hidden rows tolerated and ignored for statuses |
| `web_users.json`, `web_oauth_policy.json`, `web_user_api_tokens.json`, `stix-objects.json`, `sigma/runtime.json` | Web/auth/STIX/Sigma state | Unaffected |
| `payloads/` (repo, untracked) | Owner's external ATT&CK corpus | Untouched, out of scope |
