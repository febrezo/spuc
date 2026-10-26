# Remove Adversary Emulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (Native execution, chosen by the owner ["continua y acaba la tarea"]). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the entire adversary-emulation user surface (CLI `emulate`, `spuc-agent`, abilities/abilities catalog, web adversaries+payloads, dual-flow) and give translation its own rules store, leaving SPUC with parse/verify/translate/sigma/jsonrpc/web-rules only.

**Architecture:** Staged slices, each keeping compile + tests green: (A) relocate activity/output modules out of `src/emulation/`, add translation-owned `catalog/rules.json` store with legacy-abilities seeding; (B) rewrite web rules persistence so it never calls emulate; (C) cut CLI; (D) delete engine + packaging; (E) web adversary/payload cut; (F) docs; (G) hygiene gate. Design decisions live in the spec — see §7 items 1–15 and Appendix A/B (data-retention contract, migration discriminator, id scheme, seed marker, delete semantics).

**Tech Stack:** Rust (`spuc-core` workspace lib + `spuc-cli` bin + `spuc-gui`), file persistence (JSON/JSONL), serde, tests via `cargo test`.

**Spec:** `docs/superpowers/specs/2026-10-22-remove-adversary-emulation-design.md` (read together; the plan argues from it).

## Global Constraints

- Immutable, never modify: `kb/standards/STIXPattern.g4`, `kb/standards/stix-v2.1-cs01.html`, `kb/guides/GUIDE_EN.md`, `kb/guides/GUIDE_ES.md`.
- `payloads/` (untracked): never add, modify, commit, or delete it.
- Preserve the owner's in-flight working-tree edits (assets.rs pagination labels, i18n Cytomic, Rule Lab TLP/PAP, docs tweaks, Cargo.tomls, Cargo.lock): Task 0 commits them verbatim first; never revert them.
- On-disk legacy data (`abilities/*.json`, `intrusion_sets/*`, hidden emulate activity rows): never deleted or written by SPUC; seeding reads abilities but leaves files byte-identical.
- Web modal footer convention unchanged for surviving modals (left `Cancelar`/`btn-danger`, right primary).
- No release/tag/publish in this iteration; version stays `0.9.4`.
- Defensive-only posture; every task updates tests in the same iteration; CLI behavior changes are documented in the same task.
- No new invented metadata fields: the persisted-rule field set mirrors exactly what `encode_rule_metadata_description`/`decode_rule_metadata_description` in `src/web/api.rs` encode/decode today.

## Review Focus

- A legacy ability holding web-save metadata must be recovered by seeding and keep every encoded field (test: Task 3 step pins roundtrip of TLP/PAP/TTP/observables/indicates through decode).
- Hidden legacy `emulate` rows in `translation_activities.jsonl` must remain on disk and be tolerated by readers forever (test: Task 4 loads a JSONL mixing legacy hidden rows and asserts they survive delete).
- Rules save/list/edit/delete must work with `abilities/` entirely absent (fresh machine) (test: Task 4 uses a temp config root with no abilities dir).
- Deleting a rule must be durable — no resurrection from legacy ability files after the seed marker exists (test: Task 3/4 delete → reload → absent).
- Unsaved translated patterns keep appearing in the grid with translation statuses derived from visible translate rows only (test: Task 4 mixes visible translate + legacy emulate rows and asserts derivation).
- `spuc help` must show the exact target command list without `emulate`, and `emulate` must be rejected like `plan`/`explore` (test: Task 5 cli_examples).
- Dashboard/Must counters must not mention abilities/adversaries/emulation coverage (test: Task 7 grep + API shape test).

---

## Task 0: Commit the owner's in-flight edits (protect them)

**Files:** Working-tree dirty files only (no content changes).

- [ ] **Step 1:** `git status --short` → confirm only the expected dirty set (Cargo.lock, crates/*/Cargo.toml, docs/current-decisions.md, docs/web.md, src/web/assets.rs, src/web/static/boot.js, src/web/static/index.html).
- [ ] **Step 2:** `git diff` quick pass to confirm edits are small label/metadata tweaks (no surprises hiding in the diff).
- [ ] **Step 3:** `cargo test -p spuc-core` green on the tree as-is (baseline).
- [ ] **Step 4:** Commit everything except the untracked `payloads/` dir:
  `git add -A ':!payloads' && git commit -m "chore: preserve in-flight UI/doc tweaks (rule-lab TLP/PAP, pagination labels, i18n Cytomic)"`
  Verify `payloads/` is still untracked.

## Task 1: Relocate activity log + output renderer out of `src/emulation/` (behavior-neutral)

**Files:**
- Create: `src/catalog/activities.rs`, `src/ui/output.rs`
- Modify: `src/emulation/catalog.rs`, `src/emulation/mod.rs`, all import sites (`grep -rn "emulation::catalog\|emulation::output\|AbilityCatalog" src/`), `src/domain/mod.rs` if module wiring needs it
- Test: unit tests move with the code (new modules' `#[cfg(test)]` blocks)

**Interfaces:**
- Produces: `src/catalog/activities.rs` with `pub(crate) struct ActivityLog` (resolve config root via `paths::spuc_config_root()`, NOT via an `abilities`-dir parent trick) exposing `record_translation_activity(&TranslationActivity)`, `list_translation_activities(Option<&str>, Option<usize>)`, `delete_translate_activities_by_rule(&str) -> Result<usize>` (deletes ONLY rows with `command == "translate"`), `list_rule_activity_summary`, `translation_activities_path(config_root) -> PathBuf` (`<root>/catalog/translation_activities.jsonl`, create_dir_all). Structs `TranslationActivity` (+`new`, `with_cache_meta`) and `RuleActivitySummary` move here unchanged (serde format byte-compatible).
- Produces: `src/ui/output.rs` with `OutputBlock`, `OutputSection`, existing renderers unchanged; all callers use `crate::ui::output` (common.rs, catalog/mod.rs, plan.rs; `src/app/run.rs:121-126` adapter deleted with its orphaned `main.rs` test).
- Note: `AbilityCatalog` keeps ONLY ability-file methods for now (ability/__helpers die in Task 7); its activity methods and their callers move to `ActivityLog`.

- [ ] **Step 1 (failing test):** write tests in `src/catalog/activities.rs` mirroring the moved tests (`activity_log_records_and_lists_in_desc_order`, `activity_rule_summary_groups_by_rule`, `activity_log_survives_concurrent_appends`, `has_cached_activity_matches_cache_meta`) against `ActivityLog`; they fail to compile before code exists.
- [ ] **Step 2:** run `cargo test -p spuc-core activities` → compilation failure expected.
- [ ] **Step 3:** implement: move structs/functions verbatim from `src/emulation/catalog.rs:17-345` — keep bodies byte-identical except `activities_path` now derives from `spuc_config_root()` directly; delete `has_cached_activity` ONLY if no non-emulation caller remains (`grep` first; translate's dual-flow still uses it until Task 3 — if used, keep in activities.rs).
- [ ] **Step 4:** update every import site (`grep -rn "emulation::catalog::\|emulation::output" src/`) → `crate::catalog::activities` / `crate::ui::output`; move `src/emulation/output.rs` content to `src/ui/output.rs` (check its internal imports first), remove moved decls from `src/emulation/mod.rs`.
- [ ] **Step 5:** run `cargo test -p spuc-core` → PASS (old emulation/catalog tests for activities removed, ability tests stay until Task 7).
- [ ] **Step 6:** `cargo fmt` + commit `refactor: move translation activities and output blocks out of emulation (behavior-neutral)`.

## Task 2: Translation-owned rules store `catalog/rules.json`

**Files:**
- Create: `src/catalog/rules.rs` (module declared in `src/catalog/mod.rs`)
- Modify: `src/web/api.rs` — relocate `encode_rule_metadata_description` / `decode_rule_metadata_description` (approx. lines 6075+, definition and decode-pair) into `src/catalog/rules.rs` verbatim (api.rs calls the new module fns; NOT duplicated copy)
- Test: unit tests in `src/catalog/rules.rs`

**Interfaces:**
- Produces: `pub(crate) struct PersistedRule` — fields exactly mirroring the moved encode pair's payload (expect: `indicator_id`, `source_pattern`, `name`, `description`, `tlp`, `pap`, `ttp: Option<String>`, `rule_confidence: Option<u8>`, `observables: Vec<String>`, `indicates: Vec<String>`; adjust to what encode/decode actually carry — added/invented fields violate Global Constraints). Serde: field-level `#[serde(default)]` where decode tolerates absence.
- Produces: `mint_rule_indicator_id(source_pattern: &str) -> String` → `indicator--<fnv>` — extract the FNV-over-trimmed-pattern logic already in `src/catalog/mod.rs:781-830` (`catalog_indicator_id` fallback branch) as the single canonical scheme; `rule_hash`-based variants die with the dual-flow (Task 3 deletes their last caller).
- Produces: `rules_path(config_root) -> PathBuf` (`<root>/catalog/rules.json`); `load_persisted_rules(config_root) -> Vec<PersistedRule>` (skip unparseable entries, tolerate missing fields — same permissiveness as ability listing); `save_persisted_rules(config_root, &[PersistedRule]) -> Result<()>` (pretty JSON, write-whole-file); `upsert_persisted_rule(config_root, PersistedRule) -> Result<bool>` (created? by indicator_id); `delete_persisted_rule(config_root, indicator_id) -> Result<bool>`.
- Produces (task-internal): `catalog/features.rs`? no — single file; `mod rules;` in `src/catalog/mod.rs`.
- Consumes: nothing from emulation.

- [ ] **Step 1 (failing tests):** roundtrip upsert→load→update→delete; deterministic `mint_rule_indicator_id` (same pattern → same id, distinct patterns → distinct ids, format `indicator--`); skip-invalid entries; file created on first save in temp root.
- [ ] **Step 2:** `cargo test -p spuc-core rules` → compile failure expected.
- [ ] **Step 3:** implement module + relocate encode/decode pair from api.rs (update api.rs call sites to module fns).
- [ ] **Step 4:** `cargo test -p spuc-core` PASS; `cargo test -p spuc-core --lib` also green (api.rs untouched behavior).
- [ ] **Step 5:** `cargo fmt` + commit `feat: translation-owned rules store with inlined metadata codec`.

## Task 3: Legacy seeding from `abilities/*.json` (once, marker-guarded)

**Files:**
- Modify: `src/catalog/rules.rs` (add migration fn + tests), `src/catalog/mod.rs` (call `ensure_rules_seeded` at catalog entry points used by web load path)

**Interfaces:**
- Produces: `seed_rules_from_legacy_abilities(config_root) -> Result<usize>` — reads `<root>/abilities/*.json` if present, parses each file as `serde_json::Value` (no dependency on the `Ability` struct), skips ids starting `abl-dummy-`; becomes a rule iff description decodes via the module's decode fn; entry fields: name/description/tlp/pap/ttp/rule_confidence/observables/indicates from decode + `source_pattern` from file; `indicator_id = mint_rule_indicator_id(source_pattern)`. Files are read-only (Global Constraints).
- Produces: `ensure_rules_seeded(config_root) -> Result<()>` — if marker `<root>/catalog/rules.json.seeded` (content `{"seeded_from_abilities": true,"utc": "<rfc3339>"}`) exists → no-op; else seed then write marker (crash-safe: marker after successful persist). Deleting `rules.json` afterwards does NOT re-trigger (marker persists).

- [ ] **Step 1 (failing test):** temp root with 3 legacy ability files — one web-save ability with encoded metadata, one dual-flow default ability (no encoded metadata), one `abl-dummy-*`; assert: after `ensure_rules_seeded`, exactly 1 persisted rule with every decoded field correct, legacy files byte-identical (`fs::read` before/after), marker exists, second call = no-op, `delete_persisted_rule` then `ensure_rules_seeded` again → rule stays deleted.
- [ ] **Step 2:** run → compile failure expected.
- [ ] **Step 3:** implement both fns; wire `ensure_rules_seeded` into the config-root paths reached by web rules load/save (grep `load_catalog_data` / rules endpoints) and CLI catalog surfaces via catalog entry points.
- [ ] **Step 4:** `cargo test -p spuc-core` PASS.
- [ ] **Step 5:** commit `feat: one-time seeding of rules store from legacy abilities with durable marker`.

## Task 4: Web rules persistence rewrite (no emulate anywhere in the save path)

**Files:**
- Modify: `src/web/api.rs` (`persist_rule_entry` ~4697-4764, rule endpoints ~4568-4700, `rule_view` ~5966, indicates endpoint ~4652, `build_catalog_rule_entries` consumers), `src/catalog/mod.rs` (rules grid source-of-truth merge)
- Test: unit tests in `src/web/api.rs` in-module tests + `src/catalog/mod.rs` tests (rewrite `905-964` pins; adjust `7122` save-rule test)

**Interfaces:**
- Produces: rules rows now = persisted rules ∪ activity-derived unsaved patterns; `emulation_statuses`/`emulable`/`ability_id` read as EMPTY `Vec`/`false` (serde-default fields keep compiling so the UI does not crash before Task 7 deletes them entirely).
- Produces: `DELETE /api/rules/{id}` = `delete_persisted_rule` + `delete_translate_activities_by_rule`(visible rows only) + never touches `abilities/` or hidden legacy rows.
- Produces: `POST /api/rules/save` = ensure_rules_seeded → translation evaluation of the rule across ALL detection targets recording VISIBLE translate activities (reuses the exact recording per-target path `translate` uses) → upsert PersistedRule. No `emulate::run`, no `translate::run` fallback, no ability upsert.
- Consumes: Task 1 `ActivityLog`, Task 2 store fns, `src/app/services/translation.rs` evaluation entry used by translate (`grep evaluate_rule_from_labels` for exact signature).

- [ ] **Step 1 (failing tests):** (a) save rule in temp root WITHOUT abilities dir → 200/ok shape, rules.json contains entry with metadata; (b) JSONL with visible translate rows + legacy hidden emulate rows → grid statuses derive only from translate rows; emulate rows survive a rule delete (unchanged file bytes for hidden rows); (c) unsaved translated pattern appears as row without persisted entry; (d) indicates roundtrip.
- [ ] **Step 2:** run new tests → fail.
- [ ] **Step 3:** implement (rewrite named fns; catalog/mod.rs grid merge; keep response structs compiling with defaulted emulation fields).
- [ ] **Step 4:** full `cargo test -p spuc-core` green including adjusted former pins.
- [ ] **Step 5:** commit `feat: web rule save/list/edit/delete served by translation rules store (no emulation path)`.

## Task 5: CLI cut — remove `spuc emulate`

**Files:**
- Modify: `src/cli.rs` (remove `Commands::Emulate` + `AbilityTarget` enum + emulate-only help; translate: remove `--refresh` field, fix `--ttp` help text — rule metadata for detection output; fix `spuc web` one-liner), `src/app/run.rs` (remove `Commands::Emulate` match arm), `src/commands/mod.rs` (remove `emulate`), delete `src/commands/emulate.rs`, `src/commands/common.rs` (delete `emulate_rules` body + dual-flow block in `translate_rules` = remove sync_hidden_emulation_from_translate call + fn; keep visible-activity recording lines 189-200 behavior; delete `sync_hidden_translation_from_emulate`, `DUAL_FLOW_ENGINE_VERSION`, rule_hash/composer if last callers stop)
- Modify tests: `tests/cli_examples.rs` (`help_groups_root_commands` → expected list WITHOUT emulate: `jsonrpc translate verify sigma web version help`? — pin the literal string the enum produces after removal; `removed_cli_commands_are_rejected` add `"emulate"`), delete `tests/ability_cli.rs` (pins emulate CLI behavior that no longer exists)

**Interfaces:**
- Consumes: Task 1 ActivityLog for `translate_rules` visible recording (unchanged semantics).
- Produces: `translate` keeps `--mode partial`, `--export csv`, `--output`, `--description`, `--rule-confidence`, `--ttp` (corrected help); loses `--refresh` (docs updated in Task 8; add one-line note in commit body).

- [ ] **Step 1 (failing test):** update `tests/cli_examples.rs` expectations (help list + rejected `emulate`) → run → fail.
- [ ] **Step 2:** implement CLI removals; keep `plan.rs` compiling (web still imports `export_saved_adversary`); `grep -rn "emulate_rules\|AbilityTarget" src/` → only emulation-internal refs remaining until Task 7.
- [ ] **Step 3:** `cargo test` (all 3 crates) PASS; delete `tests/ability_cli.rs` in this task (its behavior is now gone).
- [ ] **Step 4:** commit `feat: remove spuc emulate from CLI; translate loses dual-flow --refresh` (body notes behavior change).

## Task 6: Remove `spuc-agent` binary + packaging; delete unreachable legacy arms

**Files:**
- Modify: `crates/spuc-cli/Cargo.toml` (remove `[[bin]] spuc-agent`), delete `src/emulation/agents/spuc_agent_cli.rs`, `Dockerfile:10,34`, `.github/workflows/ci.yml` spuc-agent build lines (~95-109), `.github/workflows/release.yml` (~126,144), README packaging/dual-flow mentions (partial; full rewrite Task 8)
- Delete (unreachable/uncompiled): root `src/main.rs`; `src/commands/{console,adversaries,rules}.rs` (not in `mod.rs`); `src/tui/mod.rs` + `mod tui;` in `src/lib.rs` + `rustyline` dep in root Cargo.toml; `tests/campaign_catalog_cli.rs` + `legacy-cli-tests = []` feature in root Cargo.toml (grep `cfg(legacy-cli-tests)` refs first — if any src cfg exists, remove the cfg blocks too)
- Delete: `tests/spuc_agent_cli.rs` (binary is gone)

**Interfaces:**
- Consumes: nothing new.
- Produces: workspace compiles with `-p spuc-gui` too (`cargo build -p spuc-gui` check).

- [ ] **Step 1:** `git rm` the files; edit Cargo.tomls/Dockerfile/workflows as pinned; `grep -rn "spuc-agent\|legacy-cli-tests\|rustyline" src crates .github Dockerfile README.md` → remaining hits documented as Task 8 work (README claims ok mid-iteration ONLY if a Task-8 line exists in the plan — but CI/Docker must be fully clean in THIS task).
- [ ] **Step 2:** `cargo test` + `cargo build -p spuc-gui` PASS.
- [ ] **Step 3:** commit `feat: drop spuc-agent binary and dead legacy CLI arms; clean packaging`.

## Task 7: Web adversary/payload cut + full emulation engine deletion

**Files:**
- Modify: `src/web/api.rs` (delete `/api/abilities*`, `/api/adversaries*` routes+handlers incl. dummy/compatibility/export, bootstrap counters ~2595-2599 → translation-only counter set (`rules_total`, `targets` summary), dashboard KPI block ~3614-3699 redefined to translation KPIs, learning adversary-build block ~6691-6697 deleted; delete adversary/dummy unit tests), `src/catalog/mod.rs` (delete ability loading/`emulable`/intrusion-set merging; grid = rules store + activities only), `src/commands/common.rs` (delete `build_ability_from_rule` + predicate/value coercers 852-1719 + ability imports), delete `src/commands/plan.rs` (wholesale; `export_saved_adversary` callers are the deleted endpoints) + `mod plan;` decl, delete `src/emulation/{ability,materialize,validate,export,catalog,campaign}` + `agents/{mod,atomic_red_team,bash,mitre_caldera,powershell,spuc_agent}.rs` + delete `pub mod emulation;` from `src/lib.rs` + delete `src/emulation/mod.rs`
- Modify: `src/paths.rs` (delete `abilities_dir`, `campaigns_dir` — grep callers first), `src/domain/mod.rs` (updated mount notes)
- Web: `src/web/static/index.html` (nav lines ~106 Payloads, ~114 Adversaries; learning keeps its nav; welcome-card adversary links ~184, ~546-560 → point to rules catalog), `src/web/static/boot.js` (views/dialogs/routes for adversaries+payloads, `RULE_EMULATION_TARGETS`, rules-table emulation column, rule-detail emulation tab, `localStorage` payload keys, dashboard chart data), `src/web/assets.rs` (rewrite emulation DOM pins ~277,302-305,337-370 to pin the rules-only DOM), `src/web/i18n.rs` (prune adversar*/ability/emulation*/payload keys EN+ES)
- Test: api.rs in-module tests rewritten/deleted accordingly; assets.rs updates

**Interfaces:**
- Consumes: Task 2 rules store, Task 4 grid merge.
- Produces: final module graph has NO `emulation` namespace; `grep -rn "emulation" src/` returns zero; `spuc help` exact target list.
- Bootstrap counter names (pinned for Task 8/9 checks): `rules_total` and `targets` (summary of converted targets) — `abilities_total`, `adversaries_total`, `emulation_coverage` gone.

- [ ] **Step 1:** endpoints/handlers deleted FIRST (compiles while engine still present); web UI files pruned in same task (nav → views → dialogs → i18n keys); assets.rs tests updated to fail first, then new DOM pinned.
- [ ] **Step 2:** delete `plan.rs` + emulation engine directories + `build_ability_from_rule` in `common.rs`; `pub mod emulation;` removed; catalog/mod.rs grid reads Task-2 store only; `cargo test` after each of these two commits-green interleaves (endpoint commit, engine commit).
- [ ] **Step 3:** `grep -rni "emul\|adversar\|abl-dummy" src/` → zero relevant hits (word-boundary check; benign words only documented in commit body).
- [ ] **Step 4:** `cargo test` all crates PASS; commit 1 `feat: remove adversary/payload web surface`, commit 2 `feat: delete emulation engine from codebase`.

## Task 8: Docs truth pass (same-iteration docs rule)

**Files:**
- Delete: `docs/abilities.md`, `docs/intrusion-sets.md`, `docs/ability-roadmap.md`, `docs/intrusion-set-roadmap.md`, `examples/workflow/` (emulation samples)
- Rewrite: `README.md` (mermaid flow without Emulate/Plan/agent; usage = translate/verify/sigma/web/jsonrpc/version; CLI help sample synced with Task 5 test string; behavior notes without dual-flow; delete "Available Emulation Targets" and emulate workflow claims; packaging without spuc-agent; short "Emulation removed (2026-10)" note pointing to future LLM/agent approach), `AGENTS.md` (Project Intent → translate/verify/catalog; Working Workflow → translate/verify/sigma/web; docs list updated; web modal convention kept), `docs/current-decisions.md` (drop Ability Contract/Intrusion Persistence paragraphs; add rules catalog store + data-retention paragraph per Appendix B; fix CLI Source Layout (`crates/spuc-cli` is the compiled entry; root `src/main.rs` deleted), Translation Activity Tracking → activities description, dual-flow removed), `docs/catalog.md` (rules + activities + rules.json store; NO removed commands), `docs/deployment.md` (env vars, no spuc-agent), `docs/web.md` (append removal changelog dated 2026-10-22; strip emulation feature narratives), `docs/README index`? (check if docs index references removed files and update)
- Keep: `docs/jsonrpc.md`, `docs/mcp.md`, `docs/ci-cd.md` (verify no emulation claims; strip if found)

- [ ] **Step 1:** `grep -rn "emulate\|emulation\|adversar\|intrusion\|spuc-agent\|abilit(y|ies)" README.md AGENTS.md docs/ examples/` → edit every hit to the target state.
- [ ] **Step 2:** build docs (CI runs `cargo doc`? — run `cargo doc --no-deps` if cheap; else skip with note) + `cargo test` still green.
- [ ] **Step 3:** commit `docs: repository truth after emulation removal (2026-10-22)`.

## Task 9: Hygiene + verification gate

**Files:** none by design; verification only (fix-ups allowed, folded into final commit).

- [ ] **Step 1:** `cargo fmt --check` PASS; `cargo clippy --workspace -D warnings` PASS (CI-gated lints).
- [ ] **Step 2:** `cargo test` (default members) PASS 3× in a row (flakiness check on activity/store/migration tests).
- [ ] **Step 3:** manual CLI checks: `spuc help` matches Task 5 pinned list; `spuc emulate --rule x 2>&1 | head -3` rejected; `spuc translate --rule "[process:name = 'cmd.exe']" --to kql` emits KQL; fresh `SPUC_CONFIG_DIR=$(mktemp -d)` run leaves NO `abilities/` dir and no `intrusion_sets/` dir, but DOES create `catalog/translation_activities.jsonl` + `catalog/rules.json` after a web-style save (or skipped if save only reachable via web curl — use the documented API script instead);
- [ ] **Step 4:** `git log --oneline` review of the slice commits; final commit `chore: verification gate after emulation removal` only if fix-ups happened.
