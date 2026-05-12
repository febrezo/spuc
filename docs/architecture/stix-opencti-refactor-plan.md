# STIX-OpenCTI Refactor Plan

Last updated: 2026-05-12

## Goal

Prepare a safe refactor path to integrate STIX/OpenCTI-oriented workflows without breaking current SPUC defensive behavior, catalog persistence, or web UX.

## 1) Existing STIX Translation APIs

### Web API (HTTP)
Source: src/web/api.rs (route dispatcher)

- GET /healthz
- POST /api/verify
- POST /api/rules/compatibility
- POST /api/rules/export/bundle-from-pattern
- POST /api/rules/export/bundle
- GET /api/rules
- GET /api/rules/{selector}
- POST /api/rules/save
- DELETE /api/rules/{selector}
- POST /api/rules/{selector}/indicates
- GET /api/abilities
- GET /api/abilities/{id}
- GET /api/abilities/{id}/export?to=...

### JSON-RPC API
Source: src/commands/jsonrpc.rs

- POST /rpc (Bearer token required)
  - Input: rule, to[], sigma_targets[], mode, description, rule_confidence
  - Output: per-target compatibility and rendered output

### CLI Entrypoints
Source: src/cli.rs, src/app/run.rs

- spuc translate
- spuc verify
- spuc emulate (dual-flow compatibility update is active in background)

## 2) Current User/Auth/Config Model

### User/Auth
Sources: src/web/auth.rs, src/web/api.rs

- Local users in web_users.json with role model:
  - admin
  - analyst
- Session cookie: spuc_web_session
- OAuth providers: google, github
- OAuth provider authorization policy persisted and managed by admin
- --no-login mode available (bootstrap local admin principal)

### Runtime/User Settings
Source: src/web/api.rs

- Runtime settings persisted in web_runtime_settings.json
- User preferences persisted in web_user_preferences.json
- Config root resolved from SPUC_CONFIG_DIR or OS defaults (src/paths.rs)

## 3) Current Persistence Locations

- Rules and emulation abilities: <config_root>/abilities/*.json
  - Source: src/emulation/catalog.rs
- Translation activity log: <config_root>/catalog/translation_activities.jsonl
  - Source: src/emulation/catalog.rs
- Adversary manifests: <config_root>/intrusion_sets/*.yaml (or .json when explicitly exported)
  - Source: src/emulation/campaign.rs
- STIX object catalog: <config_root>/stix-objects.json
  - Source: src/web/api.rs
- Web users: <config_root>/web_users.json
- OAuth policy: <config_root>/web_oauth_policy.json
- Web runtime settings: <config_root>/web_runtime_settings.json
- Web user preferences: <config_root>/web_user_preferences.json

## 4) UI Association Points (Rules, Adversaries, STIX)

### Rule <-> STIX object association
Source: src/web/static/boot.js

- Rule Lab state and payload:
  - state.ruleLab.indicatesList
  - persistRuleLab() sends indicates_list to /api/rules/save
- Rule details and actions:
  - renderRuleLabIndicates()
  - rule-indicates action
  - /api/rules/{selector}/indicates

### STIX object CRUD and relation support
Sources: src/web/static/boot.js, src/web/api.rs

- STIX catalog route and table rendering
- /api/stix-objects (list/create)
- /api/stix-objects/{stix_id} (delete)
- /api/stix-objects/export/bundle

### Adversary <-> ability/rule outputs
Sources: src/web/static/boot.js, src/web/api.rs

- Adversary creation/update/export:
  - /api/adversaries
  - /api/adversaries/{selector}/update
  - /api/adversaries/{selector}/export
- Frontend planning/editor flows use ability_refs and platform compatibility derived from saved abilities/rules

## 5) Frontend Components Affected (Refactor + Fase 1)

- src/web/static/ui/toast.js
- src/web/static/app.css
- src/web/static/boot.js
- src/web/i18n.rs
- src/web/assets.rs (asset assertions / UI static tests)
- src/web/static/index.html (toast host node already present)

## 6) Baseline Test Strategy Before Refactor

1. Backend API tests for rule save:
- success path for POST /api/rules/save equivalent function call
- error path for confidence out of range

2. UI static tests (existing style in assets.rs):
- toast supports close button behavior contract in shipped JS
- toast style includes success/error variants and close affordance

3. Verification gates:
- cargo test
- cargo build

## 7) Refactor Guardrails

- Keep defensive-only semantics (no offensive execution behavior).
- Preserve existing CLI and web behavior unless change is explicit and documented.
- Keep file-based persistence as source of truth.
- Any endpoint/model mutation must update tests and docs in same iteration.
