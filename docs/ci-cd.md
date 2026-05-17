# CI/CD and PR Governance

Last updated: 2026-05-16

## Goals

- block regressions before merge
- require traceable, reproducible release artifacts
- publish server images to GHCR on tagged releases

## Pull Request Quality Gates

The CI workflow enforces:

- formatting: `cargo fmt --check`
- lint for default members (`spuc-core` + `spuc-cli`): `cargo clippy --all-targets -- -D warnings`
- tests for default members (`spuc-core` + `spuc-cli`): `cargo test`
- documentation build for default members: `cargo doc --no-deps`
- packaging readiness: `cargo package -p spuc-core --allow-dirty`
- publish readiness: `cargo publish -p spuc-core --dry-run --allow-dirty`
- Docker smoke check (`/healthz`)
- JSON-RPC integration check (`tests/jsonrpc_cli.rs`)
- desktop Linux build and GUI tests with GTK/WebKit dependencies installed
- dependency vulnerability/policy review

## Required Branch Protection (GitHub Settings)

Configure branch protection for your main branch with:

- require a pull request before merging
- require approvals (recommended: at least 1)
- dismiss stale approvals on new commits
- require conversation resolution before merge
- require status checks to pass before merge
- restrict direct pushes to protected branches

Suggested required checks:

- `Rust Quality Gates`
- `Integration Tests (JSON-RPC)`
- `Desktop Linux Build and Tests`
- `Docker Smoke Test`
- `Security Audit`
- `dependency-review`

## Release Automation

The release workflow runs on tags `v*` and:

- builds release binaries across supported targets
- attaches build artifacts to GitHub Releases
- builds and pushes multi-arch container images to:
  - `ghcr.io/febrezo/spuc:<tag>`
  - `ghcr.io/febrezo/spuc:latest`
- emits provenance attestation for container artifacts

## Operational Notes

- keep pull requests focused and small when possible
- update docs and tests in the same PR as behavior changes
- avoid bypassing required checks except for emergency recoveries
