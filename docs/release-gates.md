# Release safety gates

A tag-driven `Release Binaries` execution now waits for two jobs before **building** any release artifacts:

1. `validate-release-ref` requires a Git tag equal to `v` plus the root `Cargo.toml` version. Manual workflow dispatch from a branch fails closed.
2. `ci-gate` invokes the complete `.github/workflows/ci.yml` as a reusable workflow **on the tagged commit**, including Rust formatting, Clippy, documentation, tests, cargo package dry-run, desktop Linux, Docker smoke, `cargo audit` and browser E2E.

Both publishing jobs explicitly depend on the release build and both gates. A failed or cancelled CI blocks release assets and GHCR publishing; no bypass via `continue-on-error` is permitted.

## Browser E2E

`tests/browser/compose.yaml` builds a container using a Rust CLI builder and a pinned Playwright Chromium runtime. No Selenium, drivers or browsers are installed on the host. The QA container uses no network interface (`network_mode: none`), publishes no ports, and uses synthetic data under an ephemeral `/tmp`. It verifies navigation and the create/edit/delete UI flow with API and on-disk persistence checks.

To run locally from the repository root (requires Docker Compose):

```sh
clear
docker compose -f tests/browser/compose.yaml build qa
docker compose -f tests/browser/compose.yaml run --rm --no-deps qa
docker compose -f tests/browser/compose.yaml down --rmi local --remove-orphans
```

## Limitations and operator controls

- GitHub Actions cannot be fully emulated locally; validate workflow syntax and run the browser container before committing, then require the actual **remote** CI execution to pass before tagging.
- Configure GitHub branch protections, tag rulesets, environments and required status checks separately in repository settings. Workflows do **not** stop someone with administrative rights from changing/removing controls or tagging historical commits.
- The test uses synthetic rules and does not qualify migration of real legacy catalogs; that remains an explicit pre-release validation task.
- The browser E2E proves functional navigation/CRUD only, not accessibility, layout quality, performance, nor cross-browser compatibility.
- Update action and image digests under controlled dependency review. A failing security audit is a release blocker and should not be skipped to publish.
