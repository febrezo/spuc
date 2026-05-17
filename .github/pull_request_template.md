## Summary

- Describe what changed and why.

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Docker smoke check (`docker build` + `/healthz`)

## Risk and Rollback

- Risk level: low / medium / high
- Rollback plan:

## Release Notes

- [ ] User-facing docs updated
- [ ] API/docs updated (if behavior changed)
- [ ] No breaking change
- [ ] Breaking change documented
