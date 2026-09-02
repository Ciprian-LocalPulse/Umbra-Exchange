## What this changes


## Why


## Checklist
- [ ] No security property is weakened silently to make tests/CI pass — if a shortcut was necessary, it's documented loudly in `docs/THREAT_MODEL.md`, not buried
- [ ] Cryptographic claims are backed by a cited source (arkworks docs, a paper, etc.) where the claim isn't obvious
- [ ] Significant design changes were discussed in an issue first, or this PR is small enough not to need that
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` pass locally (see `circuits/`)
- [ ] `cargo test --workspace` passes locally

## Related issue(s)
<!-- Closes #... -->