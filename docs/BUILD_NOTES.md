# Build notes

Practical notes for anyone building this locally, so the next person doesn't rediscover the same issues.

## Toolchain

Built and tested against `rustc`/`cargo` 1.75.0. Should work on newer stable too, but 1.75 is the floor that's actually been verified.

## Pinned transitive dependencies

`circuits/Cargo.toml` pins a few transitive dependencies that would otherwise resolve to versions requiring a newer Cargo than 1.75 (specifically, versions that require the `edition2024` feature, which isn't stabilized pre-1.80-ish):

- `zeroize = "=1.7.0"` (newer releases pull in an `edition2024`-requiring `zeroize_derive`)
- `zeroize_derive = "=1.4.3"`
- `rayon-core = "=1.12.1"` (1.13.0 requires rustc 1.80+)
- `rayon = "=1.10.0"`

If you're building on a newer Rust toolchain and want the latest versions of these, it should be safe to relax or remove these pins — they exist for compatibility with older toolchains, not because of any functional requirement.

## Commands that are known to work

```bash
# reputation-accumulator: fully implemented, real tests
cd circuits
cargo test -p reputation-accumulator

# proof-of-observation: compiles (input allocation only — constraints are
# still TODO, see src/lib.rs)
cargo build -p proof-of-observation

# whole workspace
cargo test --workspace
```
