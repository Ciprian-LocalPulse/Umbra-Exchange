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

# proof-of-observation: Merkle-inclusion + nullifier constraints
# implemented and tested, including a real Groth16 round trip
cargo test -p proof-of-observation

# whole workspace
cargo test --workspace
```

## Poseidon parameter source

`proof-of-observation` needs Poseidon round constants and an MDS matrix for the BN254 scalar field. Rather than generate these ourselves, `poseidon_params.rs` pulls them from the [`light-poseidon`](https://crates.io/crates/light-poseidon) crate (maintained by Light Protocol), which ships the standard circomlib/iden3 "bn254_x5" constants — generated via the official reference script from the Poseidon paper. `light-poseidon` stores round constants as a flat vector; we reshape that into the `ark[round][state_index]` layout `ark-crypto-primitives`'s sponge/CRH gadgets expect. See the doc comment at the top of that file for the exact reasoning and caveats.
