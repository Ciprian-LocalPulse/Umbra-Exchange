# Trusted setup ceremony — process and status

Every Groth16 proving/verifying key in this repo today (`umbra-relay-keygen`, the test suite's `groth16_round_trip_local_setup`) comes from a **local, single-party, non-ceremony setup**. Whoever ran that setup retains the "toxic waste" and could, in principle, forge proofs against the resulting verifying key. This document is the honest plan for replacing that with a real ceremony — and, just as importantly, an honest account of what's already safe to build ourselves versus what needs either adapted existing tooling or dedicated external cryptographic engineering. See `docs/THREAT_MODEL.md`'s "Trusted setup" entry for the current risk this leaves open.

## The two phases, and why they're split

Groth16's setup produces a circuit-specific proving/verifying keypair from a **toxic secret** that must never be reconstructible by anyone. A ceremony distributes that secret's generation across many participants, so the whole thing stays sound as long as *at least one* participant honestly destroyed their share — you don't need to trust any single participant, only that the group isn't 100% colluding.

The standard construction (Bowe–Gabizon–Miers, "BGM17"; this is what `zkLogin`, Zcash Sapling, Semaphore, Namada, and most production Groth16 deployments actually run) splits this into:

- **Phase 1 ("Powers of Tau")**: circuit-independent, produces a large, universal structured reference string. Expensive to run well (wants many participants, ideally hundreds, for real confidence), but *completely reusable across any circuit* — you don't need to run your own.
- **Phase 2**: circuit-specific, transforms the Phase 1 output into parameters for *this* circuit (`ProofOfObservationCircuit`). This has to be (re-)run whenever the circuit's shape changes.

## Phase 1: don't run our own — reuse an existing, widely-trusted one

Running a from-scratch Powers of Tau ceremony with enough participants to be meaningfully trustworthy is a significant undertaking on its own, and largely redundant: several long-running, well-documented, widely-reused BN254 Phase 1 transcripts already exist and are the de facto standard input for *any* new circuit's Phase 2, not just their original project's. The best-known is the **Perpetual Powers of Tau** ceremony (hundreds of participants, ongoing, BN254-compatible, publicly verifiable transcript) — used as the Phase 1 input by Tornado Cash, Semaphore, and many others cited during this doc's research. **Recommendation: use that (or another well-established public BN254 Phase 1 transcript) as this project's Phase 1 input, rather than running our own.** This needs a decision (which specific transcript/contribution index to pin) and someone to actually fetch and verify it, not new cryptography.

## Phase 2: the part that still needs real work

This is where `ProofOfObservationCircuit`-specific parameters get produced, and it's the part that's actually blocked right now. Researched directly before writing this doc (not assumed): every Rust Groth16 MPC implementation found — `celo-org/snark-setup`, `anoma/namada-trusted-setup`, the `phase2`/`phase21` crates — targets either **`bellman`** (a different SNARK library, not arkworks) or the **pre-rename Zexe-era arkworks API** (`algebra`/`r1cs-core`, before the 2021 rename to `ark-ff`/`ark-relations` that this entire workspace is built on). None install or link against this workspace's `ark-groth16 0.4` as-is.

Three honest paths forward, in order of how much new risk each introduces:

1. **Adapt an existing reference implementation** (most likely `celo-org/snark-setup`'s `phase2` crate, since it's the most arkworks-native of the ones found) to the current `ark-groth16 0.4` API. This is real, nontrivial engineering — the underlying BGM17 math doesn't change, but the API surface (`ConstraintSystem`, serialization traits, curve arithmetic types) all shifted in the arkworks rename. Whoever does this should cross-test the ported implementation against the original crate's own test vectors before trusting it for anything real, not just "port it and hope."
2. **Bridge to `snarkjs`** (JavaScript, circom-based, by far the most battle-tested Phase 2 ceremony tooling in the wider ecosystem — used in most production circom deployments) via something like `ark-circom`'s R1CS export, run the ceremony there, and import the resulting parameters back. Extra moving parts (a second toolchain, a format bridge to get right), but leans entirely on tooling with a long track record instead of freshly-adapted code.
3. **Commission this specifically for external cryptographic review.** Given the stakes — this is the one piece where a subtle mistake doesn't just cause a bug, it silently produces a system that *looks* secure and isn't — this is a reasonable place to draw the line on what a single unreviewed contributor (AI or human) should confidently ship without independent review, rather than rushing out freshly-written MPC contribution/verification code with no way to cross-check it against known-good test vectors.

**This document does not pick one of the three for you.** That's a real decision (time, budget, who's available to do the adaptation or the review) that belongs to whoever is driving this project, not something to default silently.

## What's safe to build ourselves right now, and is done as of this commit

Two tools that use only already-tested arkworks machinery — no new cryptographic protocol code, just serialization and hashing:

- **`fingerprint`** (`cargo run -p proof-of-observation --features test-support --bin fingerprint`): hashes `ProofOfObservationCircuit`'s actual R1CS matrices (not just variable counts — two different circuits could coincidentally share those) via SHA-512. Every ceremony participant should confirm they get the *same* fingerprint before contributing — this is what stops "half the participants contributed to one version of the circuit, half to a subtly different one" from going unnoticed. This exact pattern (`cs_hash` alongside a contribution transcript) is standard practice in every reference implementation found during research.
- **`verify-ceremony-params`** (`cargo run -p proof-of-observation --features test-support --bin verify-ceremony-params -- <pk-path> <vk-path>`): given *any* (proving key, verifying key) pair — from a real ceremony, from `umbra-relay-keygen`, from anywhere — checks it deserializes as well-formed (checked, not unchecked: real curve/subgroup validation, not just "the right number of bytes"), then actually builds a real proof against `ProofOfObservationCircuit` and verifies it round-trips. This catches a different, real class of mistake (wrong circuit, corrupted file, mismatched pk/vk pair, wrong curve) — it does NOT verify that a multi-party contribution protocol itself was executed honestly; that needs whichever Phase 2 tool's own transcript verification (see above).

Neither of these touches MPC contribution math. Both should still be run before trusting *any* ceremony's output, including a properly-run one — cheap insurance against a much more mundane class of mistake than a compromised ceremony.

## Fixed protocol parameters a real ceremony needs agreed first

Not blocking Phase 1 selection, but blocking Phase 2: the circuit's shape depends on the indicator-tree and credential-tree depths, which are currently a de facto convention (4-leaf / depth-2 trees, matching every tool and test in this workspace) rather than a value anyone has deliberately fixed as *the* production parameter. Whatever depth is chosen becomes baked into every proving/verifying key produced by the ceremony — changing it later means re-running Phase 2 entirely. Decide this deliberately (see `docs/PROTOCOL_SPEC.md`) before running a real ceremony, not by inertia from what the test suite happens to use.
