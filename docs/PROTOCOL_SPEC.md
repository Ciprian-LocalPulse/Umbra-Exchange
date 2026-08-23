# Protocol Specification (draft v0.1)

This is a working draft. Anything here can and will change as the circuits get audited and the credential scheme gets nailed down.

## 1. Data model

**Indicator (IOC):** a normalized string — hash, IP, domain, URL, etc. — canonicalized before hashing so `HTTP://Example.com/` and `http://example.com` commit to the same leaf.

**Epoch:** a fixed time window (default: 24h). Contributors commit one Merkle root per epoch. Epochs bound the size of what needs to be proven and give the relay a natural aggregation boundary.

**Leaf:** `Poseidon(indicator_normalized || epoch_id || contributor_salt)`

**Root:** standard binary Merkle tree over that epoch's leaves.

## 2. Credentials

Each contributor holds a secret backing an anonymous credential. Tiering (0–3) reflects vetting level — e.g. tier 0 = self-registered / unvetted, tier 3 = verified CERT/ISAC member. Credential issuance is out of scope for the cryptographic protocol itself (it's a governance question — see open issue below).

**Implementation note (as of the credential-tier gadget landing in `proof-of-observation`):** the *proof* that a contributor holds a given tier is Merkle-tree membership, not a signature. An issuer publishes a Merkle tree whose leaves are `Poseidon(credential_secret, credential_tier, DOMAIN_TAG)`; a contributor proves membership of their own leaf plus `credential_tier >= min_tier`, without revealing which leaf. This is a deliberate simplification from this doc's original sketch of "Groth16 proof of knowledge of a signature under the issuer's key" (EdDSA-in-circuit): membership proofs reuse the exact same Merkle-path gadget the indicator tree already needed, at a fraction of the constraint cost of an in-circuit signature scheme. The trade-off is on the issuer's side, not the prover's: adding or revoking one credential means republishing the whole tree (a new `credential_root`), whereas a signature scheme lets an issuer mint credentials one at a time without coordinating a shared tree. For Phase 1's expected issuer cadence (occasional batch vetting, not high-frequency onboarding) this trade-off favors the simpler, cheaper gadget — revisit if that assumption stops holding.

A relay or other verifier's trust in a given `credential_root` is a policy decision, not something the circuit can establish — see `relay`'s `trusted_credential_roots` and `docs/THREAT_MODEL.md`.

**Open design question:** who issues tier-3 credentials, and what stops that issuer from becoming the new single point of trust? Current thinking: multiple independent issuers (CERTs, ISACs), each publishing their own `credential_root`, all accepted by relays that choose to trust them — so no single issuer is a chokepoint — but this needs input before Phase 1 locks it in.

## 3. Proof statement (proof-of-observation)

For a chosen (indicator, epoch) pair, the contributor proves, in zero knowledge:

> "I know a Merkle path from leaf `Poseidon(indicator || epoch || salt)` to a root R that I previously published, AND I know a Merkle path from a credential leaf `Poseidon(credential_secret || credential_tier || DOMAIN_TAG)` to a credential root that some issuer published, where `credential_tier >= N`, AND this is the first time I've disclosed this (indicator, epoch) pair (nullifier check)."

Public inputs: `indicator_hash`, `epoch`, `R`, `nullifier`, `N` (claimed minimum tier), `credential_root`.
Private inputs: indicator Merkle path + `salt`, credential secret, actual `credential_tier`, credential Merkle path.

## 4. Nullifiers

To stop a contributor from replaying the same observation across epochs to inflate a score, or claiming credit twice for one observation: `nullifier = Poseidon(credential_secret || indicator || epoch)`. The relay rejects a proof whose nullifier it has already seen for that (indicator, epoch) pair.

## 5. Aggregation

For indicator X in epoch E, the relay's confidence score is a weighted count of valid, distinct-nullifier proofs received, weighted by claimed tier:

```
confidence(X, E) = Σ tier_weight(N_i)   for each valid proof i on (X, E)
```

Where `tier_weight` is a policy parameter (e.g. tier 0 = 1, tier 3 = 8) — deliberately not hardcoded, since different consumer communities will want different weighting.

## 6. STIX/MISP export

Indicators crossing a configurable confidence threshold get exported as STIX 2.1 `indicator` objects, with `confidence` mapped from the aggregate score and a custom property `x_umbra_proof_count` for transparency about how the score was derived. See `schema/stix_mapping.md`.

## Explicit non-goals (for now)

- This protocol does not attribute an indicator to a threat actor or campaign — it only aggregates "was this observed, by how many trusted parties." Attribution is a downstream, human/analyst task.
- This is not a malware sample sharing system — it's indicator-only. Sample sharing has a different, much harder privacy profile (the sample itself may contain sensitive victim data).
