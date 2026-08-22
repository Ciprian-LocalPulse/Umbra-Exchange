//! Wire encoding for the relay's JSON API.
//!
//! Field elements (`Fr`) and Groth16 artifacts (`Proof<Bn254>`,
//! `VerifyingKey<Bn254>`) all implement `ark-serialize`'s
//! `CanonicalSerialize`/`CanonicalDeserialize` traits, which give a
//! well-defined, canonical byte encoding. This module just wraps that in
//! hex so it round-trips cleanly through JSON, which has no native binary
//! type.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt;

#[derive(Debug)]
pub struct EncodingError(pub &'static str);

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encoding error: {}", self.0)
    }
}

impl std::error::Error for EncodingError {}

pub fn fr_to_hex(value: &Fr) -> String {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("Fr serialization is infallible for a well-formed field element");
    hex::encode(bytes)
}

pub fn fr_from_hex(s: &str) -> Result<Fr, EncodingError> {
    let bytes = hex::decode(s.trim()).map_err(|_| EncodingError("field element is not valid hex"))?;
    Fr::deserialize_compressed(&bytes[..]).map_err(|_| EncodingError("bytes are not a valid BN254 field element"))
}

pub fn proof_to_hex(proof: &Proof<Bn254>) -> String {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .expect("Proof serialization is infallible for a well-formed proof");
    hex::encode(bytes)
}

pub fn proof_from_hex(s: &str) -> Result<Proof<Bn254>, EncodingError> {
    let bytes = hex::decode(s.trim()).map_err(|_| EncodingError("proof is not valid hex"))?;
    Proof::deserialize_compressed(&bytes[..]).map_err(|_| EncodingError("bytes are not a valid Groth16 proof"))
}

pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .expect("VerifyingKey serialization is infallible for a well-formed key");
    bytes
}

pub fn vk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, EncodingError> {
    VerifyingKey::deserialize_compressed(bytes).map_err(|_| EncodingError("bytes are not a valid Groth16 verifying key"))
}
