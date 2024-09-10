// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use aptos_crypto::{
    bls12381,
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
    PrivateKey, Uniform,
};
use rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};

/// Ed25519 key generator.
#[derive(Debug)]
pub struct KeyGen(StdRng);


impl KeyGen {
    /// Constructs a key generator with a specific seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(StdRng::from_seed(seed))
    }

    /// Constructs a key generator with a random seed.
    /// The random seed itself is generated using the OS rng.
    pub fn from_os_rng() -> Self {
        let mut seed_rng = OsRng;
        let seed: [u8; 32] = seed_rng.gen();
        Self::from_seed(seed)
    }

    pub fn generate_ed25519_private_key(&mut self) -> Ed25519PrivateKey {
        Ed25519PrivateKey::generate(&mut self.0)
    }

    /// Generate an Ed25519 key pair.
    pub fn generate_keypair(&mut self) -> (Ed25519PrivateKey, Ed25519PublicKey) {
        let private_key = self.generate_ed25519_private_key();
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    /// Generate a bls12381 private key.
    pub fn generate_bls12381_private_key(&mut self) -> bls12381::PrivateKey {
        bls12381::PrivateKey::generate(&mut self.0)
    }

    /// Generate an Ed25519 key pair.
    pub fn generate_ed25519_keypair(&mut self) -> (Ed25519PrivateKey, Ed25519PublicKey) {
        let private_key = self.generate_ed25519_private_key();
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

}
