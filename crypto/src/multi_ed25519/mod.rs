// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::backend_rand::SeedableRng;
pub use crate::crypto_backend::multi_ed25519::*;
use crate::multi_ed25519::multi_shard::MultiEd25519KeyShard;
use crate::test_utils::TEST_SEED;

pub mod multi_shard;

/// A static multi key pair for test
pub fn genesis_multi_key_pair() -> (MultiEd25519KeyShard, MultiEd25519PublicKey) {
    let mut rng = crate::backend_rand::rngs::StdRng::from_seed(TEST_SEED);
    let mut shards = MultiEd25519KeyShard::generate(&mut rng, 2, 1)
        .expect("Generate MultiEd25519KeyShard should success");
    //only take last one.
    let shard = shards.pop().expect("shards must not empty.");
    let public_key = shard.public_key();
    (shard, public_key)
}

#[cfg(test)]
mod tests;
