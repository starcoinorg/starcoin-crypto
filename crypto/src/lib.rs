// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! A library supplying various cryptographic primitives
//! that can be backed by either `diem-crypto` (compiler-v1) or
//! `aptos-crypto` (compiler-v2).

#[cfg(all(feature = "compiler-v1", feature = "compiler-v2"))]
compile_error!("`compiler-v1` and `compiler-v2` cannot be enabled at the same time.");
#[cfg(not(any(feature = "compiler-v1", feature = "compiler-v2")))]
compile_error!("Either `compiler-v1` or `compiler-v2` feature must be enabled.");

#[cfg(feature = "compiler-v2")]
#[doc(hidden)]
pub use aptos_crypto as crypto_backend;
#[cfg(all(feature = "compiler-v1", not(feature = "compiler-v2")))]
#[doc(hidden)]
pub use diem_crypto as crypto_backend;
#[cfg(feature = "compiler-v2")]
pub(crate) use rand as backend_rand;
#[cfg(all(feature = "compiler-v1", not(feature = "compiler-v2")))]
pub(crate) use rand08 as backend_rand;

#[cfg(feature = "compiler-v2")]
#[doc(hidden)]
pub use aptos_crypto_derive as crypto_backend_derive;
#[cfg(all(feature = "compiler-v1", not(feature = "compiler-v2")))]
#[doc(hidden)]
pub use diem_crypto_derive as crypto_backend_derive;

pub mod ed25519 {
    pub use crate::crypto_backend::ed25519::*;
    use crate::keygen::KeyGen;
    use crate::Genesis;

    pub fn random_public_key() -> Ed25519PublicKey {
        KeyGen::from_os_rng().generate_keypair().1
    }

    /// A static key pair
    pub fn genesis_key_pair() -> (Ed25519PrivateKey, Ed25519PublicKey) {
        let private_key = Ed25519PrivateKey::genesis();
        let public_key = <Ed25519PrivateKey as crate::PrivateKey>::public_key(&private_key);
        (private_key, public_key)
    }
}

pub mod hash;
pub mod keygen;
pub mod multi_ed25519;

pub mod test_utils {
    pub use crate::crypto_backend::test_utils::*;

    #[cfg(all(feature = "compiler-v2", any(test, feature = "fuzzing")))]
    pub type TestDiemCrypto = TestAptosCrypto;
    #[cfg(all(
        feature = "compiler-v1",
        not(feature = "compiler-v2"),
        any(test, feature = "fuzzing")
    ))]
    pub type TestAptosCrypto = TestDiemCrypto;
    #[cfg(all(any(test, feature = "fuzzing"), feature = "compiler-v2"))]
    pub type TestCrypto = TestAptosCrypto;
    #[cfg(all(
        any(test, feature = "fuzzing"),
        feature = "compiler-v1",
        not(feature = "compiler-v2")
    ))]
    pub type TestCrypto = TestDiemCrypto;
}

pub mod traits {
    pub use crate::crypto_backend::traits::*;
}

#[cfg(feature = "compiler-v2")]
pub mod bls12381 {
    pub use crate::crypto_backend::bls12381::*;
}

#[cfg(feature = "compiler-v2")]
pub mod bulletproofs {
    pub use crate::crypto_backend::bulletproofs::*;
}

pub use crate::hash::HashValue;
pub use crate::traits::*;

// Reexport once_cell for use in CryptoHasher Derive implementation
#[doc(hidden)]
pub use once_cell as _once_cell;
#[doc(hidden)]
pub use serde_name as _serde_name;

pub mod derive {
    pub use crate::crypto_backend_derive::{
        CryptoHasher, DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
    };
}
