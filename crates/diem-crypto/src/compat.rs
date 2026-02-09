// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Wrapper structs for types that need [RustCrypto](https://github.com/RustCrypto)
//! traits implemented.

use digest::{
    consts::{U136, U32},
    core_api::BlockSizeUser,
    Digest, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
};
use tiny_keccak::{Hasher, Sha3};

/// A wrapper for [`tiny_keccak::Sha3::v256`] that
/// implements RustCrypto [`digest`] traits [`BlockInput`], [`Update`], [`Reset`],
/// and [`FixedOutput`]. Consequently, this wrapper can be used in RustCrypto
/// APIs that require a hash function (usually something that impls [`Digest`]).
#[derive(Clone)]
pub struct Sha3_256(Sha3);

// ensure that we impl all of the sub-traits required for the Digest trait alias
static_assertions::assert_impl_all!(Sha3_256: Digest);

impl Default for Sha3_256 {
    #[inline]
    fn default() -> Self {
        Self(Sha3::v256())
    }
}

impl BlockSizeUser for Sha3_256 {
    type BlockSize = U136;
}

impl OutputSizeUser for Sha3_256 {
    type OutputSize = U32;
}

impl HashMarker for Sha3_256 {}

impl Update for Sha3_256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Reset for Sha3_256 {
    #[inline]
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl FixedOutput for Sha3_256 {
    #[inline]
    fn finalize_into(self, out: &mut Output<Self>) {
        self.0.finalize(out.as_mut());
    }
}

impl FixedOutputReset for Sha3_256 {
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.clone(), out);
        Reset::reset(self)
    }
}
