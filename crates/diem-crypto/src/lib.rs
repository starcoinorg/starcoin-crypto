// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(feature = "avx512f", allow(unsafe_code), allow(missing_docs))]
//! This feature gets turned on only if diem-crypto is compiled via MIRAI in a nightly build.
#![cfg_attr(mirai, allow(incomplete_features), feature(const_generics))]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]

//! A library supplying various cryptographic primitives
pub mod compat;
pub mod ed25519;
pub mod error;
pub mod hash;
pub mod hkdf;
pub mod multi_ed25519;
pub mod noise;
pub mod test_utils;
pub mod traits;
pub mod validatable;
pub mod x25519;

#[cfg(test)]
mod unit_tests;

#[cfg(mirai)]
mod tags;

pub use self::traits::*;
pub use hash::HashValue;

// Reexport once_cell and serde_name for use in CryptoHasher Derive implementation.
#[doc(hidden)]
pub use once_cell as _once_cell;
#[doc(hidden)]
pub use serde_name as _serde_name;

#[cfg(feature = "avx512f")]
use std::mem::MaybeUninit;
#[cfg(feature = "avx512f")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// We use [formally verified arithmetic](https://crates.io/crates/fiat-crypto)
// in maintained forks of the dalek suite of libraries ({curve, ed,
// x}25519-dalek). This is controlled by a feature in the forked crates
// ('fiat_u64_backend'), which we turn on by default.
#[cfg(not(any(feature = "fiat", feature = "u64", feature = "u32")))]
compile_error!(
    "no dalek arithmetic backend cargo feature enabled! \
     please enable one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u64"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "u64", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

// MIRAI's tag analysis makes use of the incomplete const_generics feature, so the module
// containing the definitions of MIRAI tag types should not get compiled in a release build.
// The code below fails a build of the crate if mirai is on but debug_assertions is not.
#[cfg(all(mirai, not(debug_assertions)))]
compile_error!("MIRAI can only be used to compile the crate in a debug build!");

#[cfg(feature = "avx512f")]
#[derive(Clone)]
pub struct Avx512Sha3(Keccak_HashInstance);

#[cfg(feature = "avx512f")]
impl Avx512Sha3 {
    pub fn new() -> Self {
        let mut inner = MaybeUninit::uninit();
        let inner = unsafe {
            let ret = Keccak_HashInitialize(inner.as_mut_ptr(), 1088, 512, 256, 0x06);
            debug_assert_eq!(0, ret);
            inner.assume_init()
        };
        Self(inner)
    }

    pub fn update(&mut self, input: &[u8]) {
        unsafe {
            let ret = Keccak_HashUpdate(&mut self.0, input.as_ptr(), (input.len() * 8) as u64);
            debug_assert_eq!(0, ret);
        }
    }

    pub fn finalize(&mut self) -> HashValue {
        let mut bytes = [0u8; HashValue::LENGTH];
        unsafe {
            let ret = Keccak_HashFinal(&mut self.0, bytes.as_mut_ptr());
            debug_assert_eq!(0, ret);
        }
        HashValue::new(bytes)
    }
}

#[test]
#[cfg(feature = "avx512f")]
fn hello_sha3_256() {
    let input = b"hello";
    let mut hash = Avx512Sha3::new();
    hash.update(input);
    let output = hash.finalize();
    let expected = b"\
        \x33\x38\xbe\x69\x4f\x50\xc5\xf3\x38\x81\x49\x86\xcd\xf0\x68\x64\
        \x53\xa8\x88\xb8\x4f\x42\x4d\x79\x2a\xf4\xb9\x20\x23\x98\xf3\x92\
    ";
    assert_eq!(expected, output.as_ref());
}
