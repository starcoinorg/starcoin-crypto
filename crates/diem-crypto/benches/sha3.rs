#![feature(test)]

extern crate test;

use test::Bencher;

use crate::avx512_sha3;

/*
#[bench]
fn simd_sha3_256_input_1000_bytes(b: &mut Bencher) {
    let data = vec![254u8; 1000];
    b.bytes = data.len() as u64;

    b.iter(|| {

        let res = avx512_sha3(data.as_slice(), data.len());
    });
}

*/
