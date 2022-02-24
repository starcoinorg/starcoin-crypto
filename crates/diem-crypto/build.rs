#[cfg(feature = "avx512f")]
fn main() {
    use bindgen::Builder;
    use cc::Build;
    use std::env;
    use std::path::PathBuf;

    let mut config = Build::new();
    config
        .include("ext/")
        .file("ext/KeccakHash.c")
        .file("ext/KeccakP-1600-AVX512.c")
        .file("ext/KeccakSponge.c");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    if target_env == "msvc" {
        config.flag("/arch:AVX512");
    } else {
        config.flag("-mavx512f");
        config.flag("-mavx512vl");
        config.flag("-O3");
    }

    config.compile("avx512_sha3");

    println!("cargo:rustc-link-lib=avx512_sha3");
    println!("cargo:rerun-if-changed=KeccakHash.h");

    let bindings = Builder::default()
        .header("ext/KeccakHash.h")
        .allowlist_function("Keccak_HashInitialize")
        .allowlist_function("Keccak_HashUpdate")
        .allowlist_function("Keccak_HashFinal")
        .allowlist_function("Keccak_HashSqueeze")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
#[cfg(not(feature = "avx512f"))]
fn main() {}
