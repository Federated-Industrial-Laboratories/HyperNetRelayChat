// SPDX-License-Identifier: Apache-2.0
fn main() {
    println!("cargo:rerun-if-env-changed=SQLCIPHER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SQLCIPHER_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=SQLCIPHER_STATIC");
    println!("cargo:rerun-if-env-changed=HRC_CRYPTO_LIB_DIR");
    if std::env::var_os("SQLCIPHER_LIB_DIR").is_none() {
        panic!("HRC requires controlled SQLCipher: source Tools/Environment.sh before building");
    }
    let crypto = std::path::PathBuf::from(
        std::env::var_os("HRC_CRYPTO_LIB_DIR")
            .expect("source Tools/Environment.sh to select static OpenSSL 3"),
    );
    let archive = crypto.join("libcrypto.a");
    assert!(
        crypto.is_absolute() && archive.is_file(),
        "the selected OpenSSL static archive is unavailable"
    );
    println!("cargo:rerun-if-changed={}", archive.display());
    println!("cargo:rustc-link-search=native={}", crypto.display());
    println!("cargo:rustc-link-lib=static=crypto");
    for library in ["m", "z", "dl", "pthread"] {
        println!("cargo:rustc-link-lib={library}");
    }
}
