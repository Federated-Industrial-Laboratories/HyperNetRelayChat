// SPDX-License-Identifier: Apache-2.0
fn main() {
    println!("cargo:rerun-if-env-changed=SQLCIPHER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=SQLCIPHER_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=SQLCIPHER_STATIC");
    if std::env::var_os("SQLCIPHER_LIB_DIR").is_none() {
        panic!("HRC requires controlled SQLCipher: source Tools/Environment.sh before building");
    }
    for library in ["crypto", "m", "z"] {
        println!("cargo:rustc-link-lib={library}");
    }
}
