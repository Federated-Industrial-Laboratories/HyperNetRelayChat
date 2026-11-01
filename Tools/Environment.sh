# SPDX-License-Identifier: Apache-2.0
# Source this file to select HRC's controlled native SQLCipher dependency.
hrc_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export HRC_NATIVE_PREFIX=${HRC_NATIVE_PREFIX:-"$hrc_root/target/native"}
export SQLCIPHER_LIB_DIR="$HRC_NATIVE_PREFIX/lib"
export SQLCIPHER_INCLUDE_DIR="$HRC_NATIVE_PREFIX/include"
export SQLCIPHER_STATIC=1
export CARGO_INCREMENTAL=0
if [[ ! -f "$SQLCIPHER_LIB_DIR/libsqlcipher.a" ]]; then
    echo 'Build the controlled SQLCipher dependency with bash Tools/Native.sh first.' >&2
    return 1
fi
