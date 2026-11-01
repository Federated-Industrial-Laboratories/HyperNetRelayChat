#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the pinned SQLCipher engine into a private, reusable local prefix.
set -euo pipefail
hrc_root=$(cd "$(dirname "$0")/.." && pwd)
hrc_prefix=${HRC_NATIVE_PREFIX:-"$hrc_root/target/native"}
hrc_source=${HRC_NATIVE_SOURCE:-"$hrc_root/target/sqlcipher-source"}
hrc_commit=355d4db92d3404e71faa8088d071a71d767807f4
if [[ $hrc_prefix != /* || $hrc_source != /* ]]; then
    echo 'Native source and installation paths must be absolute.' >&2
    exit 1
fi
if [[ -x "$hrc_prefix/bin/sqlite3" && -f "$hrc_prefix/lib/libsqlcipher.a" ]]; then
    hrc_version=$("$hrc_prefix/bin/sqlite3" :memory: 'PRAGMA cipher_version; SELECT sqlite_version();')
    if [[ $hrc_version == $'4.20.0 community\n3.54.1' ]]; then
        exit 0
    fi
    echo 'Existing native prefix has a different SQLCipher version.' >&2
    exit 1
fi
if [[ ! -d "$hrc_source/.git" ]]; then
    mkdir -p "$hrc_source"
    git init -q "$hrc_source"
    git -C "$hrc_source" remote add origin https://github.com/sqlcipher/sqlcipher.git
    git -C "$hrc_source" fetch --depth 1 origin "$hrc_commit"
    git -C "$hrc_source" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$hrc_source" rev-parse HEAD) == "$hrc_commit" ]]
[[ -z $(git -C "$hrc_source" status --porcelain --untracked-files=no) ]]
mkdir -p "$hrc_prefix"
cd "$hrc_source"
./configure --prefix="$hrc_prefix" --disable-shared --enable-static --enable-fts5 \
    --with-tempstore=always \
    CFLAGS='-O2 -DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown -DSQLITE_TEMP_STORE=3' \
    LDFLAGS='-lcrypto'
make -j4
make install
ln -s libsqlite3.a "$hrc_prefix/lib/libsqlcipher.a"
hrc_version=$("$hrc_prefix/bin/sqlite3" :memory: 'PRAGMA cipher_version; SELECT sqlite_version();')
[[ $hrc_version == $'4.20.0 community\n3.54.1' ]]
