#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the adjacent Linux package for this desktop user; no root access is used.
set -euo pipefail
package_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -e "$package_root/Packages" || -L "$package_root/Packages" ]]; then
    if [[ ! -d "$package_root/Packages/Core" || ! -d "$package_root/Packages/Suite" ]]; then
        echo 'The coordinated package is incomplete. Unpack the complete release before installing.' >&2
        exit 1
    fi
    exec "$package_root/Bin/hrc" install --native-packages "$package_root/Packages"
fi
exec "$package_root/Bin/hrc" install
