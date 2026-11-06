#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the adjacent Linux package for this desktop user; no root access is used.
set -euo pipefail
package_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec "$package_root/Bin/hrc" install
