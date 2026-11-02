# Linux installation and upgrades

HRC packages contain the GUI, TUI, CLI and deterministic bot in one `Bin/hrc`
executable. HyperNet Core and Suite are separate prerequisites. Installing HRC
does not create a network, grant application access or start a service.

Release qualification is in progress. Development packages are not a supported
stable release. Check the package's release notes and qualification record before
using its stated platform or capacity limits.

## Requirements

The package target is native Linux x86_64 with GNU libc and OpenSSL 3. `Package.json`
records the binary's minimum GNU libc symbol version and linked shared libraries.
The GUI additionally needs a working Wayland or X11 session, EGL/OpenGL, XKB and
Fontconfig. Install fonts for the languages in use; missing terminal or GUI glyphs
do not change stored text. Sound is optional and off initially.

Use independently verified HyperNet binaries with the version-2 application
companion and `checkAuthority-v2`. Each service and caller needs its own current
application admission and approved stream configuration. See
[service setup](ConversationSetup.md) for identities, clock observations and
private directory permissions. There is no direct Internet fallback.

## Verify and unpack

Obtain the archive and its SHA-256 from the authenticated release channel. A digest
detects changed bytes; it does not independently establish who published them.
Verify the archive before extracting it into a new user-owned directory. Keep the
installation separate from every service directory, endpoint profile and guard.

```sh
sha256sum HRC-VERSION-linux-x86_64.tar.gz
mkdir -m 700 /private/hrc-install
tar --no-same-owner -xzf HRC-VERSION-linux-x86_64.tar.gz -C /private/hrc-install
/private/hrc-install/HRC-VERSION-linux-x86_64/Bin/hrc --version
/private/hrc-install/HRC-VERSION-linux-x86_64/Bin/hrc --help
```

Replace `VERSION` and the private path with the selected release and destination.
Run `gui --profile PROFILE`, `tui --profile PROFILE` or the documented CLI command
using that binary. Add its `Bin` directory to the user's chosen PATH if desired.
No privileged installer or automatic desktop/service registration is required.

`Documentation/DependencyNotices.txt` contains the dependency and font notices.
`Documentation/Dependencies.json`, `Cargo.lock` and the accompanying source archive
identify the build inputs. `Package.json` lists file digests and source provenance;
it is an inventory inside the archive, not a replacement for external verification.

## Upgrade

1. Read the target version's migration and HyperNet compatibility notes.
2. Close clients and stop bots and HRC services normally. Confirm that no process
   still owns the affected profile or service store.
3. Retain the old installation and a stopped, encrypted state backup according to
   the [operations guide](Operations.md). Do not move live state into a package.
4. Unpack the new version into a separate installation directory and verify it.
5. Start it against the existing state. Supported migrations use the same guarded
   transaction and durability boundary as ordinary operations. Unknown schemas,
   missing guards or corrupt state refuse startup; they never create a fresh store.
6. Check identity, retained history, pending outcomes and current permissions before
   enabling unattended bots. Reconnection resolves exact uncertain operations.

Do not run an older executable against a newer schema unless its release explicitly
supports that schema. Replacing a binary does not make an old database backup
current. A continuity refusal must be investigated, not bypassed by deleting guards
or recreating keys. Removing an installation directory leaves separately stored
profiles, service data and HyperNet configuration untouched.

## Build and package from source

Use a trusted checkout and the [build dependencies](../README.md). Build the pinned
SQLCipher source with `Tools/Native.sh`, then source `Tools/Environment.sh` before
every Cargo build or check. The package tool requires Python 3.11 or later and GNU
binutils in addition to the build tools.

```sh
bash Tools/Native.sh
source Tools/Environment.sh
CARGO_ENCODED_RUSTFLAGS="$(python3 Tools/Package.py --build-rustflags)"
export CARGO_ENCODED_RUSTFLAGS
cargo build --locked --release --bin hrc
cargo metadata --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu > /dev/null
python3 Tools/Package.py --binary target/release/hrc \
  --sqlcipher-source target/sqlcipher-source \
  --output /private/output/HRC-VERSION-linux-x86_64.tar.gz
```

When selecting a shared build directory or native source prefix, pass its actual
paths. The packager requires a clean committed checkout, refuses existing output,
checks the binary version/architecture, and collects the locked dependency notices
offline. It neither starts the binary's network workflows nor changes an installed
copy. It does not establish reproducibility by itself; retain the build and
qualification evidence for the exact package being distributed.

The encoded build flags retain existing `CARGO_ENCODED_RUSTFLAGS`, or `RUSTFLAGS`
when the encoded variable is absent, and append path remapping for the current
home, Cargo cache, checkout and explicit `CARGO_TARGET_DIR`. They support paths
containing spaces. Cargo's environment flags override flags from Cargo
configuration; put any required
configuration flags in the selected environment variable before this command.
Capture the flags as shown, without printing them in build logs.

Before executing the binary or creating an archive, the packager refuses any
remaining occurrence of these known build paths. Build and package in the same
environment. This is a check for the current build locations, not proof that an
arbitrary binary built elsewhere contains no private information. Native compiler
output or embedded application data can require separate remapping; inspect a
refusal and rebuild rather than removing the check.
