# Linux installation and upgrades

HRC packages contain the GUI, TUI, CLI and deterministic bot in one `Bin/hrc`
executable. HyperNet Core and Suite are separate prerequisites. Installing HRC
does not create a network, grant application access or start a service.

HRC 0.2.0 adds desktop setup and operations. The earlier
[bounded Linux pilot](IntegrationProfile.md#8-linux-pilot-qualification) retains
its original measured versions. Use its topology and workload limits when planning deployment.

## Requirements

The package target is native Linux x86_64 with GNU libc and OpenSSL 3. `Package.json`
records the binary's minimum GNU libc symbol version and linked shared libraries.
The GUI additionally needs a working Wayland or X11 session, EGL/OpenGL, XKB and
Fontconfig. Install fonts for the languages in use; missing terminal or GUI glyphs
do not change stored text. Sound is optional and off initially.

Native network qualification uses Ubuntu 26.04 (resolute), kernel
`7.0.0-42-generic`, amd64 and GNU libc 2.43. Packaged CLI and offline GUI/TUI checks
use Ubuntu 24.04 with GNU libc 2.39; the current binary requires GNU libc 2.39 or
later. Those offline checks do not establish full native-load qualification on
Ubuntu 24.04. Other platforms are not qualified.

The supported hosting pair is Core 0.10.4 and Suite 0.10.3. Use independently
verified binaries matching the [contract map](HyperNetContract.md), with the version-2 application
companion and `checkAuthority-v2`. Each service and caller needs its own current
application admission and approved stream configuration. See
[service setup](ConversationSetup.md) for identities, clock observations and
private directory permissions. There is no direct Internet fallback.

## Verify and unpack

Obtain the selected binary archive, source archive, `SHA256SUMS`, its
`SHA256SUMS.sig` OpenSSH signature, and `PublisherKey.txt` from the
[v0.2.2 release](https://github.com/Federated-Industrial-Laboratories/HyperNetRelayChat/releases/tag/v0.2.2).
Source and release packages are public. No repository account is required
to download them.
Verify the publisher key against this independently pinned SHA-256 fingerprint:

`SHA256:XaKyGFow6q4DkZee5rQLUXN66AxQogVEtWb1sQS6m24`

The checksum signature uses principal `HyperNetPublisher` and namespace
`HyperNetRelayChatRelease1`. A downloaded key alone does not establish publisher
identity. Confirm its fingerprint before creating the allowed-signers file, then
verify the signature before checking every listed digest. Stop on any failure.

```sh
(
set -eu
test "$(ssh-keygen -lf PublisherKey.txt -E sha256 | awk '{print $2}')" = \
  'SHA256:XaKyGFow6q4DkZee5rQLUXN66AxQogVEtWb1sQS6m24'
awk '{ print "HyperNetPublisher " $0 }' PublisherKey.txt > HRC.allowed_signers
ssh-keygen -Y verify -f HRC.allowed_signers -I HyperNetPublisher \
  -n HyperNetRelayChatRelease1 -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check SHA256SUMS
mkdir -m 700 /private/hrc-install
tar --no-same-owner -xzf HRC-VERSION-linux-x86_64.tar.gz -C /private/hrc-install
/private/hrc-install/HRC-VERSION-linux-x86_64/Bin/hrc --version
/private/hrc-install/HRC-VERSION-linux-x86_64/Bin/hrc --help
)
```

Keep the installation separate from service directories, endpoint profiles and guards.
Replace `VERSION` and the private path with the selected release and destination.
Run `gui --profile PROFILE`, `tui --profile PROFILE` or the documented CLI command
using that binary. Add its `Bin` directory to the user's chosen PATH if desired.
No privileged installer or automatic desktop/service registration is required.

## Desktop setup

The desktop update adds `hrc install`, or `Tools/Install.sh` in a package, to
install the current executable and an application-menu launcher for this user.
The setup window also has an **Install launcher** button. No root access is used.
Open **HyperNet Relay Chat** from the application menu. The launcher remembers
the last profile; its **Profiles and setup** and **Open offline** actions remain
available. Reopening HRC activates its existing window.

The **Operations** button is available in the setup window and the conversation
toolbar. It opens network hosting, HRC service, local model, bot and external
assistant controls while keeping an existing chat session open. See
[desktop hosting](DesktopHosting.md) and [desktop model and bot controls](DesktopBots.md).

**Operations > Native packages** imports the supported Core or Suite release.
Choose the folder containing its `.tar`, `.tar.sig`, `.target.json`,
`.target.json.sig` and `Publisher.pub` files. Review the verified package, then
select **Install package**. Installation retains the publisher key and update
trust, uses a private per-user destination and fills the corresponding network
setup field. Existing installations are verified before reuse. Distribution
packages, kernel support and clock policy remain explicit host prerequisites.

The setup wizard can open an existing profile or guide a new endpoint through
network admission, invitation import, registration export and activation.
HRC 0.2.2 also supports an optional [private invitation](SelfServiceInvitations.md)
that completes admission and registration without a live operator exchange.
The host must explicitly enable that mode; manual approval remains available.
Core, Suite, user systemd and an authenticated local chrony source are prerequisites.
For manual approval, the operator supplies the bootstrap and an independently confirmed fingerprint,
then an HRC setup bundle and its separately confirmed SHA-256. `hrc setup-bundle
--help` lists the operator inputs. Keys stay local. In that workflow, the operator approves
network access and enrols the signed HRC registration before online chat is available.

`OnboardingRuntime.json` records only explicitly selected local tools, paths and
clock identity. A configured private chrony observer uses `-U -x` and cannot adjust
the system clock. HRC can restart its configured user services; it does not install
system packages, alter AppArmor or renew consent automatically. New-network
creation requires an explicit review in **Operations > HyperNets**.
Use **Profile > Switch or set up** to return to setup after saving the draft.
These desktop controls require HRC 0.2.0 or later.

`Documentation/DependencyNotices.txt` contains the dependency and font notices.
`Documentation/Dependencies.json`, `Cargo.lock` and the accompanying source archive
identify the build inputs. `Package.json` lists file digests and source provenance;
it is an inventory inside the archive, not a replacement for external verification.

## Upgrade

The checked development upgrade starts at the `0.1.0-dev.1` build from source
`d6e68cc934adcde3023c866f003024718038eab2` and installs `0.1.0`,
with storage continuity and Home schemas remaining at version 1.
The stopped upgrade preserved account, endpoint and home identities, indexed
Unicode history, an independent unsent draft and the exact pending operation after
a committed acknowledgement was lost. Resolution returned the original event
once, and a second resolution found no pending effect. Both service stops were
clean. This evidence covers that same-schema transition; it does not establish
compatibility with arbitrary development builds or authorize rollback.

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
