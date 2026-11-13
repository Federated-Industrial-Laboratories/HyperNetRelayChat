# Linux installation and upgrades

HRC packages contain the GUI, TUI, CLI and deterministic bot in one `Bin/hrc`
executable. HyperNet Core and Suite are separate prerequisites. Installing HRC
does not create a network, grant application access or start a service.

HRC 0.3.0 adds shared simple joining, hosting and external Agent setup. The earlier
[bounded Linux pilot](IntegrationProfile.md#8-linux-pilot-qualification) retains
its original measured versions. Use its topology and workload limits when planning deployment.

## Requirements

The package target is native Linux x86_64 with GNU libc and OpenSSL 3. `Package.json`
records the binary's minimum GNU libc symbol version and linked shared libraries.
The GUI additionally needs a working Wayland or X11 session, EGL/OpenGL, XKB and
Fontconfig. Install fonts for the languages in use; missing terminal or GUI glyphs
do not change stored text. Sound is optional and off initially.

The earlier native network qualification used Ubuntu 26.04 (resolute), kernel
`7.0.0-42-generic`, amd64 and GNU libc 2.43. Earlier packaged CLI and offline GUI/TUI checks
used Ubuntu 24.04 with GNU libc 2.39. Those checks retain their original releases
and do not establish full native-load qualification on Ubuntu 24.04. Use the
selected package's `minimumGlibc` and library inventory for its actual binary
requirements. Other platforms are not qualified.

The supported hosting pair is Core 0.11.0 and Suite 0.11.0. Use independently
verified binaries matching the [contract map](HyperNetContract.md), with the version-2 application
companion and `checkAuthority-v2`. Each service and caller needs its own current
application admission and approved stream configuration. See
[service setup](ConversationSetup.md) for identities, clock observations and
private directory permissions. There is no direct Internet fallback.

## Verify and unpack

Obtain the selected binary archive, source archive, `SHA256SUMS`, its
`SHA256SUMS.sig` OpenSSH signature, and `PublisherKey.txt` from the
[v0.3.0 release](https://github.com/Federated-Industrial-Laboratories/HyperNetRelayChat/releases/tag/v0.3.0).
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

The coordinated package's `Tools/Install.sh` verifies and installs its supplied
Core/Suite tools, registers the shared native invitation handler, then installs HRC
and the application-menu launcher for this user. No repository checkout or
separately collected package files are required.
The equivalent explicit command is `hrc install --native-packages /Path/Packages`.
The plain `hrc install` command and a package without native payload retain the
launcher-only installation option.
If desktop link registration fails, the verified native tools stay installed.
Retry the coordinated installer or **Install native tools** to repair registration;
saved identities and package trust are retained.
The setup window also has an **Install launcher** button. No root access is used.
A direct first launch offers **Install native tools**, with the adjacent package
folder filled in. **Choose package folder**, **Verify supplied packages** and
**Install verified native tools** provide the same reviewed path. The initial
Suite binary is verified by HRC's existing pinned importer before it can execute;
Suite then verifies the coordinated installation. Joining and shared hosting stay
unavailable until that installation verifies. This installation does not start
network services or require loading a Core container image for a joining client.
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

For simple servers, **Join a server** opens the shared HyperNet preview, password
and QR workflow. **Create or manage a server** opens its host dashboard and
coordinated package installer. The `Packages/Core/` and `Packages/Suite/` folders
contain the exact signed Core and Suite package sets; one reviewed installation
handles both products. Invites cannot select downloaded executables or trust keys. Saved profiles and **Agents > Add an external Agent** use the
same shared admission system. See [simple joining](SimpleJoining.md).

The setup wizard can open an existing profile or guide a new endpoint through
network admission, invitation import, registration export and activation.
The earlier v1 workflow also supports an optional [private invitation](SelfServiceInvitations.md)
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

### HRC 0.3.0 and coordinated native upgrade

Upgrade Core and Suite together to 0.11.0 before enabling the shared join mode.
The complete authority committee and authoring clients must support the persistent
validity and scoped admission features before those records are published. Older
voters and clients fail closed on the new tagged validity, admission records and
stream origins. Do not open post-activation native state with an older binary;
the signed 0.11.0 target policy also raises the package version floor. Keep
the accepted bootstrap, keys, journals and independent rollback floors. Existing
finite membership, grants, hosting consent and v1 invitations retain their bounds;
installing this release does not extend them. Adopt persistent authority only
through the native explicit policy and consent procedures.

Ordinary existing HRC profiles remain usable. Enabling live admission advances
the Home schema to version 2 so an older Home cannot ignore restricted participant
scopes. It then refuses that database. Do not downgrade a Home after enabling this
feature. Back up the stopped Home and its guard before the change.

Saved simple servers add their own private runtime binding beside the HRC profile.
Manual profiles receive no automatic conversion, nickname change or new Agent
classification. Automation that used a human profile can voluntarily create a
separately keyed Agent with a visible successor link; old messages and private
keys remain unchanged. Stop the old automation and resolve pending sends first.
API credentials and Agent operator consent do not transfer ownership of a person
profile or expose its recovery key.

### Historical upgrade evidence

The checked development upgrade starts at the `0.1.0-dev.1` build from source
`d6e68cc934adcde3023c866f003024718038eab2` and installs `0.1.0`,
with storage continuity and Home schemas remaining at version 1.
The stopped upgrade preserved account, endpoint and home identities, indexed
Unicode history, an independent unsent draft and the exact pending operation after
a committed acknowledgement was lost. Resolution returned the original event
once, and a second resolution found no pending effect. Both service stops were
clean. This evidence covers that same-schema transition; it does not establish
compatibility with arbitrary development builds or authorize rollback.

### Upgrade procedure

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
