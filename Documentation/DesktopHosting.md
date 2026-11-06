# Create and operate a HyperNet host

HRC's desktop hosting workflow prepares a user-owned HyperNet and an HRC home
service. The first topology runs four separately keyed authority replicas, a
relay, an attached authority endpoint and an attached HRC endpoint on one Linux
host. Three authorities must answer for a committed authority operation. This
topology does not survive failure of that host and does not provide independent
relay operators.

Choose a short private hosting folder, a separate recovery folder, the verified
Core and Suite installations, the release publisher public key, a readable
chrony command socket, the host IPv4 address, ports, display name and nickname.
The currently supported route profile requires the advertised IPv4 address to be
assigned to the host. Separate NAT bind and advertised addresses are not
supported. Choose a reachable LAN or public IPv4 from **Host interface**, or enter
an address assigned to an active interface on this host. No address is selected
automatically. Loopback cannot connect the isolated native containers, including
on a single-host installation. HRC does not change firewall or router settings.

Review the exact proposed topology, organisational privacy mode, resource limits
and finite consent interval. The preview also verifies the signed installed
packages, the selected host address and conflicts with the four requested
authority subnets. An incomplete subnet inspection blocks fresh setup. The three
service networks use native automatic allocation. Applying that preview creates distinct identities, obtains native
operator consent, starts the approved services and creates the first desktop
account. Setup reports Ready only after a live Suite authority operation and an
authenticated HRC client session both succeed. A process running by itself is
not that evidence.

Native failures show the failed step and a bounded, redacted diagnostic when one
is available. Existing keys and pending operations remain in place for resumption.

The single-owner recovery key and certificate issuer remain in the selected
recovery folder outside the active runtime. Protect and back up that folder
separately. Do not delete runtime state or generate replacement keys to resolve
an interrupted operation. Resume the same saved configuration. Existing signed
artifacts and native requester, recipient and voter journals remain authoritative.

## Prerequisites

Hosting needs rootless Podman with subordinate UID/GID mappings, an OCI runtime,
slirp4netns at its supported system path, cgroup v2 CPU/memory/PID controllers,
seccomp, Landlock ABI 6 or newer, OpenSSL and a systemd user session. Signed
package verification uses Python 3.11 or later and OpenSSH signature support.
The clock observer reads authenticated chrony observations; it does not adjust
the system clock. Missing packages, subordinate-ID allocation, clock policy,
user lingering and network exposure require separate deliberate system setup.
No package download, privileged change or consent renewal happens automatically.

Four authority reservations and three service reservations are shown separately
from HRC's application data. Default admission is 512 MiB memory and 1 GiB state
per native role. The relay accepts enough connections for the two attached
endpoints. These are pilot defaults, not a measured concurrent-user guarantee.

## Clients and agents

A joining desktop first exports its native public NetworkRequest. The host
creates an exact member invitation, bounded route vouchers, a Service-only HRC
connect grant and a one-use HRC account invitation. The resulting HrcClientSetup
bundle contains only public artifacts. Deliver its complete fingerprint through
an independently authenticated channel. The joining desktop retains its own
private network, endpoint and recovery keys.

Return the signed HRC endpoint registration to the host for enrolment. HRC
briefly stops only its own home service when an invitation or registration needs
exclusive storage access, then restores it. An agent account also names its HRC
operator. HyperNet grants and HRC agent delegation remain separate permissions.

## Stop, resume and expiry

Stop and Start act only on the units derived from this hosting configuration.
They preserve keys, profiles, conversation history and native replay protection.
Native container-network reservations also remain available for restart. A
second host configuration needs a different unused subnet range; stopping the
first host does not release those reservations. Native withdrawal is permanent
and releases the withdrawn deployment's reservations.
For resumption, HRC verifies the exact private hosting journal and configuration;
it does not claim that the saved subnets are free. Native runtime checks remain
authoritative for retained reservations and every later allocation.
These are session services; boot startup and user lingering are not silently
enabled. The desktop can display the durable phase of an interrupted setup
without acquiring its mutation lock.

Hosting consent is finite and separate from the bootstrap administrator policy,
member/application permission and route validity. A host reboot can require an
explicit stopped successor that binds the new boot to the same monitor key.
Stop the host, inspect the native successor previews, then apply their exact
review digest. Existing network and service identities remain unchanged.

Renewal performs the stopped host consent transition, obtains current authority
admission, renews signed routes and the same application binding, then applies
the exact replacement through Core's native stopped transition. The native
service identities, TLS keys, endpoint, privacy mode and resource limits remain
fixed. The desktop's renewed connect grant and the service owner's management
grant are limited to their existing HRC service and the reviewed deadline.
There is no unattended renewal. Interrupted work resumes its retained native
operations; direct edits to installed Config files are unsupported.

After reopening HRC, choose **Resume renewal review** to load the exact unfinished
review and its original deadline. Review it and approve that retained operation.
The command-line equivalent is `hrc manage network renewal-resume --config FILE`.
This does not generate new consent or replace pending native operations.

The separate governance horizon, initially 365 days, bounds the administrator
policy and stable member/read identities. Hosting and service-operation consent
are reviewed for at most seven days. Client route vouchers last less than
24 hours; status reports that earlier effective connection deadline. A longer
hosting interval does not imply an uninterrupted seven-day client route. Renew
explicitly to issue fresh vouchers. Other admitted clients obtain a fresh public
setup bundle for their existing keys from the host; their grants are not renewed
by renewing the host owner's desktop.

## Pinned native verification

The supported pair is HyperNet Core 0.10.3 and HyperNetSuite 0.10.2. HRC
embeds their released offline Bundle.py and PackageTrust.py helpers, executes them
with isolated Python, verifies the independently pinned publisher key and checks
the signed installed manifest and complete file set. It does not accept a matching
version string as sufficient package identity.

| Source | Pinned release |
| --- | --- |
| HyperNet Core | [v0.10.3](https://github.com/Federated-Industrial-Laboratories/HyperNet/releases/tag/v0.10.3) |
| HyperNetSuite | [v0.10.2](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.10.2) |

| Embedded helper | SHA-256 |
| --- | --- |
| Core Bundle.py | `47f636c1d35df1396ee878c30d3872504f5ee31cf54c6768eaf90b9e62a549e4` |
| Core PackageTrust.py | `5f58c67ea68ceca21ed33aa5229d62c17ea647d028dc74a9a637f5aaeb3e8e2d` |
| Suite Bundle.py | `9c738affdd1843a9969eaa6b0254cd39b685e68998c5ece6462d0a9c61b66dde` |
| Suite PackageTrust.py | `84600aa9eec08d549d19a04534ae2ecf1644945687174e6d79a3bb17c1106833` |

The helpers retain their MIT notices. See [native hosting licences](NativeHostingLicences.txt).
