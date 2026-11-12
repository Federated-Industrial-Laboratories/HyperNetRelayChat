# Create and operate a HyperNet host

## Simple shared hosting

Open **Profiles and setup > Join a server > Create or manage a server**. HRC
opens the shared HyperNet host window with its installed executable. Closing
that window leaves the current chat profile open.

1. Select **Invite only**, **Password** or **Public**. A new server starts with
   Invite only selected. Public joining is an explicit choice.
2. Set the server name, reachable IPv4 address and owner nickname. Choose finite
   access or **Access until removed**, and finite hosting consent or **Run until
   stopped or withdrawn**. Existing finite consent is never converted silently.
3. Review participant capacity, optional Agents and resource settings. The shared
   chat preset permits at most 32 participants including the separate owner. It
   allows the welcome room and approved Pages; ordinary room creation, moderation,
   publication, hosting and delegation are off. Agent enrolment is optional, with
   a host-selected quota of one to eight Agents per operator.
4. Use **Install / verify packages** if native dependencies are missing. Select
   the coordinated release's `Packages` folder; it contains `Core/` and `Suite/`
   with their signed package sets. The installer preserves signature and rollback
   checks. Distribution packages and host permissions remain explicit prerequisites.
5. Choose **Review server setup**, inspect the topology and permissions, then
   **Create and start server**. Resume the same saved setup after an interruption.
6. From the dashboard, create a private invitation or show the public connection
   link. Copy the connection instructions or save its QR image. Share a password
   separately. Test the link from another connection before inviting others.

The dashboard can pause new joining, rotate the password, disable invitations,
remove members, open the owner chat or welcome Page, and export redacted diagnosis.
Invitation expiry or password rotation affects future joins, not existing members.
Removing a person also retires their scoped Agents; **Continue removal** resumes
an interrupted cascade. Chat history and original registration outcomes remain
retained. **Stop hosting** preserves state. Withdrawal also revokes local hosting
consent and requires a fresh review before hosting again.

Enable unattended user services deliberately if hosting must continue after logout
or reboot. There is no service lifetime timer in persistent mode. Current clock
checks, short-lived transport proofs and explicit removal still apply. Ready means
checks from this host passed; it does not prove Internet routing or firewall access.
The first topology uses one computer and does not provide independent fault domains.

The shared workflow uses the [private HRC hosting adapter](SharedHosting.md) to
create the separate owner, restricted Home and general room while Suite owns the
native network and read-only Pages. Suite can also host Pages with HRC absent.
The existing finite/manual workflow follows below.

## Finite and manual hosting

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
The manual workflow does not download packages, make privileged changes or renew
consent automatically. The shared workflow offers reviewed package installation
and a separate, explicit unattended-service setting.

Four authority reservations and three service reservations are shown separately
from HRC's application data. Default admission is 512 MiB memory and 1 GiB state
per native role. The relay accepts enough connections for the two attached
endpoints. These are pilot defaults, not a measured concurrent-user guarantee.

## Clients and agents

Hosts can optionally enable [self-service invitations](SelfServiceInvitations.md)
to send one private invitation before a recipient creates their keys. That
separate admission service defaults to disabled. It automates the public-file
exchange and ordinary enrolment described below; manual approval remains available.

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

For a host with owner-created rooms only, set the [room creation policy](Operations.md#restrict-conversation-creation)
in **Operations > HRC service** before inviting participants. List the owner's
complete enrolled human account ID. The service then refuses new rooms, private
groups and direct conversations from other accounts, including bots. Existing
conversation access and moderation remain unchanged. No Core or Suite update is
required for this HRC policy.

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
Renewal replaces the stopped desktop companion's cached voucher under its
exclusive lock. Account keys, requester journals, route identity and privacy
settings remain unchanged; the new voucher is checked before connection.
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

The supported pair is HyperNet Core 0.11.0 and HyperNetSuite 0.11.0. HRC
embeds their released offline Bundle.py and PackageTrust.py helpers, executes them
with isolated Python, verifies the independently pinned publisher key and checks
the signed installed manifest and complete file set. It does not accept a matching
version string as sufficient package identity.

| Source | Pinned release |
| --- | --- |
| HyperNet Core | [v0.11.0](https://github.com/Federated-Industrial-Laboratories/HyperNet/releases/tag/v0.11.0) |
| HyperNetSuite | [v0.11.0](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/releases/tag/v0.11.0) |

| Embedded helper | SHA-256 |
| --- | --- |
| Core Bundle.py | `aa278629cae5afaa390de96c7d6f77c0e63aad88506e96e13ad2563a51f80629` |
| Core PackageTrust.py | `5f58c67ea68ceca21ed33aa5229d62c17ea647d028dc74a9a637f5aaeb3e8e2d` |
| Suite Bundle.py | `8e3dfd5bab246db067600e550350e3c9d9efa33b6e69554a73e2822c26d74c47` |
| Suite PackageTrust.py | `5f58c67ea68ceca21ed33aa5229d62c17ea647d028dc74a9a637f5aaeb3e8e2d` |

The helpers retain their MIT notices. See [native hosting licences](NativeHostingLicences.txt).
