# Private invitations

Self-service invitations are an optional HRC hosting feature. The host sends a
private invitation before the recipient creates their keys. HRC generates those
keys locally, sends signed public requests to the invitation service, and completes
ordinary native admission and HRC registration. Chat and Page traffic continue to
use HyperNet. The invitation service does not receive private endpoint, recovery,
database or native identity keys.

The existing bootstrap, request, setup-bundle and registration file exchange
remains available. A host does not need to enable self-service invitations.

## Join from the desktop

1. Obtain the private invitation directly from the intended host. Keep the whole
   invitation private; it includes the service address, certificate pins and a
   one-use secret. A copied invitation can be claimed by whoever receives it first.
2. Open HRC and choose **Join with a private invitation**. Select a private setup
   folder and the installed native tools. Check the local runtime and start or
   select the authenticated local clock.
   Choose a short folder path. HRC checks its local companion socket path before
   generating identity keys or redeeming the invitation.
3. Paste the invitation or choose its text file. Accept the host's relay and
   service arrangement and automatic access renewal within the invitation's
   existing limits, then choose **Join or resume invitation**.
4. Keep this setup folder. HRC retains the authentication identity and exact
   public requests there. It completes native admission, creates the local HRC
   endpoint and recovery key, submits the signed registration, and enters chat
   after authentication succeeds.

Core, Suite, user systemd and an authenticated chrony source are local
prerequisites. The invitation cannot install executable files, alter system
clock policy or grant administrator privileges. Its ordinary member permissions
remain subject to the host's room-creation policy and later revocation.

Cancellation, connection loss or an interrupted response does not discard the
keys or create another account. Resume with the same setup folder and invitation.
After that folder has retained the invitation, both invitation fields can be left
empty to resume it. Do not delete the profile or requester state to retry an
uncertain operation. Access that has expired or been revoked remains refused.

Complete initial native admission within 24 hours after redemption, or sooner
if the host's access deadline requires it. This clock starts when HRC redeems the
advance invitation, not when the host sends it. Native membership acceptance
cannot be extended by replacing an interrupted join's invitation. If HRC reports
that initial admission expired, retain the old setup folder and ask the host for
a new invitation. Do not remove guards, keys or requester journals to bypass it.

## Pages

When the host supplies Page access, setup creates a second native reader profile
with fresh keys and reader permissions. It selects that profile for native Page
links automatically. The chat companion continues using its own profile. The
reader receives no HRC account or application connection grant.

The normal **Settings > HyperNet Pages** controls remain available. A manually
selected external reader retains its independently managed admission and renewal.
One native browser can use a reader profile at a time. Navigate within that
window, or close it before opening another Page from chat.

## Renewal and offline use

An invitation's initial redemption deadline, finite access deadline and route
voucher deadlines are separate. Claiming an invitation binds it to the local
authentication identity and exact public requests. It cannot create additional
recipients. Later status and renewal requests authenticate using that retained
identity rather than allocating new accounts or keys.

For an opted-in online profile, HRC waits for the native renewal boundary, saves
the current draft, releases the local client and stops only its configured chat
companion. It obtains current vouchers, retains them through the native client,
updates the stopped companion's exact target, then reopens the existing HRC
profile. History, account identity, native requester state and pending message
outcomes are retained. Reopening an expired online profile uses the same path.

**Open offline** and an explicit **Disconnect** disable automatic reconnection.
Use **Open chat** or **Reconnect** when online access is wanted again. A failed
renewal leaves the same profile available for another attempt or offline access;
it does not bypass a refusal.

An already open Page browser is not terminated for renewal. New reader vouchers
remain pending locally until that reader is next launched and its native profile
is available. Close the existing browser and retry a Page link if its access has
expired. Updating the reader does not change the chat's keys or history.

Automatic renewal stays inside the host's existing consent and the invitation's
access deadline. It does not extend hosting consent, increase permissions or
restore revoked grants. The host must separately renew its hosting arrangement;
an old invitation cannot authorise that operation.

## Prepare the host

Manual invitation and registration exchange remains the default. Self-service
requires a separate, explicitly enabled admission listener. Run it as the same
unprivileged operator that owns the native hosting state. Keep its private
directory separate from recipient exports, HRC profiles and recovery material.
Use absolute paths under private directories, with `umask 077` when preparing
files. The listener uses its own pinned TLS identity; it does not publish the
authority control socket or replace the native relay.

For an existing HRC-managed HyperNet, export its retained configuration:

```sh
hrc admission export-backend \
  --network-config /Private/NetworkConfiguration.json \
  --operator-lock /Private/HyperNet/Operation.lock \
  --output /Private/AdmissionBackend.json
```

The lock must be the managed host's existing `ROOT/Operation.lock`. The export
requires completed hosting setup and retains the existing bootstrap, native
requester floor, keys, service identities and consent expiry. It creates local
admission control metadata; it does not provision another network.

An independently operated native host can instead supply an explicit backend
JSON file. `hrc admission init --backend FILE` validates and imports this context;
there is no need to construct a managed-host journal or relocate existing stores.
The JSON uses these fields:

| Field | Required value |
| --- | --- |
| `core`, `suite`, `publisherKey` | Verified supported native executables and the pinned publisher public key. |
| `bootstrap` | The existing accepted bootstrap CBOR file. |
| `operatorDirectory`, `operatorKey` | The existing native operator workspace and its matching identity file. |
| `operatorLock` | A private lock file shared by every operation using that native requester. |
| `authorityControlDirectory` | The existing directory containing `Control.sock`. |
| `clockDirectory`, `clockMetadata` | Public clock export directory containing `ClockHealth.cbor`, and JSON containing its `publicKey` and `kernelBoot`. |
| `image` | Exact native confinement image digest, including `sha256:`. |
| `homeConfig` | Configuration produced by `hrc manage service import` for the existing HRC Home. |
| `relay`, `authority`, `application` | Objects containing the exact logical `service` identifier and signed native route `profile` path. |
| `reader` | `null`, or an object containing `content: {service, profile}` and the distinct `pageHostKey`. |
| `accessExpiresMs` | Operator-approved absolute Unix millisecond deadline, within existing hosting consent. |

This is a fixed native context, not an executable plugin. It cannot contain shell
commands or recipient-selected paths. The operator workspace must already contain
its retained `Floor`, matching `Identity.json` and `HyperNetSuite`, and `Inputs`
and `Output` directories. The existing native mapped-UID convention applies:
the workspace is private mode 0700 and owned by subordinate UID 1001. Import does
not initialize a new requester or copy a requester floor.

Before importing an existing Home, stop only that service and use the normal
service-control import:

```sh
hrc manage service import --directory /Private/Home \
  --output /Private/HomeControl.json
```

The admission worker uses that Home configuration for bounded maintenance stops.
It records whether the service was running before a stop and restores it after
the account operation, including a resumed interrupted maintenance operation.
It does not stop the relay, authority committee, browser, inference model or
unrelated services.

Every native workflow holds the configured operator lock. HRC-managed network
commands already use `Operation.lock`. For an imported context, arrange for
existing operator tools to hold the same lock with `flock` for their complete
native workflow. Do not replace or delete the lock file. Separate locks around
individual commands do not serialize a multi-command workflow using one requester.

Package verification, bootstrap/Home identity checks and operator workspace
checks occur before admission. Access is capped by the configured deadline,
bootstrap validity and configured signed route-profile validity. The native
tools verify signed route templates before grants are delegated and enforce
current certified consent during issuance. Page access additionally needs an
existing native Page host and content endpoint; this feature does not create
those hosting roles.

## Enable and issue invitations

Choose an unused unprivileged IPv4 listener address and port. The address below
is an example; replace it with the host's reachable address. Firewall changes
remain an explicit host operation.

```sh
hrc admission init --backend /Private/AdmissionBackend.json \
  --directory /Private/Admission --address 192.0.2.10:25444 \
  --name 'Community trial' --maximum-invitations 8 --route-seconds 86390
hrc admission enable --config /Private/Admission/Configuration.json
hrc admission start --config /Private/Admission/Configuration.json
hrc admission status --config /Private/Admission/Configuration.json
hrc admission issue --config /Private/Admission/Configuration.json \
  --label 'Invited participant' --hours 72 --output /Private/Recipient.txt
```

Initialization leaves the listener disabled. `start` uses the existing user
service manager; `serve` runs the same bounded listener and worker in the
foreground. Initialization and startup do not change host firewall rules.

Send only the resulting private invitation file through the intended direct
message or email. The command reports its identifier, path and deadlines without
printing the bearer secret. No email or message is sent automatically. Use
`hrc admission export --config CONFIG --id ID --output FILE` to recover the same
invitation export after an interrupted handoff.

The default redemption deadline is 72 hours; `--hours` accepts 1 through 168 and is
capped by access expiry. Native issuance begins when the recipient redeems it.
Initial native joining and HRC registration must then complete within the
reported joining deadline, at most 24 hours. Ordinary route vouchers default to
86390 seconds; `--route-seconds` accepts 120 through 86390. Short ordinary vouchers
can renew during initial setup while the original joining window remains valid.
They do not replace its immutable native invitation or extend that window.

One invitation binds to one retained authentication identity and exact public
requests. Ordinary chat admission grants Reader0/6 and Connect30 scoped to this
one application service. An optional separate reader receives Reader0/6 and
Authority/Page routes, with no chat account or application grant. No moderator,
agent, publisher, host or account-management role is added.

The invitation record limit defaults to 8 and can be set from 1 through 64 during
initialization. Revoked and completed records remain retained and count toward
that limit. The worker processes one native workflow at a time. Same-ID voucher
renewal starts only after all prior ordinary routes expire plus a two-second
margin; earlier requests return the retained delivery. It preserves the original
setup bundle, grants, membership, account and requester state.
At most 8192 renewal rounds are retained per invitation. This bound covers the
native seven-day hosting-consent limit even with 120-second ordinary vouchers.

## Inspect, disable and revoke

```sh
hrc admission list --config /Private/Admission/Configuration.json
hrc admission revoke --config /Private/Admission/Configuration.json --id ID
hrc admission disable --config /Private/Admission/Configuration.json
hrc admission stop --config /Private/Admission/Configuration.json
```

Revocation immediately blocks the invitation credential and queues permanent
revocation of its exact native grants. The running worker prioritizes these jobs
and can process queued revocations while admission is disabled. It revokes the
chat Connect grant, then reader grants, without deleting the HRC account,
membership or history. Already issued route bytes are not erased; current native
permission checks enforce the revoked grants.

Disabling admission prevents new admission work; stopping the listener also
stops its worker. Allow queued revocations to finish before stopping it when
immediate native revocation is required. Disabling the invitation service alone
does not revoke existing access or stop native chat hosting.

The worker retains exact requests, grant identifiers, route generations and
expiry values before native effects. Native output files and original HRC
invitation/enrolment outcomes can be recovered after interruption. A missing
response does not prove that an operation failed. An uncertain native effect
without a recoverable result is reported as requiring operator inspection;
partial revocation preserves both known results and unknown outcomes.

After inspecting the original outcome, use
`hrc admission retry --config CONFIG --id ID` to requeue that exact operation.
This does not allocate new identities or declare an uncertain operation undone.
If its native outcome remains unknown, it remains blocked. Inspect the existing
requester stream through the supported native tools; never delete a floor,
pending request, guard, invitation binding or retained result to force a retry.
Hosting-consent renewal remains a separate explicit operator workflow.
