# HRC in a shared HyperNet host

The HyperNet hosting workflow owns native authorities, the relay, service routes,
clock, application receiver and owner connection. When chat is selected, it uses
HRC's private hosting adapter to create the Home service, its local owner account
and the `general` community room. HRC retains its signing, database, endpoint,
recovery and registrar keys in private local files. Responses contain public
identities and private file paths, never key bytes.

The normal managed service command remains `hrc service run --directory PATH`.
The host starts it after the native receiver is ready. The existing finite
`hrc manage network` workflow and manual service/profile commands remain supported.

## Adapter contract

The verified installed HRC executable accepts one bounded JSON request on stdin:

```text
hrc service host-request --directory /Private/SharedHost/HRC
```

Use the same directory for every phase. The directory is created privately by
`prepare`; existing files and identities are retained. Concurrent requests are
refused. The request is at most 64 KiB and unknown fields are refused.

The initial request has this shape. `home` uses HRC's normal `ServiceId` JSON
representation, with the certified native network, incarnation and application
service ID. The owner principal is the separate certified owner participant.

```json
{
  "format": "HyperNet.HrcHost/1",
  "action": {
    "operation": "prepare",
    "home": {
      "network": {"network": "NETWORK_ID", "incarnation": "INCARNATION_ID"},
      "service": "APPLICATION_SERVICE_ID"
    },
    "receiverCompanion": "/Private/SharedHost/Receiver",
    "clock": {
      "observation": "/Private/SharedHost/Clock/Public/ClockHealth.cbor",
      "monitorKey": "PUBLIC_CLOCK_KEY"
    },
    "ownerPrincipal": "PUBLIC_NATIVE_OWNER_PRINCIPAL",
    "ownerCompanion": "/Private/SharedHost/OwnerCompanion",
    "nickname": "Owner",
    "motd": "Welcome to our server",
    "agentsEnabled": false,
    "maxAgentsPerOperator": 2
  }
}
```

The clock must have a fresh, valid pinned native observation. Nicknames use HRC's
normal limits: 1 to 32 grapheme clusters, at most 64 UTF-8 bytes, no controls.
Agent quota is 1 to 8. The receiver and owner companions must be distinct absolute
paths. Repeating prepare with changed inputs is refused; configuration updates
are separate host actions, not a bootstrap retry.

Prepare enrols only the retained, signed human owner registration in the empty
Home. An interrupted unused owner invitation can be renewed without replacing
the owner identity or keys. A completed registration is an exact historical
result and cannot restore a disabled endpoint. Room creation is restricted to
this owner before `Service.json` becomes available for service startup.

After the Home and both native companions are running, submit:

```json
{"format":"HyperNet.HrcHost/1","action":{"operation":"finish"}}
```

Finish uses ordinary authenticated owner operations for the initial nickname and
room. Nickname changes after registration are preserved. Signed effects and
their exact outcomes are retained before progressing. An uncertain room creation
is resolved or retried using its original operation; it never creates a second
room under a new operation. An expired or unavailable unresolved operation is
reported for inspection, without guessing success or replacing it.

The running Home then receives its admission policy through the existing private
authenticated control socket. This uses a separate registrar key. Ordinary
members cannot create rooms or administer the server. External Agents remain
subject to operator consent, room scopes and the configured per-operator quota.
The policy and a one-time bootstrap receipt commit atomically inside Home.
Repeating finish does not restore admission disabled later by the host, including
an interruption before the local completion marker was written.

Status requires no network connection or fresh clock:

```json
{"format":"HyperNet.HrcHost/1","action":{"operation":"status"}}
```

Successful responses contain `format`, `status` (`Prepared` or `Ready`),
`descriptor`, `serviceDirectory`, `ownerProfile`, `recoveryKeyFile`,
`admissionBinding`, `rooms` and `policy`. Rooms are empty until finish succeeds;
then they contain the retained general-room ID. Policy contains `agentsEnabled`
and `maxAgentsPerOperator`. These statuses describe completed provisioning,
not current service health. Suite owns managed service status, restarting,
the public joining endpoint and publication of the descriptor.

Keep the owner recovery key separately backed up. The local registrar binding
and signing files must remain private to the host account. Neither the public
listener nor an ordinary participant chooses helper executables, configuration
paths or registrar credentials.

## Isolated registrar bridge

A composed host can pass the optional pair `admissionBridge` (absolute directory)
and `admissionUid` (the registrar's mapped host UID) in Prepare. Both must be
present or absent. They become part of the retained exact host intent and cannot
change on retry. The bridge must be separate from the HRC private hosting tree.
When omitted, the existing owner-only local control workflow is unchanged.

Home creates a socket-only bridge directory owned by its host UID with mode 0711
and `Admission.sock` with mode 0666. An exact `SO_PEERCRED` UID check precedes
reading or sending a control frame. The bridge accepts only typed, signed live
admission requests; even an owner-signed configuration or legacy-administration
command is refused there. The Home owner socket remains in its private 0700
directory with mode 0600 and its separate owner controls.

The native host derives mapped UIDs from the actual rootless namespace map. It
provisions only the scoped registrar key and public binding into a separate
mapped-owned private state directory. No Home signing/database key, owner profile
or recovery state is mounted into the registrar. The original scoped key remains
private at the host for exact provisioning retries. Do not print it or send it
through command arguments.

With fixed mounts `/HrcAdmission` for scoped state and `/HrcBridge` for the socket,
the isolated binding is `directory: "/HrcBridge"`, `peerUid: 0`, the response's
`home` and `serviceKey`, and `registrarKeyFile: "/HrcAdmission/Registrar.key"`.
Here zero identifies the Home owner's translated UID inside that namespace,
not permission to run the registrar as root. The configured registrar UID remains
distinct. Home authenticates the registrar's signature and current admission
policy on every request.

The bridge sends a signed per-connection Home challenge binding its identity,
boot instance, nonce and five-second deadline. The reply must use that exact
challenge. No boot file or private service configuration is exposed. This
bridge protocol is selected only by a binding with `peerUid`; legacy bindings
continue using the original private control socket.
