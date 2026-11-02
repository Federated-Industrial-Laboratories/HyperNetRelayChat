# HRC HyperNet integration contract map

Draft 3, 31 October 2026. [Product plan](ProductPlan.md) · [Protocol proposal](ProtocolPermissions.md)

This map records inspected upstream behaviour and the HRC integration boundary. The HRC Rust adapter and smallest local conversation have representative real HyperNet integration evidence; complete release and pilot-capacity qualification remain open. The 0.10.0 source implements the previously required companion authority and directional-context extension while retaining the 0.9.1 permission correction.

| Product | Published v0.10.0 revision | Status |
| --- | --- | --- |
| HyperNet Core | `b840c8b8e7d74fac71e898cf2c2eb7c660c57275` | Published; signed public assets verified |
| HyperNetSuite | `3055f06a691fbc2f0214b4d9bb706a004d5c22ad` | Published; signed public assets verified |

Sources below refer to the exact published revisions. The stable v0.10.0 releases, all sixteen public assets, their hashes and the checksum/package signatures were verified. Installed qualification with the final release executables passed version-1 and version-2 payloads, exact session/action/nonce binding, a check using the one-second SDK default, expiry, cancellation and certified denial after grant revocation. The bounded fixture was cleaned up. This establishes the recorded HyperNet boundary, not HRC interoperability, pilot capacity, other-platform support or independent security certification. Earlier source-bound results retain their original identities. A version string alone is insufficient to prove the selected semantics.

## Transport and service contract

| Observed contract | HRC consequence |
| --- | --- |
| Application protocol 7 carries opaque duplex bytes plus separately verified application context | Define native HRC framing and room semantics; message payloads do not enter authority history |
| Named service registration binds owner/operator consent, service, endpoint, local binding, route, protocol, limits and validity | Install HRC as a consented service with exact `hrc/1` binding; never accept an arbitrary payload address |
| Route voucher permits transit; application grant permits use of a service | Neither permission is an HRC room membership or agent delegation |
| Matching endpoint and application permission gate buffered/new writes | HRC still checks its own current rights before every effect; bytes already handed to HRC do not prove future authority |
| At most 16 active incoming/outgoing connections combined per companion, 16 configured targets, bounded queues and serial authority requester | Count human devices, agent endpoints, federation directions, operator access and reconnect overlap before promising scale |
| Route maximum is one hour and 1 GiB per connection; configured values can be lower and overhead consumes allowance | Resume over freshly authorised streams before exhaustion; retain exact uncertain operations |
| Directional EOF permits half-close; cancellation, expiry, revocation or hard failure closes the stream | Distinguish transport closure from an HRC commit result; no automatic effect replay |
| Same service/principal has 16 reusable slots with generations and fenced retirement | A client close is not permission to revive a spent session or restore its quota |

These behaviours are documented in [Core application streams](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Documentation/ApplicationStreams.md) and implemented in [Suite's companion](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Source/Applications/ApplicationStreamsAgent.rs).

HyperNet is mandatory for all HRC remote chat/service paths. A refusal, unavailable relay, incompatible protocol or missing selected privacy policy fails closed. HRC must not use a direct TCP/HTTP path, process proxy, payload-supplied address or alternate trust root as recovery. Local companion IPC is the documented local boundary, not an Internet fallback.

## Action 29/30 correction and upgrade boundary

The hotfix retains signed action numbers and record bytes. Stream management is action 29 and connection is action 30, with an exact Service scope `(3, service ID)`. The terminal grant and every non-root ancestor must have only Service scopes. Network, mixed-family or other resource kinds fail these effects. Sealed publication uses Object/Namespace-only grants, so its overlapping numbers cannot grant stream access.

Only a root accepted by current governance may remain broad as an ancestor authorising explicit scoped delegation. A broad root cannot execute the stream effect as its terminal grant. A narrow child beneath a broad non-root grant does not repair the chain. Existing exact subject, action, version, admission, tier, expiry, revocation and consent checks still apply. See [scope classifier](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Protocol/TrustActionScope.rs), [chain check](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Authority/Governance/AuthorityGovernance.rs) and [stream evaluation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Authority/Domains/AuthorityStreamsEvaluation.rs).

When migrating from 0.9.0 to the corrected permission evaluator, the complete authority committee, endpoints and corresponding Suite clients need a coordinated stopped upgrade before affected work resumes. First quiesce ordered mutations and pending requests on the old version, complete catch-up, inspect fresh quorum evidence, and stop all voters at the same fully applied and committed height. Preserve complete journals, state, history and floors. An old committed but unapplied suffix would execute under the new evaluator and can diverge; lagging or mixed-version upgrades are unsupported. Old binaries retain the earlier broad interpretation; unchanged wire numbers do not make mixed semantics supported. Existing broad admissions/service/reviewer bindings need the documented explicit migration. Same-rights application renewal cannot change an accepted grant. [Permission scopes and migration](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Documentation/PermissionScopes.md)

The additive 0.10.0 check interface needs matching Core endpoints and Suite companions, stopped service replacement and renewed local artifact consent. It does not itself require new grants. Existing 0.9.1 payload-only peers remain compatible but cannot supply the fresh-check capability HRC requires.

## Application identity and renewal

An application admission binds its own key, owner and exact grant, with validity at most seven days and within grant validity. Applications have no further delegation authority. Same-rights renewal requires explicit owner/application consent; it does not enlarge rights or permit unattended consent. Withdrawal remains restrictive, and withdrawn application keys cannot be reused. [Application lifecycle](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Documentation/Applications.md)

Each HRC agent that requires independent transport attribution needs its own admitted principal and companion/profile. Sharing a human's companion authenticates the same principal and cannot prove a separate agent. HRC's account/endpoint enrolment must bind that principal explicitly; no caller-supplied display name or represented-account field can do so.

## Private companion interface

Suite is currently a binary application with a packaged Python SDK, not a published external Rust library for this interface. HRC integration uses a narrow owned Rust adapter to the pinned local companion contract, with interoperability tests against the shipped SDK and real companion. Reuse Suite's cryptographic/authority ownership rather than copying it into HRC. Library publication is an alternative only after a supported upstream interface exists. [SDK](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/SDK/README.md) · [Cargo targets](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Cargo.toml)

| IPC element | Observed representation and adapter obligation |
| --- | --- |
| Local endpoint | Absolute canonical private directory, owner UID, mode 0700; `Control.sock` owner UID/mode 0600; validate Linux peer credentials and inode/path identity |
| Request/response | Big-endian four-byte length, non-empty JSON body at most 16,384 bytes; versions 1 and 2 have explicit schemas; reject malformed types, length and unsupported versions |
| Request fields | `version`, `action`, optional operation-specific `service`, `protocol`, `id`, `timeoutMs`; version 2 adds `nonce` and `actionDigest` only for `checkAuthority`; Rust request decoding rejects unknown fields |
| Operations | `connect`, `accept`, `status`, `cancel`; version 2 adds `checkAuthority`; connect resolves only configured named targets, not an IP supplied by HRC |
| Timeouts | Preparation: 100-60,000 ms, default 30,000; fresh check: required 100-5,000 ms, SDK default 1,000; payload socket I/O needs its own bounded timeout/cancellation |
| Successful handoff | JSON response contains `ok`, local connection `id` and separate `peer`; version 2 adds `privacy` and `checkAuthority`; remaining socket bytes are opaque application data, not additional JSON control |
| Status | Version 2 exposes bounded public connection metadata, separate directional privacy and `capabilities.checkAuthority`; capability support, endpoint readiness and exact-connection eligibility are distinct; status is not a fresh authority proof |
| Refusal | Preparation retains local `Capacity`, accept `Timeout` and generic `Refused`; fresh checks separately expose typed `permitted`, `denied`, `unavailable`, `expired` and `notActive`; generic closure still gives no certified reason |

The adapter must preserve partial reads, EOF, half-close, cancellation and ownership of exactly one stream. It must not parse status error prose into authoritative expiry/revocation categories. Reference implementations: [Python SDK](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/SDK/hypernet_streams/__init__.py), [local IPC](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Source/Networks/LocalStreamIpc.rs) and the companion above. The SDK opts in with `Agent(directory, version=2)`; its typed [context module](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/SDK/hypernet_streams/context.py) retains original call deadlines and invalidates known stale observations. HRC must implement equivalent protections at its Rust boundary.

## Direction-specific verified context

Accepted incoming context contains `network`, `incarnation`, `service`, `protocol`, `principal`, `grant`, `grantGeneration`, `session`, `generation`, `expiresMs`, `maximumBytes`, `idleMs` and `durationMs`; the companion adds bound `owner` and `endpoint`. The endpoint-signed local context binds a fresh local challenge and exact accepted binding. [Binding verification and context](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Source/Authority/Domains/ApplicationStreamBinding.rs)

Outgoing `connect` context names the verified target network/incarnation/service/protocol, owner, endpoint, route, session generation, expiry and limits. It does not carry the incoming caller's `principal`/grant fields in the same shape. Model these as distinct validated types; a missing field is not an anonymous principal to be trusted. The local `status.principal` describes that companion, not a foreign author.

Neither context establishes an HRC account, represented user, grant lifecycle, room membership, moderation role, recipient filter or original foreign actor. `expiresMs` is an initial bound, not evidence that authority cannot be revoked earlier. The HRC service cannot revalidate queued work's HyperNet authority merely by rereading old JSON.

## Fresh authority and directional privacy in 0.10.0

The supported capability is `checkAuthority-v2`. An HRC service requires this capability and obtains a fresh check when each queued action becomes eligible for evaluation. An authenticated endpoint channel must be ready and the exact incoming stream active; a version-1 payload connection or cached status cannot substitute. The request contains exactly `version: 2`, `action: "checkAuthority"`, local `id`, fresh `nonce`, immutable `actionDigest` and `timeoutMs`. Identifiers/digests use 64 lowercase hexadecimal characters; nonce and action digest must be nonzero. The companion resolves the exact kind-173 session reference internally. HRC cannot select a foreign session, principal or grant.

The Core endpoint initiates a separate persistent connection to `Ingress/Checks.sock`, mapped as `/Application/Checks.sock`, alongside the existing payload socket. A signed handshake binds the accepted binding digest, nonce, companion/endpoint instances, control generation and verified host kernel boot. Both sides require zero monotonic and boot-time namespace offsets. The mapped ingress still passes exactly one descriptor with a fixed tag under the existing private-path, peer-credential and confinement rules. No application payload framing, policy action or arbitrary authority-query interface is added.

Core performs a new endpoint-only `Stream::Permit` read, verifies its certified result and retained floor, and rechecks current clock health, gates and exact stream liveness. The signed local receipt binds the entire request and conservative deadline. The companion verifies its endpoint signature, binding, session and correlations before exposing the result. `permitted` and `denied` carry certified observation metadata; `unavailable`, `expired` and `notActive` do not. A receipt is an endpoint-signed local assertion, not a portable quorum certificate, HRC grant or approval of the action's contents.

The caller's 100-5,000 ms wait becomes an absolute `CLOCK_BOOTTIME` deadline at companion dispatch. The SDK also retains its earlier call-start deadline; HRC's Rust adapter must do the same. The authority challenge has a separate immutable ceiling at original companion start plus 5,000 ms, including time spent queued. This permits the authority uncertainty window without extending the caller's wait. The delivered receipt is clipped by current clock validity, original caller and stream bounds, current consent/gates and the certified authority lifetime. Queueing, copying and reconnect never renew it. Pending checks die with the control generation; known cancellation, closure or replacement invalidates use. A delivered observation cannot report an as-yet-unobserved remote change.

There is at most one pending check per connection and four per companion. The endpoint executes one authority read at a time with bounded request/frame queues. The control channel consumes none of the sixteen application connection slots. These are implementation bounds, not evidence that the accepted HRC pilot meets latency or fairness targets.

Version-2 outgoing context records actual authenticated nested TLS 1.3 and the selected/configured route settings. When the certified lookup matches the actual TLS destination, it includes bounded destination-profile provenance. Incoming context requires an exact-session endpoint observation: public mode 2 reports unknown upstream relay transit; attached mode 3 attests its approved attachment, relay service and profile digest. Missing evidence remains unknown. No saved profile or attachment proves physical operator independence or current profile validity; the corresponding assertions remain false. Message encryption is application-defined.

Sources: [Core check contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Documentation/ApplicationChecks.md), [canonical endpoint control schema](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Authority/Domains/ApplicationStreamControl.rs), [Suite context contract](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Documentation/ApplicationContext.md) and [check verification](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Source/Applications/ApplicationStreamChecks.rs).

## Remaining HRC integration gates

The [transport authority and federation profile](IntegrationProfile.md) applies the implemented upstream boundary to HRC. It adopts HyperNet's finite observation lifetime and strictly ordered HRC-owned controls, without promising an atomic transaction spanning authority and HRC storage.

| Remaining gate | Required outcome |
| --- | --- |
| Rust adapter and effect ordering | The [transport adapter](Transport.md) implements the local version-2 boundary and diagnostic checks. Qualification at the future HRC serial authorisation point remains open |
| Privacy presentation and deployment policy | Map supported directional facts to honest indicators; display unknown evidence and refuse unmet selected requirements; operator independence remains unverified |
| Error and outcome mapping | Distinguish certified fresh denial from unavailable/expired/inactive checks and generic I/O failure; never turn closure into an HRC revocation or absence-of-commit claim |
| Original-actor proof for federation | Implement accepted HRC origin attestation and original action authentication; a local endpoint receipt and an admitted gateway do not prove a foreign author |
| Remote freshness and clock recovery | Preserve source expiry and the home five-second challenge bound with conservative cross-host conversion and home-owned withdrawal barriers |
| Pilot and platform qualification | Exercise actual Linux IPC/security constraints, actor topology and bounded resource/latency behaviour; upstream limits are not an HRC capacity result |

HyperNet's current federation copies explicitly shared approved Pages. Its treaty/bridge trust pattern informs HRC, but it supplies no live chat forwarding contract. HRC's separately admitted bilateral gateways use the [federation runtime contract](FederationRuntime.md) and require their own setup and native qualification. [Existing federation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Documentation/Federation.md)

## Platform and evidence gate

Suite's release manifest uses Rust edition 2024 with `rust-version = 1.95`, eframe 0.37.0, Crossterm 0.29.0 and OpenMLS 0.9.1. These are inspected dependency facts, not HRC dependency commitments. The current qualified family is native Ubuntu x86_64 within its documented limits; HRC still needs its own qualification. [Manifest](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/Cargo.toml) · [Platform scope](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/3055f06a691fbc2f0214b4d9bb706a004d5c22ad/ReadMe.md)

The integration checks must demonstrate one exact admitted endpoint binding, successful/denied stream admission, narrow grant ancestry, permission expiry/revocation, cancellation, explicit renewal, same-principal versus distinct-agent attribution, and constrained receiving/sending topology. Exercise malformed IPC, path/socket replacement and size bounds at the adapter boundary. Preserve genuine transport outcomes and exact source identities; a fake transport test cannot establish this integration.
