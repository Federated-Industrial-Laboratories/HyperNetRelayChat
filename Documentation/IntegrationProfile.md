# HRC transport authority and federation profile

Revision 5, 5 November 2026. [Protocol contract](ProtocolPermissions.md) · [HyperNet contract map](HyperNetContract.md)

This profile describes the implemented current-authority, privacy and remote-actor
boundaries against the checked Core 0.10.2 and Suite 0.10.1 release candidates.
Source links pin `670b3424e8ec903a72122adada19499a870811a4` and
`a804ebd50a069659de053d866ba96b33ee8f76c0`, respectively. These are inspected
candidate revisions, not a publication or complete native qualification claim.
The HRC adapter and smallest local conversation retain their separate
representative integration evidence. The accepted pilot and history defaults
remain unchanged; the full release gates remain open.

## 1. Existing authority semantics

Core already performs fresh quorum `Stream::Permit` reads for an exact admitted session. Only that stream's registered route endpoint can request the read. The evaluator checks the session generation and open state, original caller capability, service, route and current governance. A service owner cannot replace the endpoint requester. `Inspect` and the caller's slot `Lookup` serve different purposes. [Permit evaluation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Authority/Domains/AuthorityStreamsEvaluation.rs)

The route runtime uses these reads to renew protected transport writes. Its fresh read path verifies quorum evidence, challenges, context and retained floors. A fresh read does not append an HRC message to authority history or prevent the next authority change. [Read verification](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Routing/RouteAuthorityRead.rs) · [Stream renewal](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Routing/ApplicationStreamRuntime.rs)

The current HyperNet contract bounds ordinary stream-control challenges to 5,000 ms end to end. Committed revocation prevents new permits; a permit issued before an unknown revocation retains only its original remaining lifetime. Known local withdrawal stops further use immediately. HRC inherits this finite freshness model. It does not promise that independent authority and database commits are globally atomic. The 15-second Page-federation maintenance exception does not apply to HRC. [Authority time and revocation contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Documentation/AuthorityContract.md)

HRC's own pause, revocation, membership and agreement controls remain strictly ordered by the receiving home service. Acknowledged HRC revocation rejects effects ordered after it. This is a stronger local ordering guarantee than observing a remote HyperNet revocation, and the UI must distinguish them.

## 2. Fresh checks for already-received work

The version-2 companion exposes `checkAuthority` alongside `connect`, `accept`, `status` and `cancel`. Its connection list and original peer context remain distinct from a fresh authority read. Socket liveness, an HRC ping, old admission evidence and status error prose cannot authorise an action waiting in an HRC queue.

**Implemented upstream contract: `checkAuthority-v2` for an exact active incoming connection.** Core's existing endpoint remains the authority requester and the companion remains the local verification boundary. HRC receives neither an endpoint signing key nor an arbitrary authority-query facility. [Core check contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Documentation/ApplicationChecks.md) · [Suite API](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/a804ebd50a069659de053d866ba96b33ee8f76c0/Documentation/ApplicationContext.md)

| Request or result | Implemented meaning and HRC obligation |
| --- | --- |
| Local connection ID | Companion resolves the active incoming binding and complete kind-173 session reference; HRC cannot supply another principal, grant or session |
| Nonce | Fresh nonzero 32-byte random nonce, lowercase hexadecimal in local IPC, bound to the exact response |
| Action digest | Nonzero 32-byte digest of immutable application content; HRC selects SHA-256 of its final canonical Action bytes; Core treats it as opaque correlation |
| Caller deadline | Required 100-5,000 ms wait, SDK default 1,000; companion dispatch creates an absolute boot-clock bound and the caller separately preserves its earlier call-start deadline |
| Permitted result | Verified endpoint receipt correlates the exact request, session/generation, instances, control generation and boot; certified observation matches the accepted peer's network/incarnation; HRC retains its already verified principal/grant binding |
| Denied result | Fresh certified refusal with structured code and original observation position/lifetime; it does not establish an HRC-specific refusal reason |
| Unavailable/expired/notActive | No usable current authority observation; no permission is inferred from old context or a missing quorum |
| Connection closed/replaced | Known closure, cancellation or control-generation change invalidates use; a new stream needs a new check and current actor binding |

The endpoint performs a new `Stream::Permit` read after the request arrives. It verifies certified authority, rechecks current gates, clock health and exact forwarding/session liveness, and signs a receipt bound to the full request. The companion verifies the signature and accepted binding before exposing typed results. Only `permitted` and `denied` carry certified observation metadata. Neither is a portable quorum proof or a reusable application grant. Changed content, another connection or a new control generation cannot reuse it.

The separate endpoint-initiated `Ingress/Checks.sock` channel preserves opaque application bytes and mapped ingress-directory isolation. The endpoint sees `/Application/Checks.sock`, not the user's native command socket, profile or unrelated files. A signed challenge/ready exchange binds the accepted binding digest, nonce, companion/endpoint instances, control generation and verified host boot. Both sides require zero monotonic/boot-time namespace offsets. Framing retains the 16,384-byte ceiling; the endpoint control schema uses its existing canonical TrustWire signed envelope, while caller IPC uses versioned JSON. HRC implements the caller boundary, not a second endpoint verifier. [Canonical control schema](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Authority/Domains/ApplicationStreamControl.rs)

Capability status separates API support, authenticated endpoint-channel readiness and eligibility of an exact accepted incoming connection. Outgoing streams cannot use a receiving-end check. Version-1 payload clients retain their contract, but an HRC service requiring fresh effect checks refuses a companion without `checkAuthority-v2`. A temporarily unready channel yields unavailable effects; repeated `status` calls are not a fallback.

The companion deadline crosses Core's queue and authority read unchanged. Its authority challenge has a separate immutable ceiling at the original companion start plus 5,000 ms, decreasing with queue time even for a one-second caller wait. This supports the authority uncertainty window without extending transport waiting or permitting a late result. A renewable clock observation may be refreshed during the read; the delivered receipt is clipped by current clock validity, caller/session bounds, consent/gates and certified expiry. HRC must preserve the minimum of its original call deadline and the verified receipt's `notAfterBootMs`, never restart a relative lifetime, and invalidate known closure/control changes. Restart invalidates pending work. Foreign assertions use section 5; another host's boot-clock number is not comparable. [SDK result lifetime](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/a804ebd50a069659de053d866ba96b33ee8f76c0/SDK/hypernet_streams/context.py)

The candidates allow one pending check per stream and four total checks across
queued and in-flight work, including cancellation draining after reconnect.
Suite pipelines requests with exact reply correlation. Core overlaps immutable
network exchanges while one actor retains all challenge, current-state and
durable-publication ownership. Finite cohorts prepare their captured gates before
issue; unused slots can accept already-current reads only before the first
completion, within four total admissions and the fixed initial round end. No
readiness/lifecycle mutation occurs while that round is pending. Admission also
requires the existing endpoint, stream and round-tail headroom; otherwise the
original request waits for normal preparation without extending its end. A deferred
queue head retains its original permit, and lifecycle work receives a fair turn
after drain. The [contract map](HyperNetContract.md) gives the complete bounds.

Established-stream background renewal can start a finite cohort and share the
same four immutable exchange slots with already-current checks. Its completion
must still match the exact open stream and current authority before the actor
installs stream permission. It produces no action receipt. Endpoint renewal,
unestablished-stream renewal and authority-changing cleanup remain exclusive.

The native Suite authority connector uses two independently admitted sessions to
the same pinned endpoint and replica, with at most sixteen queued exchanges.
Each session keeps its original route budget. Relay and authority policies must
allow both connections alongside application traffic; admission failure remains
explicit. These authority sessions are separate from the companion's application
stream slots. Signed request and read identifiers retain their original binding
across the two sessions; cleanup cannot create a new admission.

The channel consumes no application connection slot. HRC admits four concurrent
exchanges within its existing 32-caller queue and charges work to its service and
actor budgets. Original deadlines, current gates and final authority checks still
apply. Neither concurrency nor earlier interoperability establishes the accepted
pilot's latency or fairness.

Preparation errors remain distinct from these authority dispositions. Suite
reports local `Capacity`, accept or tagged transport `Timeout`, and tagged setup
transport `Closed`; other planning/validation failures remain `Refused`. HRC must
not treat generic `Refused` as a certified denial or infer safe retry from error
prose. A lost connection alone cannot establish whether an earlier HRC effect
committed.

## 3. HRC authorisation and durable outcomes

An operation has separate stages: queued, authorised for evaluation, durably committed, and acknowledged. A fresh HyperNet check is required at the effect boundary, not only at session establishment.

1. Decode bounded input, authenticate the enrolled endpoint and validate the immutable action. Resolve an existing operation outcome before attempting a new effect.
2. When the queued action is eligible to run, request its fresh connection check. Do this outside the home commit critical section so a slow quorum does not block unrelated room controls.
3. Enter the home's serial effect order. Check that the evidence is still usable and bound to this action, connection and generation. Recheck current HRC endpoint, represented-account, grant, approval, room, agreement and epoch revisions. Known closure or restrictive state invalidates the check.
4. The guarded home transaction performs its final current-permission check at the serial authorisation point, then commits the event, outcome and required state atomically under the selected storage durability policy. No later HRC control can overtake an in-progress commit and still claim that it preceded the effect.
5. Publish and acknowledge only the durable outcome. Failure or uncertain completion follows `Operation.Resolve`; it does not trigger a fresh effect automatically.

The authorisation point is distinct from physical storage completion. An unknown HyperNet revocation after a valid check can race with this operation within the original bound. A slow storage operation can finish after that bound: do not relabel an existing durable event as rejected or claim that a timeout proved no effect. Retain its actual authorisation evidence and outcome, stop new work while storage health is uncertain, and resolve it after recovery. A proposed operation that has not crossed the authorisation point must obtain a new check if its proof expires.

This ordering does not confer a durable right to replay work after restart. Recovery may reveal an already committed result; new effects require fresh permission. If a storage failure makes the existence of a commit uncertain, report outcome unknown until the database can establish the result. The storage design must also prevent an old backup from recreating a still-retryable effect.

HRC control acknowledgement is precise: an acknowledged pause/revoke means every earlier operation has either reached its recorded outcome or is durably fenced under a defined recovery state, and no later operation can use the removed permission. The implemented guarded transaction fails closed when it cannot establish that boundary; a control cannot acknowledge precedence over an older unfenced commit that can still complete.

## 4. Directional privacy evidence

Application streams already invoke Suite's relay connector. It connects to the relay, admits the transit voucher and establishes inner endpoint TLS before application handoff. `Organisation` and `Independent` are assurance profiles, not a direct-Internet switch. Independent assurance checks distinct declared operator keys and domains; it does not prove actual noncollusion. [Companion connector](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/a804ebd50a069659de053d866ba96b33ee8f76c0/Source/Applications/ApplicationStreamsAgent.rs) · [Route connector](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/a804ebd50a069659de053d866ba96b33ee8f76c0/Source/Routing/RouteConnector.rs) · [Privacy guarantees](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Documentation/PrivateRoutes.md)

**Implemented upstream contract: version-2 directional privacy with explicit evidence provenance.** Saved profile labels remain insufficient. Outgoing metadata records the actual nested TLS path and configured route settings. A matching certified destination lookup contributes `certifiedEndpointProfile`; `certifiedRelayProfile` remains null without corresponding evidence. A retained voucher or a saved profile does not establish new currentness. [Preparation path](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/a804ebd50a069659de053d866ba96b33ee8f76c0/Source/Applications/ApplicationStreamsClient.rs)

| Property | Outgoing connection | Incoming connection |
| --- | --- | --- |
| Transport protection | Observed authenticated nested TLS 1.3 through the relay and final service | Exact-session endpoint-attested final-service TLS 1.3; unknown until that observation is available |
| Selected privacy minimum | Selected/configured local route settings, enforced during route preparation | Not inferable from a remote client's claim |
| Relay path | Observed successful nested relay/final-service connection | Approved attachment for attested mode 3; upstream transit remains unknown for public mode 2 |
| Profile provenance and separation | Matching certified destination-profile reference when available; no automatic certified relay-profile or physical-independence claim | Attested attachment service/profile digest; no current-profile or physical-independence claim |
| HRC message encryption | Determined separately by the room's validated crypto state | Same rule; transport TLS does not establish E2EE |

A public endpoint (`mode2`) accepts inner TLS directly and its existing application proof does not bind a transit voucher. Consequently, incoming peer context alone cannot prove that a remote client used a relay. This does not change the supported Suite client's enforced outgoing route. [Endpoint paths](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Routing/RouteRuntime.rs) · [Application proof and binding](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/670b3424e8ec903a72122adada19499a870811a4/Source/Authority/Domains/ApplicationStreamBinding.rs)

A deployment requiring destination-verifiable relay arrival can use an attached endpoint (`mode3`), which has no public listener and authenticates its pinned relay attachment. Its exact-session receipt attests the endpoint mode, approved attachment, relay service and profile digest. The inspected Suite candidate returns explicit unknown arrival privacy from version-2 accept without an optional query before payload handoff. HRC's fresh exact-action check supplies the current session evidence; acceptance and retained privacy never authorise an application effect. Absent or invalidated evidence stays unknown. This establishes arrival through the approved attachment, not origin anonymity, physical operator independence, current profile validity or the full path of a federated participant. A public endpoint requiring equivalent assurance still needs a separate supported relay-authenticated delivery contract; it cannot substitute an IP check or caller-supplied relay ID.

The ordinary HRC display describes **this connection**: selected minimum, verified transport, observed relay mode, supported profile provenance and evidence status. Any operator-separation declaration must be identified as a declaration with its actual evidence; the current interface sets `physicalIndependenceVerified` and `profileCurrentnessAsserted` to false. Unknown is a visible value. Do not infer whole-room or whole-federation privacy from one leg. A policy requiring unavailable evidence refuses the operation or room admission. Missing evidence never weakens a selected minimum.

Expose coarse properties and opaque evidence references in routine status. Detailed operator declarations are deliberate inspection data. Do not include addresses, local paths, raw profiles or private key material in ordinary HRC errors or diagnostics. A closed connection's previous description is historical, not an active privacy badge.

## 5. Bilateral federation evidence

Keep the one-home, two-network profile. Each direction uses a source-side origin HRC service and a separately admitted destination gateway principal. The origin service attests its own enrolled endpoint and current transport observation; the destination gateway only carries the envelope. The home service owns room order, delegated grants and destination restrictions.

An agreement binds both network/incarnation identities, exact HRC service identities, gateways and signing keys, the accepted origin attestor, rooms, remote enrolment rules, moderator scope, history/retention, crypto/privacy mode, expiry and withdrawal. Both administrations accept the same immutable agreement bytes through authenticated local administration. Activation requires independent destination HyperNet admission; a signed agreement cannot create that admission. Trust in the origin attestor is explicit and limited to source-side facts.

| Object | Required bound content and validation |
| --- | --- |
| Endpoint binding | Origin network/incarnation, account, endpoint, authentication public key, accepted transport principal, enrolment generation and validity; attested by the agreement's pinned origin service |
| Original Action | Home service, room/target, operation and retry-window IDs, actor mode, origin account/network/incarnation, endpoint and enrolment generation, exact endpoint-binding digest and federation agreement ID/revision/digest, represented account and exact grant when delegated, immutable body, expected revisions and approval reference |
| Home challenge | Fresh random ID, home and origin service, exact agreement revision, gateway identity, Action digest and a home-owned expiry; one outstanding challenge per admitted operation |
| Origin admission assertion | Exact challenge and Action digest, endpoint binding generation, source transport/session generation, current check result and original evidence expiry; signed by the accepted origin attestor |
| Forwarded envelope | Original signed Action, endpoint binding, exact agreement reference, challenge and origin assertion; no authority comes from the envelope's transport fields alone |
| Home outcome | Original operation ID, exact Action digest, committed event or refusal and home ordering position; uncertain replies resolve against this home |

The actor signs the immutable Action with its own enrolled HRC endpoint key. The origin attestor checks that signature and transport binding, obtains a fresh source check after receiving the home challenge, and signs the bounded assertion. The destination home verifies both signatures against separately accepted roles, the gateway's own current admission, challenge, agreement and current HRC rights. A gateway cannot become the original actor by changing the envelope kind.

Require exact comparisons of home, origin account/network/incarnation, room, action, endpoint/enrolment generation, binding digest, represented account, grant and agreement ID/revision/digest between the signed Action and the corresponding objects. The surrounding attestation cannot supply a different interpretation of an omitted signed identity or agreement field. A changed binding or agreement requires a new Action and any new exact approval; resolve the previous operation before deciding whether another effect is appropriate. The home challenge table is bounded and binds the authenticated requesting gateway; challenges are not issued to unauthenticated input. Denied, expired, duplicate and cancelled attempts consume bounded work. A new challenge may accompany an identical retry, but cannot change its immutable Action or extend the service-issued retry window.

Challenge consumption and the operation outcome must be atomic with the home commit. An existing result for the same actor and Action can be returned without recreating an effect; changing content under the same ID conflicts. Pending challenge state is discarded on restart, and old challenges are rejected. Committed outcomes survive according to the accepted deduplication policy. Foreign event copies never become a second send operation, and the first profile performs no onward forwarding.

The home bounds the full challenge round trip by at most five seconds on its own boot clock. It also applies the earliest valid source, agreement, destination and credential expiry, conservatively translated under the accepted clock-health model. Forwarding never starts a new source permission lifetime. If a safe expiry cannot be established, the request fails unavailable. The origin attestor is trusted for its source check; a signed foreign timestamp alone is insufficient. The [federation runtime](FederationRuntime.md) defines the signed schema and conservative clock conversion that preserve this inherited bound.

This profile inherits HyperNet's bounded unknown-revocation race. HRC-owned grants are instead checked at their receiving home. Agreement withdrawal immediately stops local new exchange and requests a durable home barrier; the UI distinguishes requested from acknowledged withdrawal. No disconnected network can claim that the other home has already stopped. Encrypted rooms block new sends until their required removal transition is validated.

## 6. Signature and representation

The [wire specification](WireProtocol.md) selects deterministic CBOR with COSE_Sign1 and a single explicit Ed25519 algorithm for HRC signed objects. It defines the exact assignments and role bindings. CBOR supplies a deterministic encoding profile; COSE supplies the standard signed structure. RFC 9864 assigns the fully specified Ed25519 COSE algorithm value `-19`, avoiding the deprecated polymorphic `EdDSA` identifier. [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) · [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2) · [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2)

The profile requires definite lengths, shortest integer/length encoding, deterministic key order and rejection of duplicate keys, trailing data, malformed UTF-8 and unsupported types. Preserve exact signed payload bytes; never normalise text or decode/re-encode it into a different signature input. No floats, compression or arbitrary nested tags are needed in the first profile. Bounds apply to the outer envelope, every embedded object and their combined decode depth and size.

Specify protected algorithm, role/content type and key identifier; require an empty unprotected-header map and attached payload. Bind a distinct HRC protocol/version and object role in each payload. A key identifier is only a lookup hint into an already accepted role/key binding, never evidence of trust. Gateway, endpoint, origin-attestor and administrative signatures are not interchangeable. COSE signs the standard signature structure rather than an ad hoc concatenation of fields. The wire specification and maintained vectors define library use, strict decoding, exact field labels and extension rules. Interoperability claims require the corresponding implementation evidence.

HyperNet's existing signed objects remain opaque and retain their own verified representation. Do not rewrap them as HRC authority or reinterpret their action numbers. The HRC profile uses separate application keys and domains; it never borrows endpoint or authority private keys.

## 7. Boundaries, delivery and verification

| Change | Authoritative owner | Dependency and evidence |
| --- | --- | --- |
| Fresh endpoint-to-companion checks | Core application-stream runtime and existing route authority reader; mirrored binding verification and Suite companion/SDK | Implemented in the checked candidates; earlier 0.10.0 Linux evidence covers exact session/action/nonce, default deadline, expiry/cancellation and certified denial after revocation on those historical artifacts; current candidate capacity remains unqualified |
| Directional connection privacy | Route preparation/connector and endpoint arrival binding; Suite handoff | Implemented outgoing nested-TLS and incoming attachment provenance; unavailable or unproven path/profile facts remain unknown; no independence/currentness assertion |
| HRC Rust adapter | A narrow local companion boundary | Private Unix path/peer checks, framing, capabilities, validated incoming/outgoing types, cancellation and refusal translation; no copied HyperNet authority evaluator |
| HRC effect ordering | Conversation/Delegation operation owners and persistence boundary | Fresh action check plus current home state; interrupted durability, timeout and unknown-outcome recovery |
| Federation evidence | HRC agreement, identity and federation owners | Implemented attestor/key roles, immutable Action, bounded challenge table, original expiry, destination rights and home deduplication; native origin, delegation, encrypted recovery and withdrawal workflows pass on two independently administered networks on one host |
| Presentation | Shared HRC connection/privacy state | Correct live versus historical status, no unverified badge, consistent CLI/TUI/GUI/API outcomes |

The companion extension and HRC runtime are implemented. Source-bound native checks cover the local conversation and interfaces, encrypted direct and private-group conversations, bilateral federation, and stopped same-schema upgrade with an uncertain committed send. Federation qualification uses two independently administered networks on one host; it does not establish independent host-failure recovery. These results retain their original artifact identities. Current pilot-load qualification and final publication remain pending. Federation extends the same operation and permission path under the selected [runtime contract](FederationRuntime.md).

Meaningful regressions include: withdrawal before and after a fresh check; stale original context; changed action/session/nonce; expiry while queued; process restart; missing quorum or unhealthy clock; storage completion after the check deadline; known closure before authorisation; mode2 versus mode3 incoming evidence; wrong relay/TLS identity; selected-minimum downgrade; stale profile declarations; foreign-origin/key substitution; inherited expiry across forwarding; challenge replay; lost acknowledgement; and withdrawal during partition. Measure fresh-check cost and unaffected-client latency against the accepted stream allocation before claiming supported capacity.

The upstream boundary supplies fresh checks and typed context; HRC owns application permissions, atomic storage ordering, cross-host freshness and foreign actor authentication. The [state specification](StateAndRecovery.md), [wire protocol](WireProtocol.md), [clock boundary](ClockAndOrdering.md), [MLS runtime](CryptoRuntime.md) and [text profile](TextAndSearch.md) define the selected implementation contracts. Current numerical load qualification and final release delivery remain open. Changes to owner recovery authority or declared privacy/availability guarantees require an owner decision; ordinary implementation details can be resolved within these contracts.
