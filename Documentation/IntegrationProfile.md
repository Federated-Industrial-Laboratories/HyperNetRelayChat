# HRC transport authority and federation profile

Draft 1, 31 October 2026. [Protocol proposal](ProtocolPermissions.md) · [Released HyperNet contract](HyperNetContract.md)

This design refines the current-authority, privacy and remote-actor boundaries. Sections labelled **required addition** describe interfaces that HyperNet 0.9.1 does not expose. They are implementation dependencies, not claims about the released SDK. The accepted pilot and history defaults in the product plan remain unchanged.

## 1. Existing authority semantics

Core already performs fresh quorum `Stream::Permit` reads for an exact admitted session. Only that stream's registered route endpoint can request the read. The evaluator checks the session generation and open state, original caller capability, service, route and current governance. A service owner cannot replace the endpoint requester. `Inspect` and the caller's slot `Lookup` serve different purposes. [Permit evaluation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Authority/Domains/AuthorityStreamsEvaluation.rs)

The route runtime uses these reads to renew protected transport writes. Its fresh read path verifies quorum evidence, challenges, context and retained floors. A fresh read does not append an HRC message to authority history or prevent the next authority change. [Read verification](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Routing/RouteAuthorityRead.rs) · [Stream renewal](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Routing/ApplicationStreamRuntime.rs)

The current HyperNet contract bounds ordinary stream-control challenges to 5,000 ms end to end. Committed revocation prevents new permits; a permit issued before an unknown revocation retains only its original remaining lifetime. Known local withdrawal stops further use immediately. HRC inherits this finite freshness model. It does not promise that independent authority and database commits are globally atomic. The 15-second Page-federation maintenance exception does not apply to HRC. [Authority time and revocation contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/AuthorityContract.md)

HRC's own pause, revocation, membership and agreement controls remain strictly ordered by the receiving home service. Acknowledged HRC revocation rejects effects ordered after it. This is a stronger local ordering guarantee than observing a remote HyperNet revocation, and the UI must distinguish them.

## 2. Fresh checks for already-received work

The released companion exposes `connect`, `accept`, `status` and `cancel`. Its connection list and original peer context are not fresh authority reads. Socket liveness, an HRC ping, an old admission proof and a status error string cannot authorise an action waiting in an HRC queue.

**Required addition: a bounded, action-bound check for an exact active incoming connection.** Keep the existing Core endpoint as the authority requester and the companion as the verification boundary. Never give HRC an endpoint signing key, arbitrary authority-query facility or independent copy of HyperNet governance.

| Request or result | Required meaning |
| --- | --- |
| Local connection ID | Resolved by the companion to its current incoming binding and exact session generation; not a payload-selected principal or arbitrary session |
| Nonce | Fresh 32-byte random request nonce, bound to the response and discarded after completion |
| Action digest | SHA-256 of the exact immutable HRC Action bytes; forwarded as opaque correlation data, not interpreted as chat authority by Core |
| Deadline | A caller deadline capped by the remaining connection/credential lifetime and the ordinary five-second end-to-end limit |
| Permitted result | Endpoint-authenticated binding, network/incarnation, service, session/generation, original principal/grant, nonce, action digest, verified authority position and conservative expiry |
| Denied result | Authenticated refusal from fresh evaluation, without inventing a more specific cause than the evaluator provides |
| Unavailable/expired result | No usable current proof; no authority is inferred from an earlier permit or an unavailable quorum |
| Connection closed/replaced | The original check is unusable; a new stream requires a new check and current actor binding |

The endpoint must perform a new `Stream::Permit` read after the request arrives. Returning a cached write-gate deadline is insufficient. Its assertion binds the exact binding/session and request. The companion verifies the endpoint signature and its local binding, then returns a validated type to HRC. Old replies, changed action content, another connection ID or a new generation fail correlation.

Use a separate bounded local control exchange between the endpoint and companion. Do not insert control messages into opaque application bytes. Preserve Core's existing mapped ingress-directory isolation; it must not gain access to the user's native control socket, profile or unrelated files. The local control connection needs authenticated endpoint binding, private path/peer checks, cancellation, bounded concurrency and teardown with the owning binding. Its exact framing and lifecycle require upstream implementation design before the addition is usable.

Expose the feature through a versioned companion contract with explicit capabilities, for example `current-session-check/1` and `connection-privacy/1`. Preserve the existing 16,384-byte control-frame ceiling. The existing version-1 SDK can continue serving its documented clients; an HRC service requiring fresh effect checks must refuse startup against a companion lacking that capability. It must not silently fall back to repeated `status` calls.

The companion/HRC boundary uses an absolute local boot-clock deadline, scoped to the current boot and companion instance. It must conservatively account for the entire request and response interval, endpoint proof expiry and clock uncertainty. A relative lifetime must never be restarted when a response is copied or forwarded. Restart invalidates all pending checks. Foreign assertions use the separate rule in section 5; a boot-clock number from another host is not comparable.

Proposed admission bounds are one pending check per connection and four across a companion, charged to the original actor and service. They require measurement against the accepted pilot. Control traffic needs its own bounded work budget; reserving it does not bypass actor, represented-account or service limits.

## 3. HRC authorisation and durable outcomes

An operation has separate stages: queued, authorised for evaluation, durably committed, and acknowledged. A fresh HyperNet check is required at the effect boundary, not only at session establishment.

1. Decode bounded input, authenticate the enrolled endpoint and validate the immutable action. Resolve an existing operation outcome before attempting a new effect.
2. When the queued action is eligible to run, request its fresh connection check. Do this outside the home commit critical section so a slow quorum does not block unrelated room controls.
3. Enter the home's serial effect order. Check that the evidence is still usable and bound to this action, connection and generation. Recheck current HRC endpoint, represented-account, grant, approval, room, agreement and epoch revisions. Known closure or restrictive state invalidates the check.
4. Choose the HRC authorisation point in that order, then commit the event, outcome and required state atomically under the selected storage durability policy. No later HRC control can overtake an in-progress commit and still claim that it preceded the effect.
5. Publish and acknowledge only the durable outcome. Failure or uncertain completion follows `Operation.Resolve`; it does not trigger a fresh effect automatically.

The authorisation point is distinct from physical storage completion. An unknown HyperNet revocation after a valid check can race with this operation within the original bound. A slow storage operation can finish after that bound: do not relabel an existing durable event as rejected or claim that a timeout proved no effect. Retain its actual authorisation evidence and outcome, stop new work while storage health is uncertain, and resolve it after recovery. A proposed operation that has not crossed the authorisation point must obtain a new check if its proof expires.

This ordering does not confer a durable right to replay work after restart. Recovery may reveal an already committed result; new effects require fresh permission. If a storage failure makes the existence of a commit uncertain, report outcome unknown until the database can establish the result. The storage design must also prevent an old backup from recreating a still-retryable effect.

HRC control acknowledgement is precise: an acknowledged pause/revoke means every earlier operation has either reached its recorded outcome or is durably fenced under a defined recovery state, and no later operation can use the removed permission. The first implementation should fail closed if it cannot establish that boundary, rather than acknowledge a control while an unfenced older commit can still complete.

## 4. Directional privacy evidence

Application streams already invoke Suite's relay connector. It connects to the relay, admits the transit voucher and establishes inner endpoint TLS before application handoff. `Organisation` and `Independent` are assurance profiles, not a direct-Internet switch. Independent assurance checks distinct declared operator keys and domains; it does not prove actual noncollusion. [Companion connector](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Applications/ApplicationStreamsAgent.rs) · [Route connector](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Routing/RouteConnector.rs) · [Privacy guarantees](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/PrivateRoutes.md)

**Required addition: a connection-bound privacy description with explicit evidence provenance.** Saved profile labels alone are insufficient. A retained voucher may avoid a new profile lookup during preparation, so the implementation must bind declarations to verified profiles and state when their evidence was evaluated. [Preparation path](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Applications/ApplicationStreamsClient.rs)

| Property | Outgoing connection | Incoming connection |
| --- | --- | --- |
| Transport protection | Locally verified relay TLS and endpoint TLS; exact negotiated version | Endpoint-attested protection of the arriving application channel |
| Selected privacy minimum | Bound local profile plus stricter bootstrap minimum | Not inferable from a remote client's claim |
| Relay path | Locally observed successful relay connection and endpoint admission | Requires endpoint-side arrival evidence; otherwise unknown |
| Declared separation | Exact verified relay/destination profiles and their operator/domain declarations | Only if those profiles are bound to the endpoint's verified arrival path |
| HRC message encryption | Determined separately by the room's validated crypto state | Same rule; transport TLS does not establish E2EE |

A public endpoint (`mode2`) accepts inner TLS directly and its existing application proof does not bind a transit voucher. Consequently, incoming peer context alone cannot prove that a remote client used a relay. This does not change the supported Suite client's enforced outgoing route. [Endpoint paths](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Routing/RouteRuntime.rs) · [Application proof and binding](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Authority/Domains/ApplicationStreamBinding.rs)

A deployment requiring destination-verifiable relay arrival can use an attached endpoint (`mode3`), which has no public listener and authenticates its pinned relay attachment. Extend the signed local context with the endpoint mode and the exact verified arrival/profile references. That evidence establishes arrival through the approved attachment, not origin anonymity, actual operator independence or the full path of a federated participant. A public endpoint requiring equivalent assurance needs a separate relay-authenticated delivery binding; it cannot substitute an IP check or caller-supplied relay ID.

The ordinary HRC display describes **this connection**: selected minimum, verified transport, observed relay mode, declared separation and evidence status. Unknown is a visible value. Do not infer whole-room or whole-federation privacy from one leg. A policy requiring unavailable evidence refuses the operation or room admission. Missing evidence never weakens a selected minimum.

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

The home bounds the full challenge round trip by at most five seconds on its own boot clock. It also applies the earliest valid source, agreement, destination and credential expiry, conservatively translated under the accepted clock-health model. Forwarding never starts a new source permission lifetime. If a safe expiry cannot be established, the request fails unavailable. The origin attestor is trusted for its source check; a signed foreign timestamp alone is insufficient. The final signature schema and clock conversion must make this inherited bound explicit.

This profile inherits HyperNet's bounded unknown-revocation race. HRC-owned grants are instead checked at their receiving home. Agreement withdrawal immediately stops local new exchange and requests a durable home barrier; the UI distinguishes requested from acknowledged withdrawal. No disconnected network can claim that the other home has already stopped. Encrypted rooms block new sends until their required removal transition is validated.

## 6. Signature and representation candidate

A concrete candidate for the signed HRC objects is deterministic CBOR with COSE_Sign1 and a single explicit Ed25519 algorithm. This is an engineering candidate, not a new cryptographic construction or a final wire assignment. CBOR supplies a deterministic encoding profile; COSE supplies the standard signed structure. RFC 9864 assigns the fully specified Ed25519 COSE algorithm value `-19`, avoiding the deprecated polymorphic `EdDSA` identifier. [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1) · [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2) · [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2)

For this candidate, require definite lengths, shortest integer/length encoding, deterministic key order and rejection of duplicate keys, trailing data, malformed UTF-8 and unsupported types. Preserve exact signed payload bytes; never normalise text or decode/re-encode it into a different signature input. No floats, compression or arbitrary nested tags are needed in the first profile. Bounds apply to the outer envelope, every embedded object and their combined decode depth and size.

Specify protected algorithm, role/content type and key identifier; require an empty unprotected-header map and attached payload. Bind a distinct HRC protocol/version and object role in each payload. A key identifier is only a lookup hint into an already accepted role/key binding, never evidence of trust. Gateway, endpoint, origin-attestor and administrative signatures are not interchangeable. COSE signs the standard signature structure rather than an ad hoc concatenation of fields. Library selection, strict decoding, exact field labels, extension rules and cross-implementation vectors remain necessary before this candidate becomes the wire contract.

HyperNet's existing signed objects remain opaque and retain their own verified representation. Do not rewrap them as HRC authority or reinterpret their action numbers. The HRC profile uses separate application keys and domains; it never borrows endpoint or authority private keys.

## 7. Boundaries, delivery and verification

| Change | Authoritative owner | Dependency and evidence |
| --- | --- | --- |
| Fresh endpoint-to-companion checks | Core application-stream runtime and existing route authority reader; mirrored binding verification and Suite companion/SDK | Exact active-session resolution, fresh reads, deadline propagation, cancellation and bounded control exchange; no new policy action number |
| Verified connection privacy | Route preparation/connector and endpoint arrival binding; Suite handoff | Exact current profile references and directional evidence; retained vouchers and public/attached endpoints tested |
| HRC Rust adapter | A narrow local companion boundary | Private Unix path/peer checks, framing, capabilities, validated incoming/outgoing types, cancellation and refusal translation; no copied HyperNet authority evaluator |
| HRC effect ordering | Conversation/Delegation operation owners and persistence boundary | Fresh action check plus current home state; interrupted durability, timeout and unknown-outcome recovery |
| Federation evidence | HRC agreement, identity and federation owners | Accepted attestor/key roles, immutable Action, bounded challenge table, original expiry, destination rights and home deduplication |
| Presentation | Shared HRC connection/privacy state | Correct live versus historical status, no unverified badge, consistent CLI/TUI/GUI/API outcomes |

Begin with a small upstream companion contract extension and its real installed interoperability checks. Then qualify the HRC adapter and local conversation slice. Federation extends the same operation/permission path after its exact evidence schema is settled. No speculative crate hierarchy, general authority broker or universal event framework is needed.

Meaningful regressions include: withdrawal before and after a fresh check; stale original context; changed action/session/nonce; expiry while queued; process restart; missing quorum or unhealthy clock; storage completion after the check deadline; known closure before authorisation; mode2 versus mode3 incoming evidence; wrong relay/TLS identity; selected-minimum downgrade; stale profile declarations; foreign-origin/key substitution; inherited expiry across forwarding; challenge replay; lost acknowledgement; and withdrawal during partition. Measure fresh-check cost and unaffected-client latency against the accepted stream allocation before claiming supported capacity.

Remaining implementation prerequisites are the exact local control transport and versioned schema, conservative deadline mapping, strict signed-object schema/library validation, storage/recovery design, account recovery authority and MLS lifecycle. These are explicit design work, not placeholder acceptance evidence. Ordinary implementation choices can be resolved from the contracts; changes to owner recovery authority or declared privacy/availability guarantees require an owner decision.
