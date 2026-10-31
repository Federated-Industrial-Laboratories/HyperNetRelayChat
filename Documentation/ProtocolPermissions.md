# HRC protocol and permission proposal

Draft 2, 31 October 2026. [Product plan](ProductPlan.md) · [HyperNet contract](HyperNetContract.md)

This document proposes operation semantics and design decisions for review. It is not an implemented protocol, a final wire specification, or qualification evidence. The product plan and its scope amendment remain authoritative. Linux first, service-readable community rooms, encrypted confidential direct conversations and encrypted private groups are confirmed scope. The pilot allocation, retention/retry defaults and future-only encrypted history default were accepted on 31 October 2026; the product plan records their exact scope. Other values labelled **proposed** still require design agreement and measurement before implementation commitments.

## 1. Trust and ownership

HyperNet authenticates admitted application transport and enforces its current stream authority. HRC owns account bindings, room rights, delegation, ordering and storage. A verified stream principal is not proof that a human typed a message. Network transport failure never enables direct Internet fallback. Missing privacy evidence produces an explicit unknown state, never an inferred protection badge.

Each room has one designated home HRC service. That service owns the authoritative room sequence and evaluates effects against its current state. Federation adds explicit remote admission and restrictions; it does not create multi-writer history, cluster replication, leader election or failover. Home unavailability preserves permitted drafts and retained copies without claiming delivery.

## 2. Identifiers and validated types

| Type | Proposed meaning and validation |
| --- | --- |
| `NetworkIdentity` | Exact HyperNet network and incarnation; accepted independently. A new incarnation is a new identity decision. |
| `ServiceIdentity` | Network identity plus stable HRC service ID. Physical host addresses are not identity. Recovery must preserve the service's authenticated state or create an explicitly new identity. |
| `AccountId`, `RoomId` | Origin network identity plus opaque random local ID; room also binds its home service. Nicknames and room labels are changeable metadata. |
| `EndpointId` | An HRC device or agent endpoint, its own authentication key, account/operator binding and exact permitted HyperNet principal bindings. Keys are not shared between a human device and an agent. |
| `VerifiedTransport` | Constructed only by the trusted companion adapter after local socket and context validation. Never deserialised from an HRC payload. |
| `DirectActor` | Account and authenticated endpoint, whose enrolled transport binding matches `VerifiedTransport`. No represented-account or delegation field is allowed. |
| `IndependentAgent` | Agent account, authenticated endpoint and current operator binding. A human account label cannot replace this type. |
| `DelegatedActor` | Acting agent endpoint, represented account and exact home-service grant ID/generation. The service derives this from verified bindings and current grant state. |
| `RemoteActor` | Origin account/endpoint, accepted origin evidence, original action authentication and the exact federation agreement. Construction requires the checks in section 8. |
| `OperationId` | Home service, service-issued retry-window ID and random client operation ID. Reuse with different immutable action bytes is a conflict. |
| `EventId` | Home service and immutable event identity; it retains room identity and ordering position across reconnects. It is not a wall-clock timestamp. |

Endpoint enrolment requires an already authorised account controller, proof of possession of the new endpoint key, the exact transport-principal binding and explicit confirmation. Account classification, device enrolment and an agent's right to act are separate records. First-account enrolment and recovery use an explicit administrator/invitation policy, not an unauthenticated nickname claim; the final recovery authority remains an open decision.

## 3. Sessions and operation envelope

After HyperNet handoff, `Session.Open` proposes a protocol version and bounded capabilities. The server verifies its expected network/service context and returns negotiated limits, session identity, retry-window validity and clock/permission status that it can actually establish. `Session.Resume` creates a fresh session after current checks; it cannot restore expired transport authority. The proposed application protocol label is `hrc/1`; it is distinct from HyperNet transport protocol 7.

Every effect carries an `OperationId`, operation kind, exact target, actor mode, immutable content, relevant expected revisions and optional approval reference. The authenticated endpoint is bound to this session. The server rejects payload attempts to substitute actor, home service or origin. The canonical Action encoding and signature envelope remain open; no signatures or hashes can be interoperable until their exact bytes, domain separation and extension rules are specified.

Unknown critical capabilities or fields fail with `UnsupportedVersion` or `UnsupportedFeature`. Optional ignorable fields are explicitly enumerated per operation. Capability negotiation cannot remove required permission, privacy or encryption rules. A client that cannot process a room's required encryption/group-policy version cannot join it.

The initial proposal has no compressed application frames. The final wire profile must define exact integer bounds, duplicate-field handling and canonical bytes before signed federation actions or approvals are implemented.

| Operation family | Preconditions and effect | Result and retry contract |
| --- | --- | --- |
| `Session.Open/Resume/Close` | Verified transport, enrolled endpoint, version agreement and current service admission | Fresh session or refusal; closing a stream does not roll back a committed action |
| `Account.SetNickname`, `Presence.Set` | Current account/endpoint rights; identifier and rate checks | Ordered account metadata; presence has finite expiry and separate human/agent entries |
| `Room.Create/Join/Leave/SetTopic` | Current account rights, room mode, invitation/admission and expected room-policy revision | Home-ordered event or explicit conflict; leave removes future delivery eligibility |
| `Message.Send/Reply/Action` | Current membership, sender rights, content bounds and any exact delegation/approval; replies name an accessible event | One committed event or durable rejection; `/msg` and `/whisper` resolve to the same direct-conversation semantics |
| `History.Page`, `Search.Query/Cancel` | Current membership/history window, grant and recipient filter; bounded cursor/query | Current-authorised page or cancellation; cancellation does not promise rollback of already returned content |
| `Events.Subscribe/Resume`, `Unread.Set` | Current room and history access; room-bound cursor; unread belongs to that account | Bounded stream/page; explicit gap or resynchronisation result |
| `Draft.Put/Get/Delete` | Account-local rights; encrypted drafts stay client-local unless an explicit encrypted synchronisation design is adopted | Local durability state; a draft is not accepted or delivered chat |
| `Delegation.Create/Inspect/Pause/Resume/Revoke` | Represented account's authorised controller; exact receiving home service; monotonic grant revision | Durable control result; revoke is terminal and cannot become resume |
| `Approval.Prepare/Approve/Reject` | Grant mode and owner authority; immutable candidate and finite validity | Exact action approval; changed target/content/operation requires a fresh approval |
| `Moderation.Ignore/Mute/Silence/Kick/Ban` | Recipient ownership for ignore/mute; current moderator scope for room restrictions | Attributable bounded record; checks precede delivery/publication as appropriate |
| `Crypto.EnrolEndpoint/PublishKeyPackage/Propose/Commit` | Account/device authorisation, room crypto policy and current epoch | Exact endpoint/epoch transition or conflict; no automatic history grant |
| `Federation.Propose/Accept/Withdraw/Exchange` | Both administrations, independent gateway admissions and exact agreement/evidence | Home-ordered decision; withdrawal reports which destination barrier is confirmed |

`Inspect` responses expose effective operations, rooms, history bounds, expiry, agent mode and pending approvals. They do not substitute for a fresh effect check. CLI structured output, TUI commands, GUI controls and agent APIs call these same domain contracts. `/me`, `/motd`, mentions and completion are typed interaction conveniences, not alternate permission paths.

## 4. Delegation and exact approval

A grant binds owner, agent endpoint/account, receiving home service/network, room IDs or exact recipients, operations, history interval, mode, validity, rate/cost limits and revision. Allowed operations distinguish read, reply, initiate, mark handled and each moderation action. Delegation creation and further delegation are excluded from agent scope. A purpose description is explanatory text; it grants nothing.

Effective permission is the intersection of current transport authority, endpoint binding, represented account rights, grant, room policy, recipient restrictions and federation policy. An agent receives no access through a represented account's ban. Changing to its independent identity does not convert a denied delegated request into success; distinct independent participation still needs independent room admission and applicable ban policy.

| Mode or state | Permitted behaviour |
| --- | --- |
| Draft only | Prepare a local or explicitly authorised owner-visible draft; no conversation send effect |
| Approve before sending | Submit only the immutable action approved by its owner, within remaining grant rights and approval validity |
| Act within scope | Submit permitted actions without repeated owner approval; all effect-time checks remain |
| Active → Paused → Active | Pause rejects subsequent delegated effects; resume uses a new revision and does not automatically submit old queued work |
| Active/Paused → Revoked | Terminal invalidation; restoring access requires a new grant ID |
| Expired | No new effect; renewal is an explicit new grant/revision under the finally selected lifecycle, not inferred consent |

`Approval.Prepare` stores or identifies the complete immutable action, including operation ID, actor/represented identity, grant revision, room/recipient, content bytes, attachments if later supported, expiry and expected policy/epoch. The trusted owner interface renders that exact candidate. `Approve` binds its exact digest and a one-use approval ID; execution atomically consumes it with the outcome. Repeating the same operation returns its old result, while reusing an approval for another operation fails.

For encrypted sends, the server cannot inspect approved plaintext. The owner's authorised endpoint must independently decrypt and validate the exact candidate ciphertext and bound metadata before approving its digest. An unverified agent-supplied plaintext preview is insufficient. Client cryptographic state must distinguish staged inspection from final ingestion and preserve exact ciphertext for retries; that state transition needs explicit library-level design before this mode ships. If the owner cannot verify the candidate, approval is unavailable.

Pause/revoke is owned by the receiving home service, including remote grants. Its durable acknowledgement means no later action in that service's evaluation order can use the old permission. Queued work is rechecked at commit; draft time and connection time confer no priority. Effects already committed are retained with attribution. Revocation does not erase disclosed content or instantly remove an endpoint's old decryption keys.

## 5. Ordering, durability and recovery

Proposed implementation contract: one home-service serial commit order spans room effects and security-control changes. Each room exposes its own monotonic sequence; a durable transaction checks relevant current grant, agreement and room revisions before publishing. Cross-room pause therefore has one service-owned boundary without requiring a global order between independently administered services. Server receive time and commit time are recorded distinctly; client time is advisory only.

The event stores its ID, room sequence, authenticated actor, optional represented account/grant, policy references, content or ciphertext, parent/reply reference and server timestamp semantics. Membership, moderation and epoch transitions share that room's order. Unknown database or clock health prevents acceptance; monotonic timers bound work, and uncertainty near authority expiry refuses an effect. Clock recovery policy is still a design decision.

Proposed durable acknowledgement means the event, authoritative access transition, deduplication outcome and required recovery metadata have committed to crash-durable storage before `Committed` is sent. One-host media loss is outside that guarantee. Search indexes may be rebuilt, but a result cannot be returned from an index beyond its committed visibility point. Disk exhaustion returns `Overloaded/StorageQuota` before a success acknowledgement.

| Client-visible state | Meaning |
| --- | --- |
| Draft / Queued locally | Held by this client; the service has made no commitment |
| Accepted pending | Admitted to a bounded service queue; neither durable commit nor recipient delivery is implied |
| Committed | Durable home event and deduplication result exist under the declared durability profile |
| Rejected | Explicit terminal refusal for this operation; editing/retrying as a new action requires current checks |
| Outcome unknown | Connection failed before a definitive result; resolve this ID before attempting another effect |
| Delivered / Read | Separate opt-in recipient events with stated device/account meaning; never inferred from commit or ignore-filtered output |

The accepted retry-window limit is 24 hours. The home service issues and durably stores each window with a non-reused ID and expiry. Accepted outcome records last at least seven days and beyond their window expiry. The deduplication key includes authenticated actor and operation ID; immutable action bytes are compared before any new effect. New requests using a closed/missing window are rejected even after its deduplication rows are purged. A client cannot extend its window by changing a timestamp.

`Operation.Resolve` returns `Committed`, `Rejected`, `Pending`, `AbsentInOpenWindow` or `ExpiredUnknown`. It can disclose a minimal result for that actor's own request without restoring room-content access. Existing committed outcomes remain committed after revocation. An absent ID in an open window may be resubmitted with identical bytes and fresh current permission. An expired unknown outcome is never automatically resent under a new ID. Reconnect resolves uncertain operations, then obtains current subscriptions and resumes authorised cursors.

Only authenticated, admitted requests receive durable outcomes. Invalid framing and failed account authentication cannot allocate outcome rows. `RateLimited` or `Overloaded` before admission leaves the operation absent and permits a later identical retry within its window. A terminal rejection after admitted evaluation is retained; it is not silently reevaluated as a new effect.

Accepted history defaults are 30 days with a 10 GiB service quota and seven days/512 MiB for local archives. The implementation must qualify these limits; acceptance of the policy is not a measured capacity claim. Current access and expiry exclude content immediately; index/preview removal completes within a proposed 60-second cleanup bound. Quota exhaustion does not silently shorten an agreed retention window. Exports require deliberate selection; diagnostic logs exclude message bodies, decrypted drafts and keys.

Backups preserve identity, committed history, deduplication windows/outcomes, grant and agreement revisions, device policy, monotonic recovery markers and encrypted local key state where applicable. Restoring an older backup must not silently accept previously committed operations as new. A recovery generation fence or a strictly current recoverable log is required before service restart; the exact storage/backup design remains open. If continuity cannot be proved, show an explicit recovery boundary and require new identity/consent as applicable.

Resume cursors are opaque and bind home service, room, room sequence, authorised history window and current access/filter revisions. They never grant access. Membership/policy changes cause reevaluation, not continuation under old rights. Missing retained history returns `ResynchronisationRequired` with the permitted earliest point, without exposing inaccessible event existence. Search uses the same current access predicate and recipient ignore filter as live delivery; pagination remains bounded and cancellable.

## 6. Text and presentation boundaries

Protocol text is UTF-8; malformed sequences fail during bounded decoding. Original message bytes are preserved. The proposal separates maximum bytes, graphemes and display width; cursor motion and editing use grapheme boundaries. The final Unicode version must match qualified Rust libraries and test vectors. [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629.html) and [UAX #29](https://www.unicode.org/reports/tr29/) provide the encoding/segmentation reference.

Proposed handles use a versioned normalised lookup key while preserving display spelling; exact normalisation and case-folding rules remain open. Opaque IDs decide authority. Identity displays reveal directional/invisible controls and distinguish origin. Terminal rendering treats control/escape sequences as inert visible text; it cannot execute remote commands or hyperlinks automatically. Encrypted search is confined to authorised locally decrypted indexes, protected and retained like their content. The service never claims plaintext search without keys.

The service enforces frame/ciphertext and visible-metadata bounds for encrypted rooms; authorised endpoints enforce plaintext text/grapheme limits after decryption. Signed bytes are never normalised after verification. Oversized or invalid decrypted content is rejected locally without allowing unbounded rendering or a response storm.

Ignore removes matching recipient deliveries, notifications, preview requests and agent triggers before enqueueing, and filters that recipient's history/search. It does not erase shared history. Local mute changes presentation/notifications only. Room silence denies send publication; kick removes membership; ban also blocks readmission under the declared subject/operator policy. These effects carry scope, duration and moderator attribution. Enforcement logs and notices share bounded budgets.

## 7. Confidential direct conversations and private groups

**Proposal:** use a maintained MLS implementation for both modes, with distinct endpoints as group members. MLS supplies group key agreement; HRC still supplies identity authentication, delivery and policy. MLS supports two-client groups, and its architecture leaves application-specific behaviour to the surrounding system. [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) · [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html)

Each device or agent endpoint has independent keys and explicit enrolment. Proposed HRC credentials bind endpoint, account/operator, permitted represented identity and current enrolment generation. Clients validate those bindings against accepted authentication authorities and visible device confirmations. Authentication-service compromise is a distinct threat; independent key verification and recovery policy need selection. The server sees routing, size, timing and required membership metadata; encryption does not promise metadata concealment.

Proposed membership flow: a home-ordered change authorises exact endpoint additions/removals; an eligible client prepares the MLS transition; the home serialises a single candidate from the expected epoch; clients validate the commit and policy before applying it. Pending membership changes block affected application sends. Conflicting candidates resynchronise. Welcome is released only after the winning commit is accepted. MLS requires a defined commit-conflict rule and careful tentative-state handling. [RFC 9420 §14](https://www.rfc-editor.org/rfc/rfc9420.html#section-14)

A home delivery acknowledgement does not prove that every recipient validated the MLS transition. The design must select the readiness evidence and invalid-commit recovery rule before implementing this barrier. Invalid or inconsistent transitions keep sending suspended; no endpoint applies an invalid commit merely because the service ordered it. Handshake visibility determines which checks the service can perform without content keys.

Removal, agent read-scope withdrawal and federation-member withdrawal suspend new ciphertext publication until the removal epoch is accepted. Recipients reject content against an obsolete membership policy. A paused agent with read permission removed also needs this barrier. If no authorised endpoint can complete the transition, the conversation remains unavailable for new sends. Already disclosed plaintext and old keys cannot be retracted. This service barrier does not constrain malicious recipients communicating outside HRC.

The accepted default for new or recovered devices is future encrypted messages only, in both direct conversations and private groups. New agents likewise receive no historical keys by default. Existing authorised devices retain their permitted local archives. Proposed recovery replaces a lost endpoint and removes its old membership; it does not restore old history automatically. Prior-history access is strictly optional and disabled by default. Any future archive-transfer or recovery mechanism requires deliberate, separately authorised disclosure and a defined recipient, history scope and retention policy; neither enrolment nor ordinary login enables it. No such mechanism or key-backup policy has yet been selected. MLS itself does not give a newly added device historical messages. [RFC 9750 §§6.6–6.7](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.6)

Client persistence must atomically retain outbound ciphertext and advanced crypto state before transmission; uncertain sends retry identical bytes, never reuse a nonce or recreate a message under an old state. Bound skipped-message keys, epoch catch-up and offline lifetime; select erasure and update schedules before implementation. Cipher suite/library version, handshake visibility, credential format, recovery secrets and old-epoch retention remain decisions. Suite Mail is an integration reference, not this lifecycle.

Agents receive no user private keys. A read grant for a private group requires its own visibly enrolled endpoint and the corresponding membership transition. External model disclosure needs a separate permitted destination and consent. Service-side content moderation is available only where the service can read content; an encrypted-room moderation agent is a visible authorised participant.

MLS membership exposes the group's messages for the epochs whose secrets an endpoint holds. Do not enrol an agent when its grant permits only selected messages or a narrower context within an epoch. Such access needs a separately authorised, encrypted disclosure of the selected context to that agent's own endpoint, or an explicit refusal until that disclosure contract exists. A server-side filter does not narrow cryptographic possession of an epoch key.

## 8. First federation profile

**Proposal:** bilateral shared rooms, one home service, two independently administered HyperNets, no onward forwarding. An agreement binds both network/incarnation identities, home service/rooms, exact gateway endpoints and authentication keys, origin-attestation authority, remote account admission rules, moderator scopes, history/retention/storage, privacy/crypto mode, expiry and withdrawal procedure. Both administrators accept the same immutable agreement and each affected room explicitly enables it.

Transport arrangement: each gateway has a locally admitted source-side endpoint and a separately admitted application principal/companion in the destination network for the destination HRC service. The agreement binds these distinct identities; no foreign HyperNet membership is inferred. Destination owner/application consent and purpose-specific grants are required independently. Each direction has its own admissions and target map. A gateway stream authenticates the gateway, not every multiplexed remote account.

Original actor evidence therefore needs an HRC contract beyond today's SDK. Proposed remote submission contains the exact agreement/revision, home room, origin account/endpoint, represented account and home-owned grant if delegated, original Action and authentication, origin endpoint-binding statement, a one-use home challenge and a fresh origin admission assertion. The agreed origin HRC authority attests which currently admitted transport endpoint made the request; the actor authenticates the immutable action with its enrolled HRC endpoint key. Pin the origin authority and endpoint binding through explicit agreement/enrolment. A payload account ID, gateway transport identity or old stream metadata alone proves none of this.

The home verifies gateway admission, agreement, origin binding, action authentication, challenge, destination restrictions and its own current grant/room policy before committing. An altered room, actor, represented account, content, grant or agreement invalidates the evidence. Replays resolve through home deduplication. Foreign event IDs retain origin; only the home assigns the canonical room sequence. Exchange of committed home events cannot create a second send effect or trigger onward federation.

The gateway's HRC enrolment permits only its designated federation operation family. It cannot submit an ordinary direct/independent actor request for an arbitrary account or bypass remote evidence checks by changing the envelope kind.

This profile explicitly trusts the accepted origin HRC attestor for source-side admission statements. It is not a portable HyperNet quorum-proof verifier. The concrete signed envelope, credential verification/revocation retrieval and bilateral setup must be specified and tested before claiming remote admission works. An alternative direct dual-admission endpoint profile may reduce gateway assertions, but still needs explicit origin-account binding.

Freshness is unresolved at the cross-network boundary. Proposed challenges expire after five seconds on the home's monotonic clock, are single-use and bind the exact action; this bounds stale attestations but cannot make source revocation instantaneous at the destination. A source authority change can occur between assertion and home commit. Local home-owned HRC pause/revoke remains strictly ordered because the receiving service owns it. Source HyperNet revocation requires an agreed bounded-delay contract or a coordinated destination withdrawal barrier; neither is implied by a signed timestamp.

On withdrawal, each side immediately stops its own new exchange and requests a durable home barrier. The home acknowledges the order after which it rejects that agreement, including queued effects, and suspends affected encrypted rooms for rekey. The UI distinguishes `WithdrawalRequested` from `WithdrawnAtHome`; a disconnected peer cannot be reported as globally stopped. Agreement expiry fails closed under the defined clock policy. The first-release acceptance rule must use the agreed effective barrier and declared freshness bound, not an unachievable instantaneous global observation.

## 9. Accepted pilot target and proposed work budgets

The following stream allocation is accepted as the initial qualification target. It is not measured throughput or a supported-capacity claim. One companion supports at most 16 active incoming/outgoing streams combined. Allocation per home: eight interactive endpoint streams, two agent streams and two federation-direction streams; reserve two operator streams and two transition slots. Additional devices consume slots; multiplexed remote actors still consume independent application budgets. Other work budgets below remain proposed. Up to 32 room accounts and 64 encrypted endpoints per room are proposed; these membership limits do not imply 64 simultaneous transport connections.

| Resource | Proposed pilot ceiling and response |
| --- | --- |
| Frame and parsing | 64 KiB ordinary frames; 256 KiB crypto transition frames; depth 16; 256 collection entries; check class/length before allocation and decoding |
| Text | 8 KiB UTF-8 and 2,000 graphemes per message, both enforced; handle 64 bytes/32 graphemes; display width handled separately |
| Ingress | Per actor and represented account: 2 sends/s, burst 8, 32 KiB/s; per room 10 sends/s; service 20 sends/s and 256 KiB/s; all applicable budgets must permit work |
| Connections and metadata | At most 4 HRC handshakes concurrently, 5-second deadline; actor 4 opens/minute; 10 joins/leaves/minute; nickname/presence 6/minute; no exemption for federated batches |
| Queues | 512 KiB outbound per stream; 32 pending operations per actor; 64 per room; 16 MiB combined queue-byte ceiling; stop admission before any bound is crossed |
| Workers and fairness | 4 costly workers, one reserved for authenticated control changes; at most 2 search jobs and 1 search per actor; fair actor/represented-account/peer scheduling; crypto admission is separately costed |
| Fan-out | Charge encoded bytes times actual recipient deliveries; 1 MiB/s service output and 256 KiB/s per peer; isolate slow recipients after 5 seconds at their queue limit |
| History/search | 50 results or 256 KiB per page; 16 terms/1 KiB query; 2-second work deadline; cancellation checked at bounded steps; 1 MiB catch-up per peer per minute |
| Agent chains | Trigger once per event/grant; causal depth at most 4 and 8 automated effects per root event; independent/represented budgets both apply; no response-to-response trigger by default |
| Reserved controls | Authenticated cancellation, disconnect and moderation: 64 KiB reserved within the global queue budget, 4 operations/s service budget, 8 KiB maximum control frame; excess still refuses |
| Diagnostics/notifications | No payload logs; 64 KiB/minute diagnostic budget with coalescing; 10 notifications/minute per account with summary; no individual alert per resumed history event |
| Recovery | Jittered exponential reconnect, 1–60 seconds, at most 5 attempts/minute; honour bounded retry guidance; one retry resolver per actor |
| Qualification targets | Service RSS at most 512 MiB excluding separate HyperNet processes; unaffected-client p95 commit latency under 500 ms at 5 sends/s during a bounded overload; moderation under 1 second; recovery under 30 seconds after authority/transport is healthy |

Per-queue limits are subordinate to the global byte ceiling; they are not preallocated independently. At most sixteen 512-KiB output queues account for 8 MiB of that ceiling. Crypto buffers, parsers, indexes, storage caches and process overhead also need explicit accounting against the measured RSS target. Service-wide cost rejection happens before fan-out/model work. E2EE recipient work needs its own endpoint budgets; a bounded server alone cannot protect clients from malicious MLS state growth.

Saturation returns bounded `RateLimited` or `Overloaded`, or closes only the affected stream. Never send automatic replies to errors/replies. No model call belongs in the admission path. Pre-HRC connection attacks and link saturation still require HyperNet/host controls. Qualification must include malformed frames, Unicode extremes, churn, joins, slow readers, costly searches, federation replay, agent loops and notification storms. Failed targets require smaller published limits or design changes, not relabelling a pass.

## 10. Error boundary

Stable HRC categories are `InvalidInput`, `Denied`, `Expired`, `Conflict`, `Unavailable`, `UnsupportedVersion`, `UnsupportedFeature`, `RateLimited`, `Overloaded` and `ResynchronisationRequired`. Detail codes describe public recovery actions, not keys, raw database errors or sensitive existence. Errors bind the operation ID when authenticated. Retry hints are finite, capped and advisory. A generic companion refusal or EOF maps to transport unavailability/unknown outcome until better verified evidence exists; it must not be fabricated as an HRC revocation decision.

## 11. Worked interaction traces

| Trace | Ordered interaction and expected result |
| --- | --- |
| Direct send | Endpoint P opens current HyperNet stream → HRC resolves P's account binding → creates retry window W → submits operation O → home checks membership at sequence 40 → durable event 41/outcome commit → ACK. Nickname changes later do not alter attribution. |
| Delegated reply | Agent A connects as A, not owner U → names home-owned grant G7 and reply target E → service checks U's membership, A's scope/history and room policy → exact approval if required → commits `U via A, G7`. Another room or initiate operation outside G7 returns Denied. |
| Queued work then pause | O waits in a bounded queue → owner Pause(G7) commits control C → service acknowledges Paused → O is evaluated after C and rejected. A pre-C committed event remains. Resume creates G8 state and needs explicit resubmission/current checks. |
| Uncertain send | O commits event E, connection drops before ACK → client shows Outcome unknown → new current session → Resolve(O) returns E → display one message. If no record exists in open W, identical O can be retried; changed content conflicts. |
| Expired stream and resume | HyperNet byte/time/permission limit closes stream → local draft remains → obtain current explicit permission/renewal where required → resolve O → resume room cursor with current access → retained-history gap yields ResynchronisationRequired, never a direct route. |
| Remote delegated action | Origin endpoint signs exact action for home H and its grant G → origin gateway obtains home challenge and current origin assertion → separately admitted destination gateway forwards → H checks agreement, evidence, G and destination membership → one home event preserves origin and represented attribution. Source revocation during transit follows the unresolved freshness/barrier contract, not an instant-revocation claim. |
| Agreement withdrawal | Either side records local stop → home receives withdrawal and commits barrier C → queued exchange after C refuses → source receives barrier ACK and displays WithdrawnAtHome. Without ACK, it displays remote stop unconfirmed; no new local outbound exchange starts. |
| Private-group removal | Room restriction removes endpoint D → home suspends application sends → authorised client produces removal Commit from epoch k → winning transition accepted and verified → clients send at k+1 → D gets no new HRC delivery or new epoch keys. Prior plaintext remains outside recall. |
| Ignore and search | Recipient ignores A → event from A is retained for other authorised recipients → no delivery, notification, preview or agent trigger for this recipient → current search/history omits it; no delivered/read receipt is invented. |
| State loss | Restored service cannot prove current outcome/grant continuity → refuses new effects until recovery fence is established. A lost encrypted endpoint rejoins with new explicit enrolment; it does not silently reuse old crypto state or receive history keys. |

## 12. Ownership and acceptance

| Quality criterion | Authoritative owner/boundary and review evidence |
| --- | --- |
| Implicit coupling | Session/Identity supplies explicit verified actor context; Delegation supplies current effect authority |
| Layer-first folders | Feature contracts own handlers, errors and tests; adapters stay near the capability they support |
| Duplication | One domain operation path serves all frontends/API/federation; trust-boundary rechecks remain deliberate |
| Representable illegal states | Validated actor variants, grant lifecycle and exclusive delivery outcomes; unverified envelopes remain separate types |
| God files | Conversations owns room order; Identity, Delegation, Moderation, Federation and adapters retain their own responsibility |
| Shotgun surgery | A room-policy change names its policy owner, stable consumers, relevant wire/migration work and focused tests |
| Layering violations | Domain rules consume contracts, not egui widgets, terminal escapes, raw companion frames or database rows |
| Pass-through wrappers | Every boundary validates, converts, owns lifetime or provides a demonstrated substitution point |
| Errors / validation not at the boundary | Wire, companion, storage and configuration reject malformed input; domain rules precede effects; public errors are stable |

| Product acceptance scenario | Required verification of this proposal |
| --- | --- |
| 1 Identity/nickname | Account/device mapping survives nickname and host changes without attribution rewrite |
| 2 Agent scope | Direct, independent and delegated traces; out-of-room/history/operation tests |
| 3 Pause/revoke | Queued work races against acknowledged home control; network outage remains distinct |
| 4 Unknown outcome | Interrupt around durable commit/ACK; retry window, conflict and restart preserve one result |
| 5 Restricted history | Live, search, resume and agent paths share current membership/history predicates |
| 6 Federation | Two independently administered networks; altered origin/action, replay, destination ban, withdrawal barrier and declared freshness tested |
| 7 Stream limits | Real HyperNet expiry/bytes/refusal/renewal; drafts and unresolved outcomes persist without fallback |
| 8 Confidentiality | DMs and private groups: enrolment, epoch races, removal, offline devices, recovery, exact approval and consented disclosure |
| 9 Change cost | Representative policy change and dependency review against all nine owner boundaries |
| 10 Unicode | Malformed UTF-8 refusal; combining/emoji editing, persistence, search and terminal rendering |
| 11 Ignore/silence | Pre-delivery/trigger filtering versus pre-publication restriction; bounded audit output |
| 12 Flood/recovery | Measured queue/RSS/latency/amplification ceilings and reserved controls under overload |
| 13 Search retention | Restart/index consistency, immediate access/expiry exclusion and bounded cleanup; no plaintext encrypted-content service index/log |

Before implementation: settle the wire/signature schema, endpoint/account recovery authority, clock policy, storage/recovery fence, resource accounting and qualification plans for accepted pilot/retention limits, MLS lifecycle parameters, and federation origin-evidence/freshness contract. Then derive wire vectors and executable traces from these decisions. Neither design milestone is complete while these boundaries remain open.
