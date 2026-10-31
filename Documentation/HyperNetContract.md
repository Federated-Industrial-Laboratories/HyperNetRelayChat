# HRC HyperNet integration contract map

Draft 1, 31 October 2026. [Product plan](ProductPlan.md) · [Protocol proposal](ProtocolPermissions.md)

This map records inspected source behaviour and HRC integration gaps. It does not claim that HRC has a working adapter or qualified deployment. The source contracts were inspected during the Core/Suite 0.9.1 hotfix and reconciled with the published release revisions below.

| Product | Published v0.9.1 revision | Status |
| --- | --- | --- |
| HyperNet Core | `4d4acac432f8de47298be0057c9dd69c313941bd` | Published; signed public assets verified |
| HyperNetSuite | `fc990d7e581e512d514d488fb9535a4e36af6dd6` | Published; signed public assets verified |

Sources below refer to those exact release revisions. Final source trees match the qualified candidates, including the dedicated test-directory reorganisation. Real native admission/stream checks passed on the final release binaries. This establishes the recorded HyperNet boundary, not an HRC adapter or HRC qualification. A version string alone is insufficient to prove the selected semantics.

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

These behaviours are documented in [Core application streams](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/ApplicationStreams.md) and implemented in [Suite's companion](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Applications/ApplicationStreamsAgent.rs).

HyperNet is mandatory for all HRC remote chat/service paths. A refusal, unavailable relay, incompatible protocol or missing selected privacy policy fails closed. HRC must not use a direct TCP/HTTP path, process proxy, payload-supplied address or alternate trust root as recovery. Local companion IPC is the documented local boundary, not an Internet fallback.

## Action 29/30 correction and upgrade boundary

The hotfix retains signed action numbers and record bytes. Stream management is action 29 and connection is action 30, with an exact Service scope `(3, service ID)`. The terminal grant and every non-root ancestor must have only Service scopes. Network, mixed-family or other resource kinds fail these effects. Sealed publication uses Object/Namespace-only grants, so its overlapping numbers cannot grant stream access.

Only a root accepted by current governance may remain broad as an ancestor authorising explicit scoped delegation. A broad root cannot execute the stream effect as its terminal grant. A narrow child beneath a broad non-root grant does not repair the chain. Existing exact subject, action, version, admission, tier, expiry, revocation and consent checks still apply. See [scope classifier](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Protocol/TrustActionScope.rs), [chain check](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Authority/Governance/AuthorityGovernance.rs) and [stream evaluation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Source/Authority/Domains/AuthorityStreamsEvaluation.rs).

The complete authority committee, endpoints and corresponding Suite clients need a coordinated stopped upgrade before affected work resumes. First quiesce ordered mutations and pending requests on the old version, complete catch-up, inspect fresh quorum evidence, and stop all voters at the same fully applied and committed height. Preserve complete journals, state, history and floors. An old committed but unapplied suffix would execute under the new evaluator and can diverge; lagging or mixed-version upgrades are unsupported. Old binaries retain the earlier broad interpretation; unchanged wire numbers do not make mixed semantics supported. Existing broad admissions/service/reviewer bindings need the documented explicit migration. Same-rights application renewal cannot change an accepted grant. [Permission scopes and migration](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/PermissionScopes.md)

## Application identity and renewal

An application admission binds its own key, owner and exact grant, with validity at most seven days and within grant validity. Applications have no further delegation authority. Same-rights renewal requires explicit owner/application consent; it does not enlarge rights or permit unattended consent. Withdrawal remains restrictive, and withdrawn application keys cannot be reused. [Application lifecycle](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/Applications.md)

Each HRC agent that requires independent transport attribution needs its own admitted principal and companion/profile. Sharing a human's companion authenticates the same principal and cannot prove a separate agent. HRC's account/endpoint enrolment must bind that principal explicitly; no caller-supplied display name or represented-account field can do so.

## Private companion interface

Suite is currently a binary application with a packaged Python SDK, not a published external Rust library for this interface. Proposed HRC integration is a narrow owned Rust adapter to the pinned local companion contract, with interoperability tests against the shipped SDK and real companion. Reuse Suite's cryptographic/authority ownership rather than copying it into HRC. Library publication is an alternative only after a supported upstream interface exists. [SDK](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/SDK/README.md) · [Cargo targets](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Cargo.toml)

| IPC element | Observed representation and adapter obligation |
| --- | --- |
| Local endpoint | Absolute canonical private directory, owner UID, mode 0700; `Control.sock` owner UID/mode 0600; validate Linux peer credentials and inode/path identity |
| Request/response | Big-endian four-byte length, non-empty JSON body at most 16,384 bytes, version 1; reject malformed types, length and unexpected protocol version |
| Request fields | `version`, `action`, optional `service`, `protocol`, `id`, `timeoutMs`; Rust request decoding rejects unknown fields |
| Operations | `connect`, `accept`, `status`, `cancel`; connect resolves only configured named targets, not an IP supplied by HRC |
| Preparation timeout | 100–60,000 ms, default 30,000; the Python SDK may repeat finite accept waits; application socket I/O needs its own bounded timeout/cancellation |
| Successful handoff | JSON response contains `ok`, local connection `id` and separate `peer`; remaining bytes on that socket are opaque application data, not additional JSON control |
| Status | Principal/network/incarnation, binding/targets, active connection summaries and bounded recent errors; this is not a portable authentication proof or guaranteed real-time permission oracle |
| Refusal | Explicit local `Capacity` and accept `Timeout`; other preparation failures commonly collapse into `Refused`; after handoff the application observes closure/I/O failure |

The adapter must preserve partial reads, EOF, half-close, cancellation and ownership of exactly one stream. It must not parse status error prose into authoritative expiry/revocation categories. Reference implementations: [Python SDK](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/SDK/hypernet_streams/__init__.py), [local IPC](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Networks/LocalStreamIpc.rs) and the companion above.

## Direction-specific verified context

Accepted incoming context contains `network`, `incarnation`, `service`, `protocol`, `principal`, `grant`, `grantGeneration`, `session`, `generation`, `expiresMs`, `maximumBytes`, `idleMs` and `durationMs`; the companion adds bound `owner` and `endpoint`. The endpoint-signed local context binds a fresh local challenge and exact accepted binding. [Binding verification and context](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Source/Authority/Domains/ApplicationStreamBinding.rs)

Outgoing `connect` context names the verified target network/incarnation/service/protocol, owner, endpoint, route, session generation, expiry and limits. It does not carry the incoming caller's `principal`/grant fields in the same shape. Model these as distinct validated types; a missing field is not an anonymous principal to be trusted. The local `status.principal` describes that companion, not a foreign author.

Neither context establishes an HRC account, represented user, grant lifecycle, room membership, moderation role, recipient filter or original foreign actor. `expiresMs` is an initial bound, not evidence that authority cannot be revoked earlier. The HRC service cannot revalidate queued work's HyperNet authority merely by rereading old JSON.

## Gaps that must close before their dependent claims

| Gap | Required outcome |
| --- | --- |
| Effective privacy fields absent | Extend a supported verified interface for selected/effective route privacy and relevant operator declarations, or explicitly display that HRC cannot verify them. Never infer independence from relay use. Product privacy indicators remain a release gate. |
| No typed live authority token/recheck for HRC commit | Specify how HRC checks current application authority for work already received, including revocation races, expiry and disconnect. Existing transport write gating alone does not order an HRC database commit with a later HyperNet change. |
| Refusal/closure loses structured cause | Translate only verified information; show unavailable/unknown outcome until a supported typed status/reason contract exists. HRC home pause/revoke remains separately inspectable. |
| No portable original-actor proof for federation | Define accepted HRC origin attestation and original action authentication, or a reviewed HyperNet evidence extension. An admitted gateway is not a foreign author's identity. |
| Remote source-authority freshness | Agree a bounded freshness model or destination barrier semantics; stale assertions cannot prove instantaneous cross-network revocation. |
| Rust SDK and platform qualification | Implement a narrow adapter only after the contract is settled; qualify Linux with actual socket/security constraints and compatible Rust/toolchain dependencies. |

HyperNet's current federation copies explicitly shared approved Pages. Its treaty/bridge trust pattern informs HRC, but it supplies no live chat forwarding contract. HRC's proposed separately admitted bilateral gateways require their own setup, evidence and tests. [Existing federation](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/4d4acac432f8de47298be0057c9dd69c313941bd/Documentation/Federation.md)

## Platform and evidence gate

Suite's release manifest uses Rust edition 2024 with `rust-version = 1.95`, eframe 0.37.0, Crossterm 0.29.0 and OpenMLS 0.9.1. These are inspected dependency facts, not HRC dependency commitments. The current qualified family is native Ubuntu x86_64 within its documented limits; HRC still needs its own qualification. [Manifest](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/Cargo.toml) · [Platform scope](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/fc990d7e581e512d514d488fb9535a4e36af6dd6/ReadMe.md)

Before the first slice, demonstrate one exact admitted endpoint binding, successful/denied stream admission, narrow grant ancestry, permission expiry/revocation, cancellation, explicit renewal, same-principal versus distinct-agent attribution, and constrained receiving/sending topology. Exercise malformed IPC, path/socket replacement and size bounds at the adapter boundary. Preserve genuine transport outcomes and exact source identities; a fake transport test cannot establish this integration.
