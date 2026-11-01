# Clock validity and operation ordering

HRC uses the released HyperNet host monitor's signed clock export. Configuration
pins its public key and the absolute canonical observation path. Verification
binds the signature, exact versioned bytes and the current kernel boot, and
requires unshifted monotonic and boot-time namespaces. The verifier cannot change
the clock, choose a new monitor or renew an expired observation.

The supported export is the published TrustWire envelope containing kind44,
version1, kernel boot, sample UTC milliseconds, sample boot milliseconds, original
expiry, maximum error and canonical source address. It has one pinned Ed25519
signature. Inputs are at most4096bytes. The original lifetime is exactly1000ms;
error plus observed wall-clock drift must remain at most250ms. The implementation
matches the released [export](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Authority/AuthorityClockHandoff.rs)
and [clock](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/b840c8b8e7d74fac71e898cf2c2eb7c660c57275/Source/Consensus/ConsensusClock.rs)
contracts. This is verification of a local clock observation, not a second
HyperNet authority evaluator.

At an operation boundary, HRC uses the conservative interval UTC minus250ms
through UTC plus250ms. A not-before condition requires the lower bound to have
reached it; expiry requires the upper bound to remain strictly below it. The
original signed observation is rechecked at the serial authorization point.
Reading, copying, forwarding or queueing never restarts its lifetime. Missing,
expired, future, wrong-boot, altered or shifted-clock evidence makes clock-dependent
operations unavailable. Generic transport failure does not establish clock health.

Every authoritative database transaction retains a nondecreasing lower UTC floor
inside its guarded state. Startup and subsequent effects require a current valid
observation whose lower bound has reached that floor. A clock rollback therefore
cannot reopen old retry windows or resurrect grants from a restored database.
The external continuity guard separately prevents an old snapshot from silently
becoming the current service state. A reboot requires a new current-boot clock
observation and fresh transport/session proof. Old pending session challenges die;
committed outcomes and still-valid durable retry windows remain resolvable.

Acquire an action-bound HyperNet authority observation outside the service writer
lock. Inside the serial order, recheck its usability, the clock and current
endpoint, account, delegation, membership, moderation and agreement state. Commit
the resulting state, event and operation outcome together. Persist the continuity
guard before publishing an acknowledgment. A storage failure after authorization
can leave the outcome unknown; it cannot justify a new operation identifier or
turn a committed event into a rejection.

Federated peers never compare boot-clock numbers from different hosts. The home
issues a one-use challenge with an original boot deadline at most5000ms away. The
origin signs its conservative expiry in UTC, clipped by its current authority and
credential limits. The home requires its current UTC upper bound below that
source expiry and its own original challenge deadline still live. Forwarding
cannot reset either bound. The accepted origin attestor remains the authority for
source-side statements; destination HRC policy and withdrawal barriers remain
home-owned. No timestamp establishes instantaneous global revocation.
