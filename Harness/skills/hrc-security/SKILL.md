---
name: hrc-security
description: Explain and apply explicitly selected HRC host and operations security options with concrete effects and recovery steps; advanced hardening is opt-in.
---

# HRC security options

Read [the operating contract](../hrc-setup/references/Contract.md). Start with the
user's exposure and access needs. A normal desktop user does not need an extensive
host-hardening programme to complete setup. Do not impose one.

Mandatory product checks remain enabled: authenticated identity, current consent,
authorisation, encryption verification, clock evidence and HyperNet-only chat.
Optional choices can strengthen host operations without changing those contracts.

Offer only relevant choices, with their effect and recovery path:

| Choice | Effect and cost | Recovery before applying |
| --- | --- | --- |
| Dedicated service account and private state paths | Limits unrelated local access; requires explicit ownership and service changes | Record existing ownership and service unit; keep working administrator access |
| Narrow host firewall rules | Reduces exposed listeners; can break relay, authority, DNS, time or remote administration | Preserve required ports and essential ICMP/ICMPv6; retain console access and a tested rollback |
| SSH key policy and restricted operator accounts | Limits remote administration; may lock out existing operators | Verify a second working session and recovery access before disabling a method |
| Private, encrypted backups with restore checks | Protects retained state; requires secure independent key storage and capacity | Keep the previous backup until a stopped-state restore succeeds in a separate directory |
| Service confinement and resource budgets | Limits host effects and resource exhaustion; may deny required files or clock observations | Inspect required paths/capabilities and keep the previous policy ready to restore |
| Shorter retention and scoped assistant access | Reduces retained/disclosed content; affects search, context and recovery | Explain irreversible expiry; export only deliberately selected permitted data |

Inspect current policy read-only first. Present the exact selected change, host,
impact and rollback. Use existing approval; obtain missing write authority before
privileged changes. Apply one coherent change and check its affected workflow.
Do not disable AppArmor, authentication, clock checks or TLS verification to make
a test pass. Do not change host clocks, blanket-block ICMP, expose inference
listeners, or replace a firewall ruleset as a routine HRC repair.

Keep operational evidence concise and redacted. The harness is not a security
certification and cannot make guarantees about tools or infrastructure it has
not inspected.
