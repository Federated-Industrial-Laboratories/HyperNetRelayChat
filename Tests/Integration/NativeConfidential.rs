// SPDX-License-Identifier: Apache-2.0
//! Real confidential-conversation qualification; no supplied identities, keys or substitute transport.
use clap::Parser;
use hrc::{
    client::{self, Client, CryptoView, MessageContent},
    confidential, conversations, crypto, delegation, home, identity, messaging, moderation,
    protocol::*,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
#[path = "NativeDevices.rs"]
mod devices;
#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    request: PathBuf,
    #[arg(long, default_value_t = 600)]
    maximum_seconds: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    alice: PathBuf,
    bob: PathBuf,
    agent: PathBuf,
    room: RoomId,
    bob_recovery: PathBuf,
}
#[derive(Clone)]
struct Observation {
    principal: &'static str,
    operation: &'static str,
    deadline: Instant,
}
struct Run {
    end: Instant,
    observation: Arc<Mutex<Observation>>,
    steps: u32,
    exact_recoveries: u32,
}
impl Run {
    fn step<T>(
        &mut self,
        principal: &'static str,
        operation: &'static str,
        call: impl FnOnce(Instant) -> Result<T>,
    ) -> Result<T> {
        let deadline = self.end.min(Instant::now() + Duration::from_secs(45));
        *self
            .observation
            .lock()
            .map_err(|_| "ObservationUnavailable")? = Observation {
            principal,
            operation,
            deadline,
        };
        // Deliberate pacing respects the documented crypto-account burst/refill budget.
        thread::sleep(Duration::from_secs(2));
        ensure(Instant::now() < deadline, "StepDeadline")?;
        let result = call(deadline)
            .map_err(|code| format!("principal={principal} operation={operation} status={code}"))?;
        ensure(Instant::now() < deadline, "StepDeadline")?;
        self.steps += 1;
        Ok(result)
    }
    fn effect<T: Serialize>(
        &mut self,
        who: &'static str,
        c: &mut Client,
        operation: Operation,
        target: Target,
        body: &T,
    ) -> Result<Outcome> {
        let mut recovered = 0;
        let result = self.step(who, "ExactOperation", |end| {
            let action = net(c.prepare_as(operation, target, body, None))?;
            let signed = net(c.sign(&action))?;
            execute_exact(c, &action, &signed, end, &mut recovered)
        });
        self.exact_recoveries += recovered;
        result
    }
}
fn ensure(ok: bool, code: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(code.into()) }
}
fn net<T>(value: client::Result<T>) -> Result<T> {
    value.map_err(|e| e.code().into())
}
fn transient(error: &client::Error) -> bool {
    matches!(
        error,
        client::Error::Clock
            | client::Error::Unknown
            | client::Error::Network(
                client::network::Error::Companion
                    | client::network::Error::Connect
                    | client::network::Error::Handshake
                    | client::network::Error::Transport
                    | client::network::Error::Clock
            )
            | client::Error::Refused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            }
    )
}
fn available(outcome: &Outcome) -> Option<u64> {
    match outcome {
        Outcome::Refused {
            code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
            retry_after_ms,
            ..
        } => Some(retry_after_ms.unwrap_or(1000)),
        _ => None,
    }
}
fn execute_exact(
    c: &mut Client,
    action: &Action,
    signed: &[u8],
    end: Instant,
    recoveries: &mut u32,
) -> Result<Outcome> {
    let digest = action_digest(action).map_err(|_| "ActionDigest")?;
    let read = home::is_read_operation(action.operation);
    let mut first = true;
    loop {
        ensure(Instant::now() < end, "ExactOperationDeadline")?;
        let pending = !read
            && !first
            && net(c.pending())?.iter().any(|p| {
                p.action.action().operation_id == action.operation_id && p.action.digest() == digest
            });
        let response = if pending {
            c.retry_pending(action.operation_id, digest)
        } else {
            c.execute_signed(signed)
        };
        match response {
            Ok(response) => {
                let outcome = if response.operation_id == action.operation_id {
                    ensure(response.action_digest == digest, "ResponseBinding")?;
                    response.outcome
                } else {
                    let Outcome::Result { body } = response.outcome else {
                        return Err("ResolutionResponse".into());
                    };
                    let resolved: home::ResolveResult =
                        body.deserialized().map_err(|_| "ResolutionShape")?;
                    ensure(
                        resolved.operation_id == action.operation_id
                            && resolved.action_digest == digest,
                        "ResolutionBinding",
                    )?;
                    resolved.outcome
                };
                if let Some(delay) = available(&outcome) {
                    ensure(
                        end.saturating_duration_since(Instant::now())
                            > Duration::from_millis(delay),
                        "RetryGuidanceDeadline",
                    )?;
                    thread::sleep(Duration::from_millis(delay));
                } else {
                    return Ok(outcome);
                }
            }
            Err(error) if transient(&error) => {
                let delay = match &error {
                    client::Error::Refused { retry_after_ms, .. } => retry_after_ms.unwrap_or(1000),
                    _ => 1000,
                };
                ensure(
                    end.saturating_duration_since(Instant::now()) > Duration::from_millis(delay),
                    "RetryGuidanceDeadline",
                )?;
                thread::sleep(Duration::from_millis(delay));
                c.disconnect();
                net(c.connect())?;
            }
            Err(error) => return Err(error.code().into()),
        }
        first = false;
        *recoveries += 1;
    }
}
fn committed(outcome: Outcome) -> Result<(Option<Id>, Value)> {
    match outcome {
        Outcome::Committed { event, body, .. } => Ok((event, body)),
        Outcome::Rejected { code, .. } | Outcome::Refused { code, .. } => {
            Err(format!("ExpectedCommit:{code:?}"))
        }
        _ => Err("ExpectedCommit".into()),
    }
}
fn completed(response: Response) -> Result<(Option<Id>, Value)> {
    committed(response.outcome)
}
fn room(outcome: Outcome) -> Result<RoomId> {
    let (_, body) = committed(outcome)?;
    #[derive(Deserialize)]
    struct Created {
        room: RoomId,
    }
    body.deserialized::<Created>()
        .map(|v| v.room)
        .map_err(|_| "RoomShape".into())
}
fn pin(c: &mut Client, room: RoomId, grant: Option<&delegation::Grant>) -> Result<CryptoView> {
    let view = net(c.crypto_inspect(room, grant))?;
    for contact in &view.contacts {
        match contact.state {
            client::trust::TrustState::UntrustedRegistration => {
                net(c.trust_contact(contact.account, contact.anchor, false))?
            }
            client::trust::TrustState::Trusted => {}
            _ => return Err("UnexpectedContactAnchor".into()),
        }
    }
    Ok(view)
}
fn history(
    c: &mut Client,
    room: RoomId,
    grant: Option<&delegation::Grant>,
) -> Result<client::ConversationPage> {
    net(c.history_messages(
        room,
        &messaging::Page {
            cursor: None,
            limit: 32,
        },
        grant,
    ))
}
fn message(text: &str, mentions: Vec<messaging::Mention>) -> messaging::Send {
    messaging::Send {
        text: text.into(),
        mentions,
        parent: None,
        causation: None,
    }
}
fn text(page: &client::ConversationPage, id: Id, expected: &messaging::Send) -> bool {
    matches!(page.content.get(&id),Some(MessageContent::Decrypted(message)) if message.text==expected.text && message.mentions==expected.mentions)
}
fn search(
    c: &mut Client,
    room: RoomId,
    term: &str,
    offline: bool,
) -> Result<client::ConversationPage> {
    let query = messaging::Search {
        terms: vec![term.into()],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 16,
    };
    let cancel = AtomicBool::new(false);
    if offline {
        net(c.search_retained(room, &query, &cancel))
    } else {
        net(c.search_messages(room, &query, None, &cancel))
    }
}
fn send(
    run: &mut Run,
    who: &'static str,
    c: &mut Client,
    room: RoomId,
    body: &messaging::Send,
    grant: Option<&delegation::Grant>,
) -> Result<(Id, client::PreparedSend)> {
    let prepared = run.step(who, "PrepareEncryptedMessage", |_| {
        net(c.prepare_send(room, body, grant, false, None))
    })?;
    ensure(prepared.encrypted, "PlaintextDowngrade")?;
    let mut recovered = 0;
    let outcome = run.step(who, "SubmitEncryptedMessage", |end| {
        execute_exact(c, &prepared.action, &prepared.signed, end, &mut recovered)
    })?;
    run.exact_recoveries += recovered;
    let (event, _) = committed(outcome)?;
    Ok((event.ok_or("MissingMessageEvent")?, prepared))
}
fn join_pair(run: &mut Run, alice: &mut Client, bob: &mut Client, room: RoomId) -> Result<()> {
    run.effect(
        "Bob",
        bob,
        Operation::RoomJoin,
        Target::Room(room),
        &home::Empty {},
    )
    .and_then(committed)?;
    run.step("Alice", "TrustInitialContacts", |_| pin(alice, room, None))?;
    run.step("Alice", "InitialiseGroup", |_| {
        completed(net(alice.crypto_initialise(room, false))?)
    })?;
    run.step("Bob", "PublishKeyPackage", |_| {
        completed(net(bob.crypto_publish(room, None))?)
    })?;
    let view = run.step("Alice", "TrustAddedContact", |_| pin(alice, room, None))?;
    let endpoint = net(bob.session())?.ready.acting.endpoint;
    let package = view
        .remote
        .packages
        .iter()
        .find(|p| p.member.credential.actor.endpoint == endpoint)
        .ok_or("BobPackageUnavailable")?
        .digest;
    run.step("Alice", "CommitAddBob", |_| {
        completed(net(alice.crypto_commit(room, &[package], &[], None))?)
    })?;
    run.step("Bob", "TrustWelcomeRoster", |_| pin(bob, room, None))?;
    let joined = run.step("Bob", "WelcomeAndReady", |_| {
        net(bob.crypto_sync(room, None))
    })?;
    ensure(
        joined
            .local
            .as_ref()
            .is_some_and(|s| s.active && s.epoch == joined.remote.epoch)
            && !joined.remote.send_barrier,
        "BobEpochNotReady",
    )?;
    Ok(())
}
fn workflow(run: &mut Run, request: &Request) -> Result<serde_json::Value> {
    let mut alice = run.step("Alice", "Open", |_| net(Client::open(&request.alice)))?;
    let mut bob = run.step("Bob", "Open", |_| net(Client::open(&request.bob)))?;
    let mut agent = run.step("Agent", "Open", |_| net(Client::open(&request.agent)))?;
    let alice_id = alice.profile.registration.account;
    let bob_id = bob.profile.registration.account;
    let agent_actor = net(agent.session())?.ready.acting.clone();
    ensure(
        alice_id != bob_id && alice_id != agent_actor.account && bob_id != agent_actor.account,
        "DistinctPrincipals",
    )?;
    ensure(
        request.room.home == alice.profile.server.home
            && alice.profile.server.home == bob.profile.server.home
            && bob.profile.server.home == agent.profile.server.home,
        "HomeBinding",
    )?;
    run.effect(
        "Bob",
        &mut bob,
        Operation::AccountSetNickname,
        Target::Account(bob_id),
        &identity::Nickname {
            nickname: "CipherBob".into(),
        },
    )
    .and_then(committed)?;
    for (who, c) in [
        ("Alice", &mut alice),
        ("Bob", &mut bob),
        ("Agent", &mut agent),
    ] {
        run.step(who, "EnrolIndependentMlsKey", |_| {
            completed(net(c.crypto_enrol())?)
        })?;
    }
    let private = room(run.effect(
        "Alice",
        &mut alice,
        Operation::RoomCreate,
        Target::Service,
        &conversations::Create {
            name: "Native confidential group".into(),
            confidentiality: RoomConfidentiality::PrivateGroup,
        },
    )?)?;
    run.effect(
        "Alice",
        &mut alice,
        Operation::RoomInvite,
        Target::Room(private),
        &confidential::Invite { account: bob_id },
    )
    .and_then(committed)?;
    join_pair(run, &mut alice, &mut bob, private)?;
    let original = message(
        "@CipherBob nativecryptocafé e\u{301} 👩🏽‍🚀 مرحبا",
        vec![messaging::Mention {
            account: bob_id,
            start: 0,
            end: 10,
        }],
    );
    let (first, prepared) = send(run, "Alice", &mut alice, private, &original, None)?;
    let seen = run.step("Bob", "ReceiveTypedCiphertext", |_| {
        history(&mut bob, private, None)
    })?;
    ensure(
        text(&seen, first, &original),
        "DecryptedUnicodeMentionMismatch",
    )?;
    let received = seen
        .events
        .iter()
        .find(|e| e.event == first)
        .ok_or("MessageEventUnavailable")?;
    let envelope: crypto::EncryptedEvent = received
        .body
        .deserialized()
        .map_err(|_| "EncryptedEventShape")?;
    ensure(
        envelope.context.operation_id == prepared.action.operation_id
            && !envelope.ciphertext.0.is_empty(),
        "CiphertextAttribution",
    )?;
    ensure(
        received.body.deserialized::<messaging::Send>().is_err(),
        "EventBodyRewrittenAsPlaintext",
    )?;
    let mut recoveries = 0;
    let repeated = run.step("Alice", "ExactCiphertextReplay", |end| {
        execute_exact(
            &mut alice,
            &prepared.action,
            &prepared.signed,
            end,
            &mut recoveries,
        )
    })?;
    run.exact_recoveries += recoveries;
    ensure(
        committed(repeated)?.0 == Some(first),
        "CiphertextReplayCreatedAnotherEvent",
    )?;
    let repeated = run.step("Bob", "ReplayHistory", |_| history(&mut bob, private, None))?;
    ensure(
        repeated
            .events
            .iter()
            .filter(|e| e.operation_id == prepared.action.operation_id)
            .count()
            == 1,
        "DuplicateCiphertextPublication",
    )?;
    bob.disconnect();
    drop(bob);
    let mut bob = run.step("Bob", "ReopenOffline", |_| {
        net(Client::open_offline(&request.bob))
    })?;
    let retained = run.step("Bob", "OfflineEncryptedSearch", |_| {
        search(&mut bob, private, "nativecryptocafé", true)
    })?;
    ensure(
        retained.stale && text(&retained, first, &original),
        "RestartArchiveMismatch",
    )?;
    run.step("Bob", "Reconnect", |_| net(bob.connect()))?;
    let current = run.step("Bob", "CurrentEncryptedSearch", |_| {
        search(&mut bob, private, "nativecryptocafé", false)
    })?;
    ensure(
        !current.stale && text(&current, first, &original),
        "CurrentSearchMismatch",
    )?;
    let now = alice
        .profile
        .clock
        .sample()
        .map_err(|_| "ClockUnavailable")?;
    let scope = delegation::Create {
        agent: agent_actor.clone(),
        rooms: vec![private],
        recipients: vec![],
        operations: vec![
            Operation::MessageSend,
            Operation::MessageReply,
            Operation::HistoryPage,
            Operation::SearchQuery,
        ],
        mode: delegation::Mode::Autonomous,
        not_before_ms: now.lower_ms.saturating_sub(2000),
        expires_ms: now.upper_ms + 900_000,
        history_from_ms: 0,
        history_until_ms: now.upper_ms + 900_000,
        max_operations_per_minute: 120,
        purpose: "Native confidential delegated conversation".into(),
    };
    let (_, body) = committed(run.effect(
        "Alice",
        &mut alice,
        Operation::DelegationCreate,
        Target::Account(alice_id),
        &scope,
    )?)?;
    let reference: GrantRef = body.deserialized().map_err(|_| "GrantReferenceShape")?;
    let grant = run.step("Alice", "InspectGrant", |_| {
        net(alice.inspect_grant(reference)).map(|p| p.inspection.grant)
    })?;
    run.step("Agent", "PublishDelegatedPackage", |_| {
        completed(net(agent.crypto_publish(private, Some(&grant)))?)
    })?;
    let view = run.step("Alice", "TrustDelegatedContact", |_| {
        pin(&mut alice, private, None)
    })?;
    let package = view
        .remote
        .packages
        .iter()
        .find(|p| {
            p.member.credential.actor == agent_actor
                && matches!(p.member.actor, Actor::Delegated { .. })
        })
        .ok_or("DelegatedPackageUnavailable")?
        .digest;
    run.step("Alice", "CommitDelegatedEndpoint", |_| {
        completed(net(alice.crypto_commit(private, &[package], &[], None))?)
    })?;
    run.step("Agent", "TrustDelegatedRoster", |_| {
        pin(&mut agent, private, Some(&grant))
    })?;
    let ready = run.step("Agent", "DelegatedWelcomeReady", |_| {
        net(agent.crypto_sync(private, Some(&grant)))
    })?;
    let keys = ready
        .remote
        .members
        .iter()
        .map(|m| m.credential.mls_key)
        .collect::<BTreeSet<_>>();
    ensure(keys.len() == 3, "IndependentMlsKeys")?;
    for c in [&alice, &bob, &agent] {
        let m = ready
            .remote
            .members
            .iter()
            .find(|m| m.actor.acting().account == c.profile.registration.account)
            .ok_or("RosterEndpointMissing")?;
        ensure(
            m.credential.mls_key != c.profile.registration.endpoint_key
                && m.credential.mls_key != c.profile.registration.recovery_key,
            "MlsKeyReusesOwnerKey",
        )?;
    }
    let past = run.step("Agent", "FutureOnlyHistory", |_| {
        history(&mut agent, private, Some(&grant))
    })?;
    ensure(
        past.events.iter().any(|e| e.event == first),
        "EarlierCiphertextNotInAuthorisedHistory",
    )?;
    ensure(
        !matches!(past.content.get(&first), Some(MessageContent::Decrypted(_))),
        "NewEndpointReceivedPastPlaintext",
    )?;
    let delegated = message("native delegated encrypted reply", vec![]);
    let (agent_event, _) = send(run, "Agent", &mut agent, private, &delegated, Some(&grant))?;
    run.step("Bob", "TrustDelegatedContact", |_| {
        pin(&mut bob, private, None)
    })?;
    let page = run.step("Bob", "ReadDelegatedCiphertext", |_| {
        history(&mut bob, private, None)
    })?;
    ensure(
        text(&page, agent_event, &delegated),
        "DelegatedDecryptionMismatch",
    )?;
    ensure(page.events.iter().any(|e|e.event==agent_event && matches!(e.actor,Actor::Delegated{represented,grant:g,..} if represented==alice_id && g==reference)),"DelegatedAttributionMismatch")?;
    let queued = run.step("Alice", "PrepareBeforeRevocation", |_| {
        net(alice.prepare_send(
            private,
            &message("revocation queued effect", vec![]),
            None,
            false,
            None,
        ))
    })?;
    run.effect(
        "Alice",
        &mut alice,
        Operation::DelegationRevoke,
        Target::Delegation(reference),
        &home::Empty {},
    )
    .and_then(committed)?;
    let barrier = run.step("Alice", "InspectRevocationBarrier", |_| {
        net(alice.crypto_inspect(private, None))
    })?;
    ensure(
        barrier.remote.send_barrier
            && barrier
                .remote
                .required_removals
                .contains(&agent_actor.endpoint),
        "RevocationBarrierMissing",
    )?;
    let mut recovered = 0;
    let rejected = run.step("Alice", "RejectQueuedOldEpoch", |end| {
        execute_exact(
            &mut alice,
            &queued.action,
            &queued.signed,
            end,
            &mut recovered,
        )
    })?;
    run.exact_recoveries += recovered;
    ensure(
        matches!(
            rejected,
            Outcome::Rejected {
                code: ErrorCode::Conflict | ErrorCode::Denied,
                ..
            }
        ),
        "OldEpochWasNotRejected",
    )?;
    run.step("Alice", "FreshSendBlockedByBarrier", |_| {
        match alice.prepare_send(
            private,
            &message("barrier refused draft", vec![]),
            None,
            false,
            None,
        ) {
            Err(client::Error::Rejected {
                code: ErrorCode::Unavailable,
                detail,
            }) if detail == "EncryptedRoomBarrier" => Ok(()),
            _ => Err("FreshSendBarrierNotEnforced".into()),
        }
    })?;
    run.step("Agent", "RevokedGrantReadRefusal", |_| {
        match agent.crypto_inspect(private, Some(&grant)) {
            Err(
                client::Error::Rejected {
                    code: ErrorCode::Denied | ErrorCode::Expired,
                    ..
                }
                | client::Error::Refused {
                    code: ErrorCode::Denied | ErrorCode::Expired,
                    ..
                },
            ) => Ok(()),
            _ => Err("RevokedGrantNotDenied".into()),
        }
    })?;
    run.step("Alice", "CommitRemoval", |_| {
        completed(net(alice.crypto_commit(
            private,
            &[],
            &[agent_actor.endpoint],
            None,
        ))?)
    })?;
    let after = run.step("Bob", "VerifyRemovalEpoch", |_| {
        net(bob.crypto_sync(private, None))
    })?;
    ensure(
        !after.remote.send_barrier
            && after.remote.members.len() == 2
            && !after
                .remote
                .members
                .iter()
                .any(|m| m.credential.actor == agent_actor),
        "RemovalNotVerified",
    )?;
    let after_message = message("after verified removal", vec![]);
    let (after_event, _) = send(run, "Alice", &mut alice, private, &after_message, None)?;
    let after_page = run.step("Bob", "ReadAfterRemoval", |_| {
        history(&mut bob, private, None)
    })?;
    ensure(
        text(&after_page, after_event, &after_message)
            && !after_page
                .events
                .iter()
                .any(|e| e.operation_id == queued.action.operation_id),
        "RevocationPublicationMismatch",
    )?;
    run.effect(
        "Bob",
        &mut bob,
        Operation::ModerationIgnore,
        Target::Account(bob_id),
        &moderation::Filter {
            subject: alice_id,
            enabled: true,
        },
    )
    .and_then(committed)?;
    let hidden = run.step("Bob", "IgnoredEncryptedSearch", |_| {
        search(&mut bob, private, "nativecryptocafé", false)
    })?;
    ensure(hidden.events.is_empty(), "IgnoredPlaintextSearchVisible")?;
    run.effect(
        "Bob",
        &mut bob,
        Operation::ModerationIgnore,
        Target::Account(bob_id),
        &moderation::Filter {
            subject: alice_id,
            enabled: false,
        },
    )
    .and_then(committed)?;
    let direct = room(run.effect(
        "Alice",
        &mut alice,
        Operation::DirectCreate,
        Target::Service,
        &confidential::Direct { recipient: bob_id },
    )?)?;
    join_pair(run, &mut alice, &mut bob, direct)?;
    let dm = message("native confidential direct café", vec![]);
    let (dm_event, _) = send(run, "Alice", &mut alice, direct, &dm, None)?;
    let dm_page = run.step("Bob", "ReadConfidentialDirect", |_| {
        history(&mut bob, direct, None)
    })?;
    ensure(text(&dm_page, dm_event, &dm), "DirectDecryptionMismatch")?;
    devices::workflow(run, request, &mut alice, &mut bob, private, first)?;
    alice.disconnect();
    bob.disconnect();
    agent.disconnect();
    Ok(
        json!({"case":"NativeConfidentialConversations","passed":true,"privateGroup":true,"confidentialDirect":true,"explicitContactPins":true,"independentMlsKeys":3,"unicodeMentions":true,"exactCiphertextReplay":true,"restartLocalSearch":true,"currentIgnore":true,"futureOnlyAdmission":true,"delegatedAttribution":true,"revocationBarrier":true,"oldEpochRejected":true,"verifiedRemoval":true,"deviceEnrolment":true,"deviceDisable":true,"ownerKeyRecovery":true,"recoveryRemovalBarrier":true,"recoveredFutureOnlyReadmission":true,"steps":run.steps,"sameIdentityRecoveries":run.exact_recoveries,"replacementEffectIdentities":0,"intentionalExactCiphertextReplays":1,"noDirectFallback":true}),
    )
}
fn main() {
    let args = Arguments::parse();
    if !(30..=900).contains(&args.maximum_seconds) {
        eprintln!("InvalidMaximumSeconds");
        std::process::exit(2);
    }
    let end = Instant::now() + Duration::from_secs(args.maximum_seconds);
    let observation = Arc::new(Mutex::new(Observation {
        principal: "Fixture",
        operation: "ReadRequest",
        deadline: end.min(Instant::now() + Duration::from_secs(45)),
    }));
    let done = Arc::new(AtomicBool::new(false));
    let watcher = observation.clone();
    let finished = done.clone();
    let watchdog = thread::spawn(move || {
        while !finished.load(Ordering::Acquire) {
            let state = watcher.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if Instant::now() >= end || Instant::now() >= state.deadline {
                eprintln!(
                    "principal={} operation={} status=DeadlineExceeded",
                    state.principal, state.operation
                );
                std::process::exit(124);
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let result = (|| {
        let bytes = hrc::service::files::read(&args.request, 16 * 1024)
            .map_err(|_| "RequestUnavailable")?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| "InvalidRequest")?;
        for path in [&request.alice, &request.bob, &request.agent] {
            ensure(path.is_absolute(), "AbsoluteProfileRequired")?;
        }
        let paths = [&request.alice, &request.bob, &request.agent]
            .into_iter()
            .map(|p| std::fs::canonicalize(p).map_err(|_| "ProfileUnavailable"))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        ensure(paths.len() == 3, "DistinctProfilesRequired")?;
        let mut run = Run {
            end,
            observation,
            steps: 0,
            exact_recoveries: 0,
        };
        workflow(&mut run, &request)
    })();
    done.store(true, Ordering::Release);
    let _ = watchdog.join();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
