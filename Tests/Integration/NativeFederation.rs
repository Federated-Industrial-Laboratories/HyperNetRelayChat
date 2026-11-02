// SPDX-License-Identifier: Apache-2.0
//! Real bilateral clients. Setup/withdrawal use the shipped CLI in NativeFederation.py.
use clap::Parser;
use hrc::{
    client::{self, Client, MessageContent},
    crypto, delegation, home, messaging, moderation,
    protocol::*,
    service::{files, io},
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
#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    request: PathBuf,
    #[arg(long, default_value_t = 900)]
    maximum_seconds: u64,
    #[arg(long)]
    withdrawal: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    alice: PathBuf,
    bob: PathBuf,
    agent: PathBuf,
    community: RoomId,
    private: RoomId,
    direct: RoomId,
    origin_descriptor: PathBuf,
    bob_recovery: PathBuf,
    controls: PathBuf,
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
    replays: u32,
}
impl Run {
    fn step<T>(
        &mut self,
        principal: &'static str,
        operation: &'static str,
        f: impl FnOnce(Instant) -> Result<T>,
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
        thread::sleep(Duration::from_secs(2));
        ensure(Instant::now() < deadline, "StepDeadline")?;
        let value = f(deadline)
            .map_err(|code| format!("principal={principal} operation={operation} status={code}"))?;
        ensure(Instant::now() < deadline, "StepDeadline")?;
        self.steps += 1;
        Ok(value)
    }
    fn effect<T: Serialize>(
        &mut self,
        who: &'static str,
        c: &mut Client,
        op: Operation,
        target: Target,
        body: &T,
    ) -> Result<Outcome> {
        let mut replays = 0;
        let value = self.step(who, "ExactOperation", |end| {
            let action = net(c.prepare_as(op, target, body, None))?;
            let signed = net(c.sign(&action))?;
            exact(c, &action, &signed, end, &mut replays)
        });
        self.replays += replays;
        value
    }
    fn send(
        &mut self,
        who: &'static str,
        c: &mut Client,
        room: RoomId,
        text: &messaging::Send,
        grant: Option<&delegation::Grant>,
    ) -> Result<(Id, client::PreparedSend)> {
        let prepared = self.step(who, "PrepareMessage", |_| {
            net(c.prepare_send(room, text, grant, false, None))
        })?;
        let mut replays = 0;
        let outcome = self.step(who, "SubmitExactMessage", |end| {
            exact(c, &prepared.action, &prepared.signed, end, &mut replays)
        })?;
        self.replays += replays;
        Ok((commit(outcome)?.0.ok_or("MessageEventMissing")?, prepared))
    }
}
fn ensure(ok: bool, code: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(code.into()) }
}
fn net<T>(result: client::Result<T>) -> Result<T> {
    result.map_err(|e| e.code().into())
}
fn retry_delay(error: &client::Error) -> Option<u64> {
    match error {
        client::Error::Refused {
            code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
            retry_after_ms,
            ..
        }
        | client::Error::Network(client::network::Error::ForwardRefused {
            code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
            retry_after_ms,
            ..
        }) => Some(retry_after_ms.unwrap_or(1000)),
        client::Error::Clock | client::Error::Unknown => Some(1000),
        client::Error::Network(error) if error.retryable_session() => Some(1000),
        _ => None,
    }
}
fn pause(end: Instant, ms: u64) -> Result<()> {
    ensure(
        ms <= 60_000 && end.saturating_duration_since(Instant::now()) > Duration::from_millis(ms),
        "RetryGuidanceDeadline",
    )?;
    thread::sleep(Duration::from_millis(ms));
    Ok(())
}
fn exact(
    c: &mut Client,
    action: &Action,
    signed: &[u8],
    end: Instant,
    replays: &mut u32,
) -> Result<Outcome> {
    let digest = action_digest(action).map_err(|_| "ActionDigest")?;
    let mut attempted = false;
    loop {
        ensure(Instant::now() < end, "ExactOperationDeadline")?;
        let pending = attempted
            && !home::is_read_operation(action.operation)
            && net(c.pending())?.iter().any(|p| {
                p.action.action().operation_id == action.operation_id && p.action.digest() == digest
            });
        let result = if pending {
            c.retry_pending(action.operation_id, digest)
        } else {
            c.execute_signed(signed)
        };
        match result {
            Ok(r) => {
                let outcome = if r.operation_id == action.operation_id {
                    ensure(r.action_digest == digest, "ResponseDigest")?;
                    r.outcome
                } else {
                    match r.outcome {
                        Outcome::Result { body } => {
                            let resolved: home::ResolveResult =
                                body.deserialized().map_err(|_| "ResolutionShape")?;
                            ensure(
                                resolved.operation_id == action.operation_id
                                    && resolved.action_digest == digest,
                                "ResolutionBinding",
                            )?;
                            resolved.outcome
                        }
                        Outcome::Refused {
                            code:
                                ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                            retry_after_ms,
                            ..
                        } => {
                            pause(end, retry_after_ms.unwrap_or(1000))?;
                            attempted = true;
                            *replays += 1;
                            continue;
                        }
                        Outcome::Rejected { code, detail }
                        | Outcome::Refused { code, detail, .. } => {
                            return Err(format!("ResolutionRefused:{code:?}:{detail}"));
                        }
                        _ => return Err("ResolutionUnknown".into()),
                    }
                };
                if let Outcome::Refused {
                    code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                    retry_after_ms,
                    ..
                } = outcome
                {
                    pause(end, retry_after_ms.unwrap_or(1000))?
                } else {
                    return Ok(outcome);
                }
            }
            Err(e) => {
                let delay = retry_delay(&e).ok_or_else(|| e.code().to_string())?;
                pause(end, delay)?;
                c.disconnect();
                net(c.connect())?;
            }
        }
        attempted = true;
        *replays += 1;
    }
}
fn commit(outcome: Outcome) -> Result<(Option<Id>, Value)> {
    match outcome {
        Outcome::Committed { event, body, .. } => Ok((event, body)),
        Outcome::Rejected { code, .. } | Outcome::Refused { code, .. } => {
            Err(format!("ExpectedCommit:{code:?}"))
        }
        _ => Err("ExpectedCommit".into()),
    }
}
fn completed(response: Response) -> Result<(Option<Id>, Value)> {
    commit(response.outcome)
}
fn message(text: &str) -> messaging::Send {
    messaging::Send {
        text: text.into(),
        mentions: vec![],
        parent: None,
        causation: None,
    }
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
            limit: 50,
        },
        grant,
    ))
}
fn visible(page: &client::ConversationPage, event: Id, text: &messaging::Send) -> bool {
    matches!(page.content.get(&event),Some(MessageContent::Decrypted(v)) if v.text==text.text&&v.mentions==text.mentions)
}
fn pin(
    c: &mut Client,
    room: RoomId,
    grant: Option<&delegation::Grant>,
) -> Result<client::CryptoView> {
    let view = net(c.crypto_inspect(room, grant))?;
    for contact in &view.contacts {
        match contact.state {
            client::trust::TrustState::UntrustedRegistration => {
                net(c.trust_contact(contact.account, contact.anchor, false))?
            }
            client::trust::TrustState::Trusted => {}
            _ => return Err("UnexpectedContactContinuity".into()),
        }
    }
    Ok(view)
}
fn search(c: &mut Client, room: RoomId, offline: bool) -> Result<client::ConversationPage> {
    let query = messaging::Search {
        terms: vec!["federatedcafé".into()],
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
fn synchronise(
    c: &mut Client,
    room: RoomId,
    grant: Option<&delegation::Grant>,
    end: Instant,
) -> Result<client::CryptoView> {
    loop {
        ensure(Instant::now() < end, "SynchronisationDeadline")?;
        let result = if c.session().is_err() {
            c.connect().and_then(|_| c.crypto_sync(room, grant))
        } else {
            c.crypto_sync(room, grant)
        };
        match result {
            Ok(view) => return Ok(view),
            Err(error) => {
                let delay = retry_delay(&error).ok_or_else(|| error.code().to_string())?;
                if matches!(error, client::Error::Network(_)) {
                    c.disconnect();
                }
                pause(end, delay)?;
            }
        }
    }
}
fn membership_ready(
    c: &mut Client,
    room: RoomId,
    response: Response,
    end: Instant,
) -> Result<(Option<Id>, Value)> {
    let outcome = completed(response)?;
    let view = synchronise(c, room, None, end)?;
    ensure(
        view.local
            .as_ref()
            .is_some_and(|state| state.active && !state.frozen && state.epoch == view.remote.epoch),
        "MembershipAuthorNotCurrent",
    )?;
    Ok(outcome)
}
fn await_ready(run: &mut Run, alice: &mut Client, room: RoomId) -> Result<client::CryptoView> {
    run.step("Alice", "CurrentRecipientFreshness", |end| {
        loop {
            let v = net(alice.crypto_inspect(room, None))?;
            if !v.remote.send_barrier {
                return Ok(v);
            }
            ensure(
                v.remote.required_removals.is_empty(),
                "UnexpectedRequiredRemoval",
            )?;
            pause(end, 1000)?;
        }
    })
}
fn pair(
    run: &mut Run,
    alice: &mut Client,
    bob: &mut Client,
    room: RoomId,
) -> Result<client::CryptoView> {
    commit(run.effect(
        "Bob",
        bob,
        Operation::RoomJoin,
        Target::Room(room),
        &home::Empty {},
    )?)?;
    run.step("Alice", "TrustInitialRoster", |_| pin(alice, room, None))?;
    run.step("Alice", "InitialiseMls", |end| {
        let response = net(alice.crypto_initialise(room, false))?;
        membership_ready(alice, room, response, end)
    })?;
    run.step("Bob", "PublishOriginKeyPackage", |_| {
        completed(net(bob.crypto_publish(room, None))?)
    })?;
    let v = run.step("Alice", "PinOriginContact", |_| pin(alice, room, None))?;
    let ep = net(bob.session())?.ready.acting.endpoint;
    let package = v
        .remote
        .packages
        .iter()
        .find(|p| p.member.credential.actor.endpoint == ep)
        .ok_or("OriginPackageMissing")?
        .digest;
    run.step("Alice", "CommitForeignLeaf", |end| {
        let response = net(alice.crypto_commit(room, &[package], &[], None))?;
        membership_ready(alice, room, response, end)
    })?;
    run.step("Bob", "PinWelcomeRoster", |_| pin(bob, room, None))?;
    run.step("Bob", "VerifyWelcomeAndReady", |end| {
        synchronise(bob, room, None, end)
    })?;
    let v = await_ready(run, alice, room)?;
    ensure(v.remote.members.len() == 2, "PairRosterSize")?;
    Ok(v)
}
struct RecoveredRoom {
    room: RoomId,
    old_event: Id,
    old_actor: EndpointActor,
    recovered: EndpointActor,
    old_roster: client::CryptoView,
}
fn readmit_encrypted_room(
    run: &mut Run,
    alice: &mut Client,
    recovered: &mut Client,
    scenario: RecoveredRoom,
) -> Result<()> {
    let old_anchor = scenario
        .old_roster
        .contacts
        .iter()
        .find(|contact| {
            contact.account == scenario.old_actor.account
                && contact.state == client::trust::TrustState::Trusted
        })
        .ok_or("OriginalPinnedContactMissing")?
        .anchor;
    let old_mls = scenario
        .old_roster
        .remote
        .members
        .iter()
        .find(|member| member.credential.actor == scenario.old_actor)
        .ok_or("OriginalMlsLeafMissing")?
        .credential
        .mls_key;
    let before = run.step("RecoveredBob", "NoInheritedForeignRoomKeys", |_| {
        net(recovered.crypto_inspect(scenario.room, None))
    })?;
    ensure(
        before.local.is_none(),
        "RecoveredForeignEndpointInheritedKeys",
    )?;
    run.step("Alice", "RemoveRecoveredForeignOldLeaf", |end| {
        let response =
            net(alice.crypto_commit(scenario.room, &[], &[scenario.old_actor.endpoint], None))?;
        membership_ready(alice, scenario.room, response, end)
    })?;
    run.step("RecoveredBob", "PublishFutureForeignKeyPackage", |_| {
        completed(net(recovered.crypto_publish(scenario.room, None))?)
    })?;
    let inspected = run.step("Alice", "VerifyPinnedForeignRecoveryContinuity", |_| {
        pin(alice, scenario.room, None)
    })?;
    ensure(
        inspected.contacts.iter().any(|contact| {
            contact.account == scenario.recovered.account
                && contact.anchor == old_anchor
                && contact.state == client::trust::TrustState::Trusted
        }),
        "ForeignRecoveryChangedPinnedAnchor",
    )?;
    let package = inspected
        .remote
        .packages
        .iter()
        .find(|package| package.member.credential.actor == scenario.recovered)
        .ok_or("RecoveredForeignPackageMissing")?;
    ensure(
        package.member.credential.mls_key != old_mls
            && package.member.credential.mls_key != recovered.profile.registration.endpoint_key
            && package.member.credential.mls_key != recovered.profile.registration.recovery_key,
        "RecoveredForeignMlsKeyNotIndependent",
    )?;
    let digest = package.digest;
    run.step("Alice", "ExplicitRecoveredForeignMlsAdmission", |end| {
        let response = net(alice.crypto_commit(scenario.room, &[digest], &[], None))?;
        membership_ready(alice, scenario.room, response, end)
    })?;
    run.step("RecoveredBob", "TrustRecoveredForeignWelcome", |_| {
        pin(recovered, scenario.room, None)
    })?;
    let ready = run.step(
        "RecoveredBob",
        "VerifyRecoveredForeignWelcomeAndReady",
        |end| synchronise(recovered, scenario.room, None, end),
    )?;
    ensure(
        ready
            .local
            .as_ref()
            .is_some_and(|local| local.active && local.epoch == ready.remote.epoch)
            && ready
                .remote
                .members
                .iter()
                .any(|member| member.credential.actor == scenario.recovered)
            && !ready
                .remote
                .members
                .iter()
                .any(|member| member.credential.actor == scenario.old_actor),
        "RecoveredForeignRosterBinding",
    )?;
    await_ready(run, alice, scenario.room)?;
    let old = run.step(
        "RecoveredBob",
        "RetainedForeignCiphertextWithoutOldPlaintext",
        |_| history(recovered, scenario.room, None),
    )?;
    ensure(
        old.events
            .iter()
            .any(|event| event.event == scenario.old_event)
            && !matches!(
                old.content.get(&scenario.old_event),
                Some(MessageContent::Decrypted(_))
            ),
        "RecoveredForeignEndpointReadOldPlaintext",
    )?;
    let future = message("future-only foreign recovered endpoint");
    let (event, prepared) = run.send("Alice", alice, scenario.room, &future, None)?;
    ensure(prepared.encrypted, "RecoveredForeignPlaintextDowngrade")?;
    let received = run.step("RecoveredBob", "DecryptNewForeignRoomMessage", |_| {
        history(recovered, scenario.room, None)
    })?;
    ensure(
        visible(&received, event, &future),
        "RecoveredForeignFutureDecryption",
    )?;
    run.step("Alice", "SettleRecoveredForeignRoomSend", |_| {
        history(alice, scenario.room, None)
    })?;
    Ok(())
}

fn control(run: &mut Run, request: &Request, name: &'static str) -> Result<()> {
    run.step("Fixture", name, |end| {
        let remaining = end.saturating_duration_since(Instant::now()).as_millis() as u64;
        let deadline = hrc::clock::boot_ms().map_err(|_| "ControlClock")? + remaining;
        files::create_json(
            &request.controls.join(format!("{name}.request")),
            &json!({"version":1,"deadlineBootMs":deadline}),
        )
        .map_err(|_| "ControlRequest")?;
        let ack = request.controls.join(format!("{name}.done"));
        while !ack.exists() {
            pause(end, 100)?
        }
        ensure(
            files::read(&ack, 32).map_err(|_| "ControlAck")? == b"HRC/1\n",
            "ControlBinding",
        )
    })
}
fn create_grant(
    run: &mut Run,
    bob: &mut Client,
    agent: EndpointActor,
    rooms: Vec<RoomId>,
    lifetime: u64,
) -> Result<delegation::Grant> {
    let now = bob.profile.clock.sample().map_err(|_| "ClockUnavailable")?;
    let scope = delegation::Create {
        agent,
        rooms,
        recipients: vec![],
        operations: vec![
            Operation::MessageSend,
            Operation::MessageReply,
            Operation::HistoryPage,
            Operation::SearchQuery,
        ],
        mode: delegation::Mode::Autonomous,
        not_before_ms: now.lower_ms.saturating_sub(2000),
        expires_ms: now.upper_ms + lifetime,
        history_from_ms: 0,
        history_until_ms: now.upper_ms + lifetime,
        max_operations_per_minute: 120,
        purpose: "Native bilateral delegated chat".into(),
    };
    let owner = bob.profile.registration.account;
    let (_, body) = commit(run.effect(
        "Bob",
        bob,
        Operation::DelegationCreate,
        Target::Account(owner),
        &scope,
    )?)?;
    let reference = body.deserialized().map_err(|_| "GrantReference")?;
    run.step("Bob", "InspectOwnerSignedGrant", |_| {
        net(bob.inspect_grant(reference)).map(|v| v.inspection.grant)
    })
}
fn denied(outcome: Outcome) -> Result<()> {
    ensure(
        matches!(
            outcome,
            Outcome::Rejected {
                code: ErrorCode::Denied | ErrorCode::Expired,
                ..
            } | Outcome::Refused {
                code: ErrorCode::Denied | ErrorCode::Expired,
                ..
            }
        ),
        "ExpectedSpecificAuthorityRefusal",
    )
}

fn denied_send(c: &mut Client, action: &Action, signed: &[u8], end: Instant) -> Result<()> {
    loop {
        match c.execute_signed(signed) {
            Ok(response) => {
                ensure(
                    response.operation_id == action.operation_id
                        && response.action_digest
                            == action_digest(action).map_err(|_| "ActionDigest")?,
                    "RefusalBinding",
                )?;
                return denied(response.outcome);
            }
            Err(
                client::Error::Refused {
                    code: ErrorCode::Denied | ErrorCode::Expired,
                    ..
                }
                | client::Error::Rejected {
                    code: ErrorCode::Denied | ErrorCode::Expired,
                    ..
                }
                | client::Error::Network(client::network::Error::ForwardRefused {
                    code: ErrorCode::Denied | ErrorCode::Expired,
                    ..
                }),
            ) => return Ok(()),
            Err(error) => {
                let delay = retry_delay(&error).ok_or_else(|| error.code().to_string())?;
                pause(end, delay)?;
                c.disconnect();
                net(c.connect())?;
            }
        }
    }
}

fn workflow(run: &mut Run, r: &Request) -> Result<serde_json::Value> {
    let mut alice = run.step("Alice", "OpenLocal", |_| net(Client::open(&r.alice)))?;
    let mut bob = run.step("Bob", "OpenForeign", |_| net(Client::open(&r.bob)))?;
    let mut agent = run.step("Agent", "OpenForeign", |_| net(Client::open(&r.agent)))?;
    let bob_actor = net(bob.session())?.ready.acting.clone();
    let agent_actor = net(agent.session())?.ready.acting.clone();
    let alice_id = alice.profile.registration.account;
    ensure(
        alice_id.origin != bob_actor.account.origin
            && bob_actor.account.origin == agent_actor.account.origin,
        "IndependentOrigins",
    )?;
    ensure(
        net(bob.session())?.remote.is_some() && net(agent.session())?.remote.is_some(),
        "RealForeignBootstrap",
    )?;
    ensure(
        bob.profile.server.home != bob.profile.active_server().home
            && bob.profile.active_server().home == alice.profile.active_server().home,
        "ForeignSelectionBinding",
    )?;
    for (who, c) in [("Bob", &mut bob), ("Agent", &mut agent)] {
        commit(run.effect(
            who,
            c,
            Operation::RoomJoin,
            Target::Room(r.community),
            &home::Empty {},
        )?)?;
    }
    let public = message("origin public conversation");
    let (public_id, plain) = run.send("Bob", &mut bob, r.community, &public, None)?;
    ensure(!plain.encrypted, "CommunityMode")?;
    let (independent, _) = run.send(
        "Agent",
        &mut agent,
        r.community,
        &message("independent origin bot"),
        None,
    )?;
    let page = run.step("Alice", "InspectForeignAttribution", |_| {
        history(&mut alice, r.community, None)
    })?;
    ensure(
        page.events
            .iter()
            .any(|e| e.event == public_id && e.actor.acting() == &bob_actor),
        "ForeignHumanAttribution",
    )?;
    ensure(page.events.iter().any(|e|e.event==independent&&matches!(&e.actor,Actor::IndependentAgent{acting,operator} if acting==&agent_actor&&*operator==bob_actor.account)),"ForeignAgentOperator")?;
    // Malicious bytes are signed by the actual admitted endpoint; only the origin is altered.
    run.step("Bob", "RejectSignedOriginSubstitution", |_| {
        let mut action = net(bob.prepare_as(
            Operation::MessageSend,
            Target::Room(r.community),
            &message("must never publish"),
            None,
        ))?;
        let Actor::Direct { acting } = &mut action.actor else {
            return Err("ExpectedHumanActor".into());
        };
        acting.account.origin = alice_id.origin;
        let key = files::key(&r.bob.join("Endpoint.key")).map_err(|_| "EndpointKeyUnavailable")?;
        let signed = sign_action(&action, &key).map_err(|_| "TamperedActionEncoding")?;
        let digest = action_digest(&action).map_err(|_| "ActionDigest")?;
        let stream = net(bob.session())?.stream_handle();
        io::send(
            &stream,
            &Frame::new(FrameKind::Action, signed).map_err(|_| "Frame")?,
            Duration::from_secs(10),
        )
        .map_err(|_| "TamperTransport")?;
        let frame = io::receive(&stream, Duration::from_secs(10)).map_err(|_| "TamperTransport")?;
        ensure(
            frame.kind == FrameKind::FederationControl,
            "ExpectedSignedSourceRefusal",
        )?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(bob.profile.server.signing_key.as_bytes())
                .map_err(|_| "OriginKey")?;
        let proof = verify_federation_control(&frame.payload, &key)
            .map_err(|_| "OriginRefusalSignature")?;
        match proof.value() {
            FederationControl::Result {
                request_digest,
                operation,
                outcome:
                    Outcome::Refused {
                        code: ErrorCode::Denied,
                        ..
                    },
                ..
            } if *request_digest == digest && *operation == Operation::FederationExchange => Ok(()),
            _ => Err("OriginSubstitutionNotDenied".into()),
        }
    })?;
    bob.disconnect();
    run.step("Bob", "ReconnectAfterAdversarialFrame", |_| {
        net(bob.connect())
    })?;
    let page = run.step("Alice", "NoSubstitutionEffect", |_| {
        history(&mut alice, r.community, None)
    })?;
    ensure(
        page.events
            .iter()
            .filter(|e| e.kind == Operation::MessageSend)
            .count()
            == 2,
        "UnexpectedCommunityPublication",
    )?;
    for (who, c) in [
        ("Alice", &mut alice),
        ("Bob", &mut bob),
        ("Agent", &mut agent),
    ] {
        run.step(who, "EnrolIndependentMlsKey", |_| {
            completed(net(c.crypto_enrol())?)
        })?;
    }
    let private_roster = pair(run, &mut alice, &mut bob, r.private)?;
    let original = messaging::Send {
        text: "@OriginBob federatedcafé e\u{301} 👩🏽‍🚀 مرحبا".into(),
        mentions: vec![messaging::Mention {
            account: bob_actor.account,
            start: 0,
            end: 10,
        }],
        parent: None,
        causation: None,
    };
    let (first, prepared) = run.send("Alice", &mut alice, r.private, &original, None)?;
    ensure(prepared.encrypted, "PrivatePlaintextDowngrade")?;
    let page = run.step("Bob", "DecryptForeignCiphertext", |_| {
        history(&mut bob, r.private, None)
    })?;
    ensure(
        visible(&page, first, &original),
        "UnicodeMentionsDecryption",
    )?;
    let event = page
        .events
        .iter()
        .find(|e| e.event == first)
        .ok_or("EventMissing")?;
    let envelope: crypto::EncryptedEvent = event
        .body
        .deserialized()
        .map_err(|_| "AuthenticatedCiphertextBody")?;
    ensure(
        envelope.context.operation_id == prepared.action.operation_id
            && !envelope.ciphertext.0.is_empty(),
        "CiphertextContext",
    )?;
    let mut replays = 0;
    let again = run.step("Alice", "ExactCiphertextRetry", |end| {
        exact(
            &mut alice,
            &prepared.action,
            &prepared.signed,
            end,
            &mut replays,
        )
    })?;
    run.replays += replays;
    ensure(commit(again)?.0 == Some(first), "DuplicateCiphertextEffect")?;
    history(&mut alice, r.private, None)?;
    bob.disconnect();
    drop(bob);
    let mut bob = run.step("Bob", "RestartOfflineArchive", |_| {
        net(Client::open_offline(&r.bob))
    })?;
    let retained = run.step("Bob", "RestartEncryptedIndex", |_| {
        search(&mut bob, r.private, true)
    })?;
    ensure(
        retained.stale && visible(&retained, first, &original),
        "RetainedCiphertextArchive",
    )?;
    run.step("Bob", "ReconnectCurrentRead", |_| net(bob.connect()))?;
    let current = run.step("Bob", "CurrentLocalDecryptedSearch", |_| {
        search(&mut bob, r.private, false)
    })?;
    ensure(
        !current.stale && visible(&current, first, &original),
        "CurrentEncryptedSearch",
    )?;
    commit(run.effect(
        "Bob",
        &mut bob,
        Operation::ModerationIgnore,
        Target::Account(bob_actor.account),
        &moderation::Filter {
            subject: alice_id,
            enabled: true,
        },
    )?)?;
    let ignored = run.step("Bob", "CurrentIgnoreFiltersLocalSearch", |_| {
        search(&mut bob, r.private, false)
    })?;
    ensure(
        !ignored.events.iter().any(|e| e.event == first),
        "IgnoredEncryptedSearchLeak",
    )?;
    commit(run.effect(
        "Bob",
        &mut bob,
        Operation::ModerationIgnore,
        Target::Account(bob_actor.account),
        &moderation::Filter {
            subject: alice_id,
            enabled: false,
        },
    )?)?;
    let direct_roster = pair(run, &mut alice, &mut bob, r.direct)?;
    let direct_text = message("confidential cross-network direct");
    let (dm, encrypted) = run.send("Bob", &mut bob, r.direct, &direct_text, None)?;
    ensure(encrypted.encrypted, "DirectPlaintextDowngrade")?;
    ensure(
        visible(
            &run.step("Alice", "DecryptForeignDirect", |_| {
                history(&mut alice, r.direct, None)
            })?,
            dm,
            &direct_text,
        ),
        "DirectDecryption",
    )?;
    history(&mut bob, r.direct, None)?;
    // Only the running origin publishes leases. Stopping it must not remove valid MLS leaves.
    let pending = run.step("Alice", "PrepareBeforeLeaseLoss", |_| {
        net(alice.prepare_send(
            r.private,
            &message("exact after origin outage"),
            None,
            false,
            None,
        ))
    })?;
    control(run, r, "PauseOrigin")?;
    run.step("Alice", "ObserveOriginalLeaseExpiry", |end| {
        pause(end, 6000)?;
        Ok(())
    })?;
    let barrier = run.step("Alice", "InspectAvailabilityBarrier", |_| {
        net(alice.crypto_inspect(r.private, None))
    })?;
    ensure(
        barrier.remote.send_barrier && barrier.remote.required_removals.is_empty(),
        "LeaseExpiryBecameIdentityRemoval",
    )?;
    let refusal = run.step("Alice", "UnavailableDoesNotConsumeCiphertext", |_| {
        net(alice.execute_signed(&pending.signed))
    })?;
    ensure(
        matches!(refusal.outcome,Outcome::Refused{code:ErrorCode::Unavailable,ref detail,..} if detail=="OriginIdentityFreshnessUnavailable"),
        "LeaseLossNotNonConsuming",
    )?;
    ensure(
        net(alice.pending())?
            .iter()
            .any(|p| p.action.action().operation_id == pending.action.operation_id),
        "PendingCiphertextLost",
    )?;
    control(run, r, "ResumeOrigin")?;
    await_ready(run, &mut alice, r.private)?;
    let mut replays = 0;
    let resumed = run.step("Alice", "RetryExactCiphertextAfterLeaseRenewal", |end| {
        exact(
            &mut alice,
            &pending.action,
            &pending.signed,
            end,
            &mut replays,
        )
    })?;
    run.replays += replays;
    let resumed_id = commit(resumed)?.0.ok_or("ResumedEvent")?;
    bob.disconnect();
    run.step("Bob", "ReconnectAfterOriginRestart", |_| net(bob.connect()))?;
    agent.disconnect();
    run.step("Agent", "ReconnectAfterOriginRestart", |_| {
        net(agent.connect())
    })?;
    let page = run.step("Bob", "OneResumedCiphertextEvent", |_| {
        history(&mut bob, r.private, None)
    })?;
    ensure(
        page.events
            .iter()
            .filter(|e| e.operation_id == pending.action.operation_id && e.event == resumed_id)
            .count()
            == 1,
        "ResumeDuplicate",
    )?;
    history(&mut alice, r.private, None)?;
    let grant = create_grant(
        run,
        &mut bob,
        agent_actor.clone(),
        vec![r.private, r.community],
        600_000,
    )?;
    run.step("Agent", "PublishDelegatedForeignPackage", |_| {
        completed(net(agent.crypto_publish(r.private, Some(&grant)))?)
    })?;
    let view = run.step("Alice", "PinOwnerAuthorizedForeignDelegation", |_| {
        pin(&mut alice, r.private, None)
    })?;
    let package = view
        .remote
        .packages
        .iter()
        .find(|p| {
            p.member.credential.actor == agent_actor
                && matches!(p.member.actor, Actor::Delegated { .. })
        })
        .ok_or("DelegatedPackage")?
        .digest;
    run.step("Alice", "AddForeignDelegatedLeaf", |end| {
        let response = net(alice.crypto_commit(r.private, &[package], &[], None))?;
        membership_ready(&mut alice, r.private, response, end)
    })?;
    run.step("Agent", "PinDelegatedWelcome", |_| {
        pin(&mut agent, r.private, Some(&grant))
    })?;
    let ready = run.step("Agent", "DelegatedWelcomeAndReady", |end| {
        synchronise(&mut agent, r.private, Some(&grant), end)
    })?;
    run.step("Bob", "AdvanceAfterAgentAdmission", |end| {
        synchronise(&mut bob, r.private, None, end)
    })?;
    ensure(
        ready
            .remote
            .members
            .iter()
            .map(|m| m.credential.mls_key)
            .collect::<BTreeSet<_>>()
            .len()
            == 3,
        "DistinctMlsKeys",
    )?;
    let old = run.step("Agent", "FutureOnlyDelegatedHistory", |_| {
        history(&mut agent, r.private, Some(&grant))
    })?;
    ensure(
        !matches!(old.content.get(&first), Some(MessageContent::Decrypted(_))),
        "AgentReceivedPriorKeys",
    )?;
    await_ready(run, &mut alice, r.private)?;
    let reply = message("foreign delegated encrypted reply");
    let (reply_id, cipher) = run.send("Agent", &mut agent, r.private, &reply, Some(&grant))?;
    ensure(cipher.encrypted, "DelegatedPlaintextDowngrade")?;
    let page = run.step("Alice", "DecryptForeignDelegatedAttribution", |_| {
        history(&mut alice, r.private, None)
    })?;
    ensure(visible(&page,reply_id,&reply)&&page.events.iter().any(|e|e.event==reply_id&&matches!(&e.actor,Actor::Delegated{acting,represented,grant:reference,..} if acting==&agent_actor&&*represented==bob_actor.account&&*reference==grant.reference)),"ForeignDelegationAttribution")?;
    history(&mut agent, r.private, Some(&grant))?;
    let scope = run.step("Agent", "RefuseDelegatedOutOfScope", |end| {
        let action = net(agent.prepare_as(
            Operation::MessageAction,
            Target::Room(r.community),
            &message("outside grant"),
            Some(&grant),
        ))?;
        let signed = net(agent.sign(&action))?;
        denied_send(&mut agent, &action, &signed, end)
    });
    scope?;
    commit(run.effect(
        "Bob",
        &mut bob,
        Operation::DelegationRevoke,
        Target::Delegation(grant.reference),
        &home::Empty {},
    )?)?;
    let barrier = run.step("Alice", "RemoteRevocationBarrier", |_| {
        net(alice.crypto_inspect(r.private, None))
    })?;
    ensure(
        barrier.remote.send_barrier
            && barrier
                .remote
                .required_removals
                .contains(&agent_actor.endpoint),
        "RemoteGrantBarrier",
    )?;
    run.step("Alice", "RemoveRevokedForeignLeaf", |end| {
        let response = net(alice.crypto_commit(r.private, &[], &[agent_actor.endpoint], None))?;
        membership_ready(&mut alice, r.private, response, end)
    })?;
    run.step("Bob", "VerifyForeignLeafRemoval", |end| {
        synchronise(&mut bob, r.private, None, end)
    })?;
    await_ready(run, &mut alice, r.private)?;
    let expiring = create_grant(
        run,
        &mut bob,
        agent_actor.clone(),
        vec![r.community],
        15_000,
    )?;
    let action = net(agent.prepare_as(
        Operation::MessageSend,
        Target::Room(r.community),
        &message("expired remote grant"),
        Some(&expiring),
    ))?;
    let signed = net(agent.sign(&action))?;
    run.step("Agent", "OriginalGrantExpiry", |end| {
        let now = agent
            .profile
            .clock
            .sample()
            .map_err(|_| "ClockUnavailable")?;
        pause(
            end,
            expiring.scope.expires_ms.saturating_sub(now.lower_ms) + 1000,
        )?;
        denied_send(&mut agent, &action, &signed, end)
    })?;
    // Recovery happens at the origin. There is deliberately no checkpoint-import callback.
    let queued = run.step("Bob", "PrepareBeforeOriginRecovery", |_| {
        let action = net(bob.prepare_as(
            Operation::MessageSend,
            Target::Room(r.community),
            &message("old generation"),
            None,
        ))?;
        let signed = net(bob.sign(&action))?;
        Ok((action, signed))
    })?;
    let recovery = r.controls.join("RecoveredBob");
    run.step("Bob", "PrepareOwnerRecoveryAtOrigin", |_| {
        client::devices::prepare(client::devices::Prepare {
            directory: &recovery,
            server: &r.origin_descriptor,
            account: bob_actor.account,
            principal: bob.profile.registration.transport_principal,
            companion: bob.profile.companion.clone(),
            clock: bob.profile.clock.clone(),
            purpose: DevicePurpose::Recover,
            replacement: None,
            request_output: &r.controls.join("RecoveryRequest.cbor"),
        })
        .map_err(|_| "RecoveryPreparation".to_string())
    })?;
    let recovered = run.step("Bob", "ProveNewEndpointAndOwnerKey", |end| {
        loop {
            match client::devices::activate(&recovery, Some(&r.bob_recovery)) {
                Ok(receipt) => return commit(receipt.outcome),
                Err(client::devices::Error::Authority | client::devices::Error::Unknown) => {
                    pause(end, 1000)?
                }
                Err(_) => return Err("OriginRecoveryRefused".into()),
            }
        }
    })?;
    let recovered: DeviceActivated = recovered.1.deserialized().map_err(|_| "RecoveryReceipt")?;
    ensure(
        recovered.identity.security_generation > bob_actor.security_generation,
        "RecoveryGeneration",
    )?;
    let changed = run.step("Alice", "AutomaticRunningOriginRecoveryFence", |end| {
        loop {
            let view = net(alice.crypto_inspect(r.private, None))?;
            if view.remote.required_removals.contains(&bob_actor.endpoint) {
                return Ok(view);
            }
            pause(end, 500)?;
        }
    })?;
    ensure(changed.remote.send_barrier, "RecoveryMustFenceCiphertext")?;
    run.step("Bob", "OldGenerationQueuedEffectRefused", |end| {
        denied_send(&mut bob, &queued.0, &queued.1, end)
    })?;
    let page = run.step("Alice", "NoExpiredOrRecoveredEffect", |_| {
        history(&mut alice, r.community, None)
    })?;
    ensure(
        !page.events.iter().any(|e| {
            e.operation_id == action.operation_id || e.operation_id == queued.0.operation_id
        }),
        "RevokedAuthorityPublished",
    )?;
    let recovered_actor = recovered
        .endpoint
        .clone()
        .ok_or("RecoveredEndpointMissing")?;
    ensure(
        recovered_actor.account == bob_actor.account
            && recovered_actor.endpoint != bob_actor.endpoint
            && recovered_actor.security_generation == recovered.identity.security_generation,
        "RecoveredForeignIdentityBinding",
    )?;
    run.step("RecoveredBob", "RequestExplicitForeignReadmission", |_| {
        files::create_json(&r.controls.join("RecoveredEndpoint.json"), &recovered_actor)
            .map_err(|_| "ReadmissionControlStorage".into())
    })?;
    alice.disconnect();
    bob.disconnect();
    agent.disconnect();
    control(run, r, "StopForRecoveredAdmission")?;
    control(run, r, "AdmitRecoveredBob")?;
    control(run, r, "ResumeAfterRecoveredAdmission")?;
    run.step("Alice", "ReconnectAfterExplicitHomeAdmission", |_| {
        net(alice.connect())
    })?;
    run.step("Agent", "ReconnectAfterExplicitHomeAdmission", |_| {
        net(agent.connect())
    })?;
    let mut new_bob = run.step("RecoveredBob", "AuthenticateNewForeignEndpoint", |_| {
        net(Client::open(&recovery))
    })?;
    let admission: hrc::federation::RemoteAdmission =
        files::json(&r.controls.join("RecoveredAdmission.json"))
            .map_err(|_| "RecoveredAdmissionReceipt")?;
    let session = net(new_bob.session())?;
    let remote = session
        .remote
        .as_ref()
        .ok_or("RecoveredForeignBootstrapMissing")?;
    ensure(
        session.ready.acting == recovered_actor
            && remote.acting == recovered_actor
            && remote.admission == admission.reference
            && admission.acting == recovered_actor
            && !admission.withdrawn
            && remote.agreement == admission.agreement
            && new_bob.profile.server.home == bob.profile.server.home
            && new_bob.profile.active_server().home == alice.profile.active_server().home,
        "RecoveredForeignAdmissionBinding",
    )?;
    run.step(
        "RecoveredBob",
        "EnrolIndependentRecoveredForeignMlsKey",
        |_| completed(net(new_bob.crypto_enrol())?),
    )?;
    readmit_encrypted_room(
        run,
        &mut alice,
        &mut new_bob,
        RecoveredRoom {
            room: r.private,
            old_event: first,
            old_actor: bob_actor.clone(),
            recovered: recovered_actor.clone(),
            old_roster: private_roster,
        },
    )?;
    readmit_encrypted_room(
        run,
        &mut alice,
        &mut new_bob,
        RecoveredRoom {
            room: r.direct,
            old_event: dm,
            old_actor: bob_actor.clone(),
            recovered: recovered_actor,
            old_roster: direct_roster,
        },
    )?;
    new_bob.disconnect();
    // This independent endpoint remains eligible after its operator's human-key recovery.
    run.step(
        "Agent",
        "CurrentIndependentEndpointBeforeWithdrawal",
        |end| {
            // Human device recovery leaves this independent endpoint idle.
            net(agent.connect())?;
            ensure(Instant::now() < end, "IndependentEndpointReadDeadline")?;
            net(agent.read_as::<hrc::conversations::Inspection, _>(
                Operation::RoomInspect,
                Target::Room(r.community),
                &home::Empty {},
                None,
            ))
        },
    )?;
    run.step("Agent", "PreserveExactWithdrawalDraft", |_| {
        let draft = message("draft withheld by agreement withdrawal");
        net(agent.save_draft(r.community, &draft.text))?;
        let action = net(agent.prepare_as(
            Operation::MessageSend,
            Target::Room(r.community),
            &draft,
            None,
        ))?;
        let signed = net(agent.sign(&action))?;
        files::create(&r.controls.join("WithdrawalCandidate.cbor"), &signed)
            .map_err(|_| "WithdrawalCandidateStorage".into())
    })?;
    Ok(
        json!({"status":"Passed","steps":run.steps,"exactRecoveries":run.replays,"independentNetworks":2,
        "remoteHuman":true,"remoteIndependentAgent":true,"remoteDelegation":true,"privateGroup":true,"direct":true,
        "exactCiphertextRetry":true,"leaseExpiryNonConsuming":true,"automaticOriginRecoveryFence":true,
        "originTamperingRefused":true,"expiredDelegationRefused":true,
        "foreignRecoveredAdmission":true,"foreignRecoveredPrivateGroup":true,"foreignRecoveredDirect":true,
        "recoveredFutureOnlyDecryption":true}),
    )
}
fn withdrawn(run: &mut Run, r: &Request) -> Result<serde_json::Value> {
    let mut agent = run.step("Agent", "OpenRetainedWithdrawalDraft", |_| {
        net(Client::open_offline(&r.agent))
    })?;
    let signed = files::read(
        &r.controls.join("WithdrawalCandidate.cbor"),
        ORDINARY_FRAME_BYTES,
    )
    .map_err(|_| "WithdrawalCandidateStorage")?;
    let key = files::key(&r.agent.join("Endpoint.key")).map_err(|_| "EndpointKeyUnavailable")?;
    let candidate =
        verify_action(&signed, &key.verifying_key()).map_err(|_| "WithdrawalCandidateBinding")?;
    ensure(
        candidate.action().actor.acting().account == agent.profile.registration.account
            && candidate.action().target == Target::Room(r.community),
        "WithdrawalCandidateBinding",
    )?;
    run.step("Agent", "SignedAgreementWithdrawalRefusal", |end| {
        loop {
            match agent.connect() {
                Err(client::Error::Network(client::network::Error::ForwardRefused {
                    code: ErrorCode::Denied,
                    detail,
                    ..
                })) if detail == "AgreementWithdrawn" => return Ok(()),
                Err(error) => pause(
                    end,
                    retry_delay(&error).ok_or_else(|| error.code().to_string())?,
                )?,
                Ok(()) => return Err("WithdrawnAgreementAdmittedEndpoint".into()),
            }
        }
    })?;
    ensure(
        net(agent.draft(r.community))?.as_deref() == Some("draft withheld by agreement withdrawal"),
        "WithdrawalLostDraft",
    )?;
    let mut alice = run.step("Alice", "InspectWithdrawalHistory", |_| {
        net(Client::open(&r.alice))
    })?;
    let page = run.step("Alice", "NoWithdrawnPublication", |_| {
        history(&mut alice, r.community, None)
    })?;
    ensure(
        !page
            .events
            .iter()
            .any(|e| e.operation_id == candidate.action().operation_id),
        "WithdrawnPublication",
    )?;
    Ok(
        json!({"status":"Passed","agreementWithdrawn":true,"signedRefusal":true,"draftPreserved":true,"noPublication":true}),
    )
}

fn main() {
    let args = Arguments::parse();
    if !(60..=1200).contains(&args.maximum_seconds) {
        eprintln!("InvalidMaximumSeconds");
        std::process::exit(2)
    }
    let end = Instant::now() + Duration::from_secs(args.maximum_seconds);
    let observation = Arc::new(Mutex::new(Observation {
        principal: "Fixture",
        operation: "ReadRequest",
        deadline: end.min(Instant::now() + Duration::from_secs(45)),
    }));
    let done = Arc::new(AtomicBool::new(false));
    let watch = observation.clone();
    let finished = done.clone();
    let watchdog = thread::spawn(move || {
        while !finished.load(Ordering::Acquire) {
            let state = watch.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if Instant::now() >= end || Instant::now() >= state.deadline {
                eprintln!(
                    "principal={} operation={} status=DeadlineExceeded",
                    state.principal, state.operation
                );
                std::process::exit(124)
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let result = (|| {
        let bytes = files::read(&args.request, 16384).map_err(|_| "RequestUnavailable")?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| "InvalidRequest")?;
        for p in [
            &request.alice,
            &request.bob,
            &request.agent,
            &request.controls,
        ] {
            ensure(p.is_absolute(), "AbsolutePathsRequired")?;
            files::directory(p, false).map_err(|_| "PrivateDirectoryRequired")?;
        }
        let mut run = Run {
            end,
            observation,
            steps: 0,
            replays: 0,
        };
        if args.withdrawal {
            withdrawn(&mut run, &request)
        } else {
            workflow(&mut run, &request)
        }
    })();
    done.store(true, Ordering::Release);
    let _ = watchdog.join();
    match result {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1)
        }
    }
}
