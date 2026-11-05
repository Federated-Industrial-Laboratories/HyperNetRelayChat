// SPDX-License-Identifier: Apache-2.0
//! Real guarded stores and signatures, with explicitly synthetic transport evidence.
//! These domain tests do not claim two-network HyperNet qualification.
use super::*;
use crate::federation as fed;
use std::time::{Duration, Instant};
#[path = "Confidential.rs"]
mod confidential;
#[path = "Discovery.rs"]
mod discovery;
#[path = "Freshness.rs"]
mod freshness;
#[path = "Identities.rs"]
mod identities;

#[derive(Clone)]
struct RemoteParty {
    key: SigningKey,
    record: EndpointRecord,
    session: AuthenticatedSession,
    window: Option<RetryWindow>,
}
struct Pair {
    home: Home,
    origin: Home,
    _home_fixture: Fixture,
    _origin_fixture: Fixture,
    remote: RemoteParty,
    local: Party,
    room: RoomId,
    agreement: fed::AgreementState,
    gateway: fed::GatewayContext,
    attestor: SigningKey,
    last_challenge: Option<Instant>,
}
fn privacy() -> FederationPrivacy {
    FederationPrivacy {
        endpoint_mode: Some(2),
        transport_protection: Some(FederationProtection::Tls13FinalService),
        relay_arrival: FederationRelay::Unknown,
        relay_service: None,
        attachment_profile_digest: None,
        provenance: "endpointAttestedArrival".into(),
        physical_independence_verified: false,
        profile_currentness_asserted: false,
    }
}
fn enrol_origin(home: &mut Home, n: u8, class: AccountClass) -> RemoteParty {
    let key = SigningKey::from_bytes(&[n; 32]);
    let recovery = SigningKey::from_bytes(&[n + 100; 32]);
    let principal = id(n + 50);
    let invitation = home
        .issue_invitation(principal, class.clone(), TimeBounds::test_now())
        .unwrap();
    let registration = AccountRegistration {
        home: home.service_id(),
        account: AccountId {
            origin: home.service_id().network,
            local: id(n),
        },
        endpoint: id(n + 1),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: principal,
        recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        classification: class,
        invitation: invitation.id,
    };
    let record = home
        .accept_registration(
            &verify_registration_request(&sign_registration(&registration, &key).unwrap()).unwrap(),
            TimeBounds::test_now(),
        )
        .unwrap();
    let session = AuthenticatedSession::new(&record, principal, id(n + 2), 1).unwrap();
    RemoteParty {
        key,
        record,
        session,
        window: None,
    }
}
fn accept_agreement(
    home: &mut Home,
    origin: &mut Home,
    agreement: &FederationAgreement,
    gateway_key: &SigningKey,
) -> (fed::AgreementState, fed::GatewayContext) {
    let hs = sign_agreement(agreement, home.signing_key()).unwrap();
    let os = sign_agreement(agreement, origin.signing_key()).unwrap();
    let pins = fed::AgreementPins {
        home: agreement.home,
        origin: agreement.origin,
        home_key: agreement.home_service_key,
        origin_key: agreement.origin_service_key,
        origin_attestor: agreement.origin_attestor_key,
    };
    let accepted = home
        .federation_accept(&hs, &os, &pins, TimeBounds::test_now())
        .unwrap();
    origin
        .federation_accept(&hs, &os, &pins, TimeBounds::test_now())
        .unwrap();
    let transport = fed::GatewayTransport {
        network: agreement.home.network,
        destination: agreement.home,
        principal: id(81),
        service_endpoint: id(82),
        session: id(85),
        generation: 1,
    };
    let t = TimeBounds::test_now();
    let challenge = GatewayMessage::Challenge {
        profile: 1,
        agreement: accepted.reference,
        gateway: id(81),
        receiver: agreement.home,
        client_nonce: id(86),
        server_nonce: id(87),
        service_boot: id(88),
        principal: id(81),
        session: id(85),
        transport_generation: 1,
        issued_ms: t.lower_ms,
        expires_ms: t.lower_ms + 5000,
    };
    let signed = verify_gateway_message(
        &sign_gateway_message(&challenge, home.signing_key()).unwrap(),
        &home.signing_key().verifying_key(),
    )
    .unwrap();
    let proof = GatewayMessage::Proof {
        profile: 1,
        agreement: accepted.reference,
        challenge_digest: signed.digest(),
    };
    let proof = verify_gateway_message(
        &sign_gateway_message(&proof, gateway_key).unwrap(),
        &gateway_key.verifying_key(),
    )
    .unwrap();
    let gateway = fed::GatewayContext::verify(
        &verify_agreement(&hs, &home.signing_key().verifying_key()).unwrap(),
        transport,
        &signed,
        &proof,
        TimeBounds::test_now(),
    )
    .unwrap();
    (accepted, gateway)
}
impl Pair {
    fn new() -> Self {
        Self::with_mode(RoomConfidentiality::Community)
    }
    fn with_mode(mode: RoomConfidentiality) -> Self {
        let hf = Fixture::new();
        let of = Fixture::new();
        let mut home = hf.create();
        let origin_id = ServiceId {
            network: NetworkId {
                network: id(40),
                incarnation: id(41),
            },
            service: id(42),
        };
        let store = Store::create(
            of.root.join("Data"),
            of.root.join("Guard"),
            &of.key,
            *origin_id.service.as_bytes(),
            storage::Limits::default(),
        )
        .unwrap();
        let mut origin = Home::create(store, origin_id, SigningKey::from_bytes(&[43; 32])).unwrap();
        let local = enrol(&mut home, 8, AccountClass::Human);
        let created = run(
            &mut home,
            &local,
            &action(
                &local,
                Operation::RoomCreate,
                Target::Service,
                &conversations::Create {
                    name: "federation".into(),
                    confidentiality: mode,
                },
            ),
        );
        let Outcome::Committed { body, .. } = created else {
            panic!("room creation")
        };
        let room = body
            .deserialized::<messaging::Committed>()
            .unwrap()
            .room
            .unwrap();
        let remote = enrol_origin(&mut origin, 12, AccountClass::Human);
        let gk = SigningKey::from_bytes(&[70; 32]);
        let reverse = SigningKey::from_bytes(&[71; 32]);
        let attestor = SigningKey::from_bytes(&[72; 32]);
        let t = TimeBounds::test_now();
        let agreement = FederationAgreement {
            profile: 1,
            id: id(80),
            revision: 1,
            home: home.service_id(),
            origin: origin_id,
            home_gateway: GatewayBinding {
                network: home.service_id().network,
                destination: home.service_id(),
                principal: id(81),
                service_endpoint: id(82),
                signing_key: Id::from_bytes(gk.verifying_key().to_bytes()),
                protocol: PROTOCOL.into(),
            },
            origin_gateway: GatewayBinding {
                network: origin_id.network,
                destination: origin_id,
                principal: id(83),
                service_endpoint: id(84),
                signing_key: Id::from_bytes(reverse.verifying_key().to_bytes()),
                protocol: PROTOCOL.into(),
            },
            home_service_key: Id::from_bytes(home.signing_key().verifying_key().to_bytes()),
            origin_service_key: Id::from_bytes(origin.signing_key().verifying_key().to_bytes()),
            origin_attestor_key: Id::from_bytes(attestor.verifying_key().to_bytes()),
            rooms: vec![SharedRoom {
                room,
                history_from_ms: 0,
                retention_ms: RETENTION,
                storage: StorageLocations::HomeOnly,
                confidentiality: mode,
                privacy: PrivacyRequirement::SupportedHyperNetRoute,
                moderator_accounts: Vec::new(),
            }],
            not_before_ms: t.lower_ms,
            expires_ms: t.lower_ms + DAY,
        };
        let (accepted, gateway) = accept_agreement(&mut home, &mut origin, &agreement, &gk);
        Self {
            home,
            origin,
            _home_fixture: hf,
            _origin_fixture: of,
            remote,
            local,
            room,
            agreement: accepted,
            gateway,
            attestor,
            last_challenge: None,
        }
    }
    fn import(&mut self, p: &RemoteParty) -> Id {
        let checkpoint = self
            .origin
            .federation_checkpoint(
                p.record.acting.account,
                self.agreement.reference,
                TimeBounds::test_now(),
            )
            .unwrap();
        let cp = verify_origin_identity_checkpoint(
            &checkpoint.0,
            &self.origin.signing_key().verifying_key(),
        )
        .unwrap();
        let mut after = 0;
        loop {
            let page = self
                .origin
                .federation_identity_page(
                    self.agreement.reference,
                    cp.digest(),
                    after,
                    4,
                    TimeBounds::test_now(),
                )
                .unwrap();
            let decoded =
                verify_origin_identity_page(&page.0, &self.origin.signing_key().verifying_key())
                    .unwrap();
            let complete = self
                .home
                .federation_import_identity(
                    self.agreement.reference,
                    &fed::IdentityImport {
                        checkpoint: checkpoint.clone(),
                        page,
                        trust_anchor: Some(fed::TrustAnchor {
                            anchor: cp.value().anchor_digest,
                            legacy: false,
                        }),
                    },
                    TimeBounds::test_now(),
                )
                .unwrap();
            if complete {
                break;
            }
            after = decoded.value().next;
        }
        cp.digest()
    }
    fn admit(&mut self, p: &RemoteParty) -> fed::RemoteAdmission {
        self.admit_rooms(p, vec![self.room], 0)
    }
    fn admit_rooms(
        &mut self,
        p: &RemoteParty,
        rooms: Vec<RoomId>,
        expected_revision: u64,
    ) -> fed::RemoteAdmission {
        let cp = self.import(p);
        let admitted = self
            .home
            .federation_admit(
                &fed::AdmitEndpoint {
                    agreement: self.agreement.reference,
                    account: p.record.acting.account,
                    endpoint: p.record.acting.endpoint,
                    binding_digest: p.record.acting.binding_digest,
                    checkpoint: cp,
                    rooms,
                    expires_ms: self.agreement.agreement.expires_ms,
                    expected_revision,
                },
                TimeBounds::test_now(),
            )
            .unwrap();
        self.origin
            .federation_acknowledge_identity(
                self.agreement.reference,
                p.record.acting.account,
                cp,
                TimeBounds::test_now(),
            )
            .unwrap();
        self.renew_freshness();
        admitted
    }
    fn renew_freshness(&mut self) {
        let page = self
            .origin
            .federation_watched(
                self.agreement.reference,
                false,
                None,
                32,
                TimeBounds::test_now(),
            )
            .unwrap();
        let checkpoints = page
            .items
            .into_iter()
            .filter(|w| !w.dirty)
            .filter_map(|w| {
                w.acknowledged.map(|checkpoint_digest| CheckpointRef {
                    account: w.account,
                    checkpoint_digest,
                })
            })
            .collect::<Vec<_>>();
        let lease = self
            .origin
            .federation_freshness(
                self.agreement.reference,
                &checkpoints,
                TimeBounds::test_now(),
            )
            .unwrap();
        self.home
            .federation_accept_freshness(&self.gateway, &lease.0, TimeBounds::test_now(), &|| true)
            .unwrap();
    }
    fn challenge(
        &mut self,
        admission: AdmissionRef,
        subject: FederationSubject,
    ) -> Verified<FederationChallenge> {
        // Respect the real shared gateway budget; these are authorization tests.
        if let Some(last) = self.last_challenge
            && let Some(wait) = Duration::from_millis(510).checked_sub(last.elapsed())
        {
            std::thread::sleep(wait)
        }
        self.last_challenge = Some(Instant::now());
        let bytes = self
            .home
            .federation_challenge(
                &self.gateway,
                admission,
                subject,
                TimeBounds::test_now(),
                &|| true,
            )
            .unwrap();
        verify_federation_challenge(&bytes.0, &self.home.signing_key().verifying_key()).unwrap()
    }
    fn assertion(
        &mut self,
        source: &fed::OriginSubject,
        challenge: &Verified<FederationChallenge>,
        p: &RemoteParty,
    ) -> Blob {
        self.origin
            .federation_origin_current(source, &p.session, TimeBounds::test_now())
            .unwrap();
        let t = TimeBounds::test_now();
        let s = OriginAssertion {
            profile: 1,
            origin: self.origin.service_id(),
            home: self.home.service_id(),
            agreement: self.agreement.reference,
            admission: challenge.value().admission,
            subject: source.subject.clone(),
            checkpoints: source.checkpoints.clone(),
            source_privacy: privacy(),
            challenge_digest: challenge.digest(),
            endpoint_binding_digest: p.record.acting.binding_digest,
            endpoint: p.record.acting.endpoint,
            security_generation: p.record.acting.security_generation,
            enrolment_generation: p.record.acting.enrolment_generation,
            transport_network: self.origin.service_id().network,
            transport_principal: p.record.principal,
            transport_session: p.session.session,
            transport_generation: 1,
            transport_grant: id(90),
            transport_grant_generation: 1,
            source_service_boot: id(91),
            control_generation: 1,
            companion_instance: id(92),
            endpoint_instance: id(93),
            permit_nonce: id(94),
            authority: AuthorityEvidence {
                configuration: id(95),
                epoch: 1,
                height: 1,
                state: id(96),
                statement_digest: id(97),
                evaluated_at_ms: t.lower_ms,
                expires_at_ms: t.lower_ms + 5000,
            },
            source_evaluated_ms: t.lower_ms,
            source_not_after_ms: t.lower_ms + 5000,
            source_uncertainty_ms: 0,
        };
        Blob(sign_origin_assertion(&s, &self.attestor).unwrap())
    }
    fn bootstrap(&mut self, p: &mut RemoteParty, admission: AdmissionRef) {
        let t = TimeBounds::test_now();
        let request = RemoteSessionRequest {
            profile: 1,
            home: self.home.service_id(),
            origin: self.origin.service_id(),
            agreement: self.agreement.reference,
            request: Id::random().unwrap(),
            account: p.record.acting.account,
            endpoint: p.record.acting.endpoint,
            endpoint_binding_digest: p.record.acting.binding_digest,
            client_nonce: Id::random().unwrap(),
            created_ms: t.lower_ms,
            expires_ms: t.lower_ms + 60_000,
        };
        let bytes = Blob(sign_remote_session_request(&request, &p.key).unwrap());
        let source = self
            .origin
            .federation_origin_subject(
                &p.session,
                fed::SourceSubject::Session(bytes.clone()),
                self.agreement.reference,
                TimeBounds::test_now(),
            )
            .unwrap();
        let challenge = self.challenge(admission, source.subject.clone());
        let assertion = self.assertion(&source, &challenge, p);
        let receipt = self
            .home
            .federation_open_remote(
                &self.gateway,
                &RemoteSessionExchange {
                    request: bytes,
                    endpoint_binding: source.endpoint_binding,
                    challenge: Blob(challenge.signed_bytes().to_vec()),
                    origin_assertion: assertion,
                },
                &privacy(),
                TimeBounds::test_now(),
                &|| true,
            )
            .unwrap();
        let ready =
            verify_remote_session_ready(&receipt.0, &self.home.signing_key().verifying_key())
                .unwrap();
        p.window = Some(ready.value().window.clone());
    }
    fn action<T: serde::Serialize>(
        &self,
        p: &RemoteParty,
        op: Operation,
        target: Target,
        body: &T,
    ) -> Action {
        Action {
            home: self.home.service_id(),
            operation_id: OperationId {
                window: p.window.as_ref().unwrap().id,
                operation: Id::random().unwrap(),
            },
            actor: match p.record.classification {
                AccountClass::Human => Actor::Direct {
                    acting: p.record.acting.clone(),
                },
                AccountClass::Agent { operator } => Actor::IndependentAgent {
                    acting: p.record.acting.clone(),
                    operator,
                },
            },
            target,
            operation: op,
            body: Value::serialized(body).unwrap(),
            expected: BTreeMap::new(),
            approval: None,
            agreement: Some(self.agreement.reference),
        }
    }
    fn envelope(
        &mut self,
        p: &RemoteParty,
        admission: AdmissionRef,
        action: &Action,
    ) -> FederationEnvelope {
        let bytes = Blob(sign_action(action, &p.key).unwrap());
        let source = self
            .origin
            .federation_origin_subject(
                &p.session,
                fed::SourceSubject::Action(bytes.clone()),
                self.agreement.reference,
                TimeBounds::test_now(),
            )
            .unwrap();
        let challenge = self.challenge(admission, source.subject.clone());
        let assertion = self.assertion(&source, &challenge, p);
        FederationEnvelope {
            profile: 1,
            agreement: self.agreement.reference,
            admission,
            action: bytes,
            endpoint_binding: source.endpoint_binding,
            challenge: Blob(challenge.signed_bytes().to_vec()),
            origin_assertion: assertion,
        }
    }
    fn run(&mut self, envelope: &FederationEnvelope) -> Response {
        let verified = self
            .home
            .federation_verify(
                &self.gateway,
                envelope,
                &privacy(),
                TimeBounds::test_now(),
                &|| true,
            )
            .unwrap();
        self.home
            .execute_remote(&verified, TimeBounds::test_now(), &|| true)
            .unwrap()
    }
}

#[test]
fn foreign_send_uses_home_order_and_exact_retry_consumes_one_challenge() {
    let mut pair = Pair::new();
    let mut remote = pair.remote.clone();
    let admission = pair.admit(&remote);
    pair.bootstrap(&mut remote, admission.reference);
    let join = pair.action(
        &remote,
        Operation::RoomJoin,
        Target::Room(pair.room),
        &Empty {},
    );
    let envelope = pair.envelope(&remote, admission.reference, &join);
    assert!(matches!(
        pair.run(&envelope).outcome,
        Outcome::Committed { .. }
    ));
    let send = pair.action(
        &remote,
        Operation::MessageSend,
        Target::Room(pair.room),
        &messaging::Send {
            text: "远方 · café 👩🏽‍💻".into(),
            mentions: Vec::new(),
            parent: None,
            causation: None,
        },
    );
    let envelope = pair.envelope(&remote, admission.reference, &send);
    let first = pair.run(&envelope);
    assert!(matches!(
        first.outcome,
        Outcome::Committed { event: Some(_), .. }
    ));
    assert!(
        pair.home
            .federation_verify(
                &pair.gateway,
                &envelope,
                &privacy(),
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    let retry = pair.envelope(&remote, admission.reference, &send);
    assert_eq!(
        encode(&first.outcome).unwrap(),
        encode(&pair.run(&retry).outcome).unwrap()
    );
    let events: u64 = pair
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row("SELECT count(*) FROM hrc_events WHERE kind=20", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(events, 1);
    drop(pair.home);
    pair.home = pair._home_fixture.open();
    let retry = pair.envelope(&remote, admission.reference, &send);
    assert_eq!(
        encode(&first.outcome).unwrap(),
        encode(&pair.run(&retry).outcome).unwrap()
    );
}

#[test]
fn foreign_actor_substitution_stale_challenge_and_gateway_loss_refuse_before_effect() {
    let mut pair = Pair::new();
    let mut remote = pair.remote.clone();
    let admission = pair.admit(&remote);
    pair.bootstrap(&mut remote, admission.reference);
    let join = pair.action(
        &remote,
        Operation::RoomJoin,
        Target::Room(pair.room),
        &Empty {},
    );
    let mut envelope = pair.envelope(&remote, admission.reference, &join);
    let mut altered = join.clone();
    altered.actor = Actor::IndependentAgent {
        acting: remote.record.acting.clone(),
        operator: remote.record.acting.account,
    };
    envelope.action = Blob(sign_action(&altered, &remote.key).unwrap());
    assert!(
        pair.home
            .federation_verify(
                &pair.gateway,
                &envelope,
                &privacy(),
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    let envelope = pair.envelope(&remote, admission.reference, &join);
    let checked = pair
        .home
        .federation_verify(
            &pair.gateway,
            &envelope,
            &privacy(),
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    let outcome = pair
        .home
        .execute_remote(&checked, TimeBounds::test_now(), &|| false)
        .unwrap()
        .outcome;
    assert!(matches!(outcome, Outcome::Refused { .. }));
    let nonce = verify_federation_challenge(
        &envelope.challenge.0,
        &pair.home.signing_key().verifying_key(),
    )
    .unwrap()
    .value()
    .nonce;
    let used: bool = pair
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT consumed FROM federation_challenges WHERE nonce=?1",
                [nonce.as_hex()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(!used);
    pair.home
        .store
        .write(|db| {
            db.execute(
                "UPDATE federation_challenges SET deadline=0 WHERE nonce=?1",
                [nonce.as_hex()],
            )?;
            Ok(Commit::new((), b"expire original deadline".to_vec()))
        })
        .unwrap();
    assert!(
        pair.home
            .federation_verify(
                &pair.gateway,
                &envelope,
                &privacy(),
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    let joined: bool = pair
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM hrc_members WHERE account=?1)",
                [remote.record.acting.account.to_string()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(!joined);
}

#[test]
fn remote_grant_keeps_origin_proof_and_current_scope_pause_ban_and_revocation() {
    let mut pair = Pair::new();
    let mut owner = pair.remote.clone();
    let owner_admission = pair.admit(&owner);
    pair.bootstrap(&mut owner, owner_admission.reference);
    let join = pair.action(
        &owner,
        Operation::RoomJoin,
        Target::Room(pair.room),
        &Empty {},
    );
    let env = pair.envelope(&owner, owner_admission.reference, &join);
    assert!(matches!(pair.run(&env).outcome, Outcome::Committed { .. }));
    let mut agent = enrol_origin(
        &mut pair.origin,
        14,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let agent_admission = pair.admit(&agent);
    pair.bootstrap(&mut agent, agent_admission.reference);
    let t = TimeBounds::test_now();
    let create = pair.action(
        &owner,
        Operation::DelegationCreate,
        Target::Account(owner.record.acting.account),
        &delegation::Create {
            agent: agent.record.acting.clone(),
            rooms: vec![pair.room],
            recipients: Vec::new(),
            operations: vec![Operation::MessageSend, Operation::HistoryPage],
            mode: delegation::Mode::Autonomous,
            not_before_ms: t.lower_ms,
            expires_ms: t.lower_ms + 60_000,
            history_from_ms: 0,
            history_until_ms: t.lower_ms + 60_000,
            max_operations_per_minute: 60,
            purpose: "remote room assistance".into(),
        },
    );
    let env = pair.envelope(&owner, owner_admission.reference, &create);
    let Outcome::Committed { body, .. } = pair.run(&env).outcome else {
        panic!("grant was not created")
    };
    let grant: GrantRef = body.deserialized().unwrap();
    let proof: OwnerCheckpointEvidence = pair
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT evidence FROM federation_grant_proofs WHERE grant_id=?1",
                [grant.id.as_hex()],
                |r| decode(&r.get::<_, Vec<u8>>(0)?),
            )
        })
        .unwrap();
    assert_eq!(proof.origin, pair.origin.service_id());
    assert_eq!(
        verify_origin_assertion(&proof.creation_assertion.0, &pair.attestor.verifying_key())
            .unwrap()
            .value()
            .subject,
        FederationSubject::Action {
            action_digest: action_digest(&create).unwrap(),
            operation_id: create.operation_id
        }
    );
    let mut send = pair.action(
        &agent,
        Operation::MessageSend,
        Target::Room(pair.room),
        &messaging::Send {
            text: "delegated remote".into(),
            mentions: Vec::new(),
            parent: None,
            causation: None,
        },
    );
    send.actor = Actor::Delegated {
        acting: agent.record.acting.clone(),
        operator: owner.record.acting.account,
        represented: owner.record.acting.account,
        represented_security_generation: 1,
        grant,
    };
    let env = pair.envelope(&agent, agent_admission.reference, &send);
    assert!(matches!(pair.run(&env).outcome, Outcome::Committed { .. }));
    let mut out_of_scope = send.clone();
    out_of_scope.operation_id.operation = Id::random().unwrap();
    out_of_scope.operation = Operation::MessageAction;
    let env = pair.envelope(&agent, agent_admission.reference, &out_of_scope);
    assert!(matches!(pair.run(&env).outcome,
        Outcome::Rejected { code: ErrorCode::Denied, ref detail, .. } if detail == "GrantOperation"));
    send.operation_id.operation = Id::random().unwrap();
    let queued = pair.envelope(&agent, agent_admission.reference, &send);
    let pause = pair.action(
        &owner,
        Operation::DelegationPause,
        Target::Delegation(grant),
        &Empty {},
    );
    let env = pair.envelope(&owner, owner_admission.reference, &pause);
    let Outcome::Committed { body, .. } = pair.run(&env).outcome else {
        panic!("pause")
    };
    let paused: GrantRef = body.deserialized().unwrap();
    assert!(matches!(
        pair.run(&queued).outcome,
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
    let resume = pair.action(
        &owner,
        Operation::DelegationResume,
        Target::Delegation(paused),
        &Empty {},
    );
    let env = pair.envelope(&owner, owner_admission.reference, &resume);
    let Outcome::Committed { body, .. } = pair.run(&env).outcome else {
        panic!("resume")
    };
    let current: GrantRef = body.deserialized().unwrap();
    if let Actor::Delegated { grant, .. } = &mut send.actor {
        *grant = current;
    }
    send.operation_id.operation = Id::random().unwrap();
    let before_ban = pair.envelope(&agent, agent_admission.reference, &send);
    let restriction = moderation::Restriction {
        subject: owner.record.acting.account,
        enabled: true,
        duration_ms: 60_000,
        reason: "current represented-user policy".into(),
    };
    let ban = action(
        &pair.local,
        Operation::ModerationBan,
        Target::Room(pair.room),
        &restriction,
    );
    assert!(matches!(
        run(&mut pair.home, &pair.local, &ban),
        Outcome::Committed { .. }
    ));
    assert!(matches!(pair.run(&before_ban).outcome,
        Outcome::Rejected { code: ErrorCode::Denied, ref detail, .. } if detail == "RoomBan"));
    let unban = action(
        &pair.local,
        Operation::ModerationBan,
        Target::Room(pair.room),
        &moderation::Restriction {
            enabled: false,
            ..restriction
        },
    );
    assert!(matches!(
        run(&mut pair.home, &pair.local, &unban),
        Outcome::Committed { .. }
    ));
    let rejoin = pair.action(
        &owner,
        Operation::RoomJoin,
        Target::Room(pair.room),
        &Empty {},
    );
    let env = pair.envelope(&owner, owner_admission.reference, &rejoin);
    assert!(matches!(pair.run(&env).outcome, Outcome::Committed { .. }));
    send.operation_id.operation = Id::random().unwrap();
    let before_revoke = pair.envelope(&agent, agent_admission.reference, &send);
    let revoke = pair.action(
        &owner,
        Operation::DelegationRevoke,
        Target::Delegation(current),
        &Empty {},
    );
    let env = pair.envelope(&owner, owner_admission.reference, &revoke);
    assert!(matches!(pair.run(&env).outcome, Outcome::Committed { .. }));
    assert!(matches!(pair.run(&before_revoke).outcome,
        Outcome::Rejected { code: ErrorCode::Denied, ref detail, .. } if detail == "GrantRevoked"));
}

#[test]
fn agreement_withdrawal_is_durable_and_old_admission_cannot_reopen() {
    let mut pair = Pair::new();
    let mut remote = pair.remote.clone();
    let admission = pair.admit(&remote);
    pair.bootstrap(&mut remote, admission.reference);
    let action = pair.action(
        &remote,
        Operation::RoomJoin,
        Target::Room(pair.room),
        &Empty {},
    );
    let queued = pair.envelope(&remote, admission.reference, &action);
    let stopped = pair
        .home
        .federation_withdraw(pair.agreement.reference, TimeBounds::test_now())
        .unwrap();
    assert!(stopped.withdrawn && stopped.barrier_position.is_some());
    assert!(
        pair.home
            .federation_verify(
                &pair.gateway,
                &queued,
                &privacy(),
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    assert!(
        pair.home
            .federation_find_admission(
                &pair.gateway,
                remote.record.acting.account,
                remote.record.acting.endpoint,
                remote.record.acting.binding_digest,
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    drop(pair.home);
    pair.home = pair._home_fixture.open();
    assert!(
        pair.home
            .federation_inspect(pair.agreement.reference)
            .unwrap()
            .withdrawn
    );
    assert!(
        pair.home
            .federation_agreement(pair.agreement.reference, TimeBounds::test_now())
            .is_err()
    );
}

#[test]
fn gateway_withdrawal_rechecks_authority_and_replays_the_original_home_barrier() {
    let mut pair = Pair::new();
    let remote = pair.remote.clone();
    pair.admit(&remote);
    let request_id = Id::random().unwrap();
    let t = TimeBounds::test_now();
    let control = |reason| FederationControl::Request {
        profile: FEDERATION_PROFILE,
        home: pair.agreement.agreement.home,
        origin: pair.agreement.agreement.origin,
        agreement: pair.agreement.reference,
        request: request_id,
        operation: Operation::FederationWithdraw,
        body: Value::serialized(&FederationWithdrawal {
            agreement: pair.agreement.reference,
            request: request_id,
            reason,
        })
        .unwrap(),
        created_ms: t.lower_ms,
        expires_ms: t.lower_ms + 60_000,
    };
    let request = verify_federation_control(
        &sign_federation_control(
            &control(WithdrawalReason::Administrative),
            pair.origin.signing_key(),
        )
        .unwrap(),
        &pair.origin.signing_key().verifying_key(),
    )
    .unwrap();
    let changed = verify_federation_control(
        &sign_federation_control(
            &control(WithdrawalReason::IdentityChange),
            pair.origin.signing_key(),
        )
        .unwrap(),
        &pair.origin.signing_key().verifying_key(),
    )
    .unwrap();
    let calls = std::cell::Cell::new(0);
    let permit = || {
        let n = calls.get();
        calls.set(n + 1);
        n == 0
    };
    assert!(matches!(
        pair.home.federation_withdraw_from_gateway(
            &pair.gateway,
            &request,
            TimeBounds::test_now(),
            &permit,
        ),
        Err(fed::Error::Refused {
            code: ErrorCode::Unavailable,
            ..
        })
    ));
    assert!(
        !pair
            .home
            .federation_inspect(pair.agreement.reference)
            .unwrap()
            .withdrawn
    );
    let receipts: u64 = pair
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row("SELECT count(*) FROM federation_controls", [], |r| r.get(0))
        })
        .unwrap();
    assert_eq!(receipts, 0);
    let first = pair
        .home
        .federation_withdraw_from_gateway(&pair.gateway, &request, TimeBounds::test_now(), &|| true)
        .unwrap();
    assert!(first.withdrawn && first.barrier_position.is_some());
    let repeated = pair
        .home
        .federation_withdraw_from_gateway(&pair.gateway, &request, TimeBounds::test_now(), &|| true)
        .unwrap();
    assert_eq!(first.barrier_position, repeated.barrier_position);
    assert!(matches!(
        pair.home.federation_withdraw_from_gateway(
            &pair.gateway,
            &changed,
            TimeBounds::test_now(),
            &|| true,
        ),
        Err(fed::Error::Refused {
            code: ErrorCode::Conflict,
            ..
        })
    ));
    let receipt = |state: &fed::AgreementState| FederationControl::Result {
        profile: FEDERATION_PROFILE,
        home: pair.agreement.agreement.home,
        origin: pair.agreement.agreement.origin,
        agreement: pair.agreement.reference,
        request: request_id,
        operation: Operation::FederationWithdraw,
        request_digest: request.digest(),
        outcome: Outcome::Result {
            body: Value::serialized(state).unwrap(),
        },
        created_ms: t.lower_ms,
        expires_ms: t.lower_ms + 60_000,
    };
    let acknowledged = verify_federation_control(
        &sign_federation_control(&receipt(&first), pair.home.signing_key()).unwrap(),
        &pair.home.signing_key().verifying_key(),
    )
    .unwrap();
    let mut wrong = first.clone();
    wrong.barrier_position = first.barrier_position.map(|p| p + 1);
    let inconsistent = verify_federation_control(
        &sign_federation_control(&receipt(&wrong), pair.home.signing_key()).unwrap(),
        &pair.home.signing_key().verifying_key(),
    )
    .unwrap();
    assert!(
        pair.origin
            .federation_record_withdrawal_ack(&request, &acknowledged, TimeBounds::test_now())
            .is_err()
    );
    let origin_stop = pair
        .origin
        .federation_withdraw(pair.agreement.reference, TimeBounds::test_now())
        .unwrap();
    assert!(origin_stop.withdrawn && origin_stop.barrier_position.is_none());
    let saved = pair
        .origin
        .federation_record_withdrawal_ack(&request, &acknowledged, TimeBounds::test_now())
        .unwrap();
    assert_eq!(saved.barrier_position, first.barrier_position);
    assert_eq!(
        pair.origin
            .federation_record_withdrawal_ack(&request, &acknowledged, TimeBounds::test_now())
            .unwrap()
            .barrier_position,
        first.barrier_position
    );
    assert!(matches!(
        pair.origin.federation_record_withdrawal_ack(
            &request,
            &inconsistent,
            TimeBounds::test_now()
        ),
        Err(fed::Error::Refused {
            code: ErrorCode::Conflict,
            ..
        })
    ));
}

#[test]
fn exact_admission_retry_keeps_revision_and_public_identity_obeys_room_scope() {
    let mut p = Pair::new();
    let mut remote = p.remote.clone();
    let admission = p.admit(&remote);
    let retry = p.admit(&remote);
    assert_eq!(encode(&admission).unwrap(), encode(&retry).unwrap());
    let reduced = p
        .home
        .federation_admit(
            &fed::AdmitEndpoint {
                agreement: p.agreement.reference,
                account: remote.record.acting.account,
                endpoint: remote.record.acting.endpoint,
                binding_digest: remote.record.acting.binding_digest,
                checkpoint: admission.checkpoint,
                rooms: Vec::new(),
                expires_ms: admission.expires_ms,
                expected_revision: admission.reference.revision,
            },
            TimeBounds::test_now(),
        )
        .unwrap();
    p.bootstrap(&mut remote, reduced.reference);
    let action = p.action(
        &remote,
        Operation::AccountPublicIdentity,
        Target::Account(p.local.record.acting.account),
        &identity::PublicIdentityRequest {
            room: p.room,
            after: 0,
            limit: 1,
            evidence: None,
        },
    );
    let envelope = p.envelope(&remote, reduced.reference, &action);
    assert!(matches!(
        p.home.federation_verify(
            &p.gateway,
            &envelope,
            &privacy(),
            TimeBounds::test_now(),
            &|| true
        ),
        Err(fed::Error::Refused {
            detail: "AdmissionRoomScope",
            ..
        })
    ));
}

#[test]
fn a_room_cannot_bridge_a_third_origin_even_after_its_first_agreement_is_withdrawn() {
    let mut p = Pair::new();
    let key = SigningKey::from_bytes(&[140; 32]);
    let mut other = p.agreement.agreement.clone();
    other.id = id(141);
    other.origin = ServiceId {
        network: NetworkId {
            network: id(142),
            incarnation: id(143),
        },
        service: id(144),
    };
    other.origin_service_key = Id::from_bytes(key.verifying_key().to_bytes());
    other.origin_gateway.network = other.origin.network;
    other.origin_gateway.destination = other.origin;
    let accept = |home: &mut Home, agreement: &FederationAgreement| {
        let hs = sign_agreement(agreement, home.signing_key()).unwrap();
        let os = sign_agreement(agreement, &key).unwrap();
        home.federation_accept(
            &hs,
            &os,
            &fed::AgreementPins {
                home: agreement.home,
                origin: agreement.origin,
                home_key: agreement.home_service_key,
                origin_key: agreement.origin_service_key,
                origin_attestor: agreement.origin_attestor_key,
            },
            TimeBounds::test_now(),
        )
    };
    for withdrawn in [false, true] {
        if withdrawn {
            p.home
                .federation_withdraw(p.agreement.reference, TimeBounds::test_now())
                .unwrap();
        }
        assert!(matches!(
            accept(&mut p.home, &other),
            Err(fed::Error::Refused {
                code: ErrorCode::Denied,
                detail: "ThirdNetworkRoom"
            })
        ));
        let count = p
            .home
            .store
            .read(Duration::from_secs(2), |db| {
                db.query_row("SELECT count(*) FROM federation_agreements", [], |r| {
                    r.get::<_, u64>(0)
                })
            })
            .unwrap();
        assert_eq!(
            count, 1,
            "a refused agreement must not leave authority behind"
        );
    }
    let Outcome::Committed { body, .. } = run(
        &mut p.home,
        &p.local,
        &action(
            &p.local,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "Separate bilateral room".into(),
                confidentiality: RoomConfidentiality::Community,
            },
        ),
    ) else {
        panic!("room creation");
    };
    other.rooms[0].room = body
        .deserialized::<messaging::Committed>()
        .unwrap()
        .room
        .unwrap();
    assert!(accept(&mut p.home, &other).is_ok());
}
