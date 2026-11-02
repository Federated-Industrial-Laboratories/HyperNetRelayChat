// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::protocol::{
    AccountId, Actor, EndpointActor, NetworkId, Operation, OperationId, ServiceId,
};
use crate::storage::{Key, Limits};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn room() -> RoomId {
    RoomId {
        home: ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        },
        local: id(4),
    }
}
struct Client {
    root: PathBuf,
    key: Key,
    store: Option<Store>,
    device: Device,
}
impl Client {
    fn new(n: u8) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-crypto-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for path in [&root, &root.join("Data"), &root.join("Guard")] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = Key::create(root.join("Key")).unwrap();
        let mut store = Store::create(
            root.join("Data"),
            root.join("Guard"),
            &key,
            [n; 32],
            Limits::default(),
        )
        .unwrap();
        initialize(&mut store).unwrap();
        let actor = EndpointActor {
            account: AccountId {
                origin: room().home.network,
                local: id(n),
            },
            endpoint: id(n + 64),
            security_generation: 1,
            enrolment_generation: 1,
            binding_digest: id(n + 128),
        };
        let device = Device::provision(&mut store, actor).unwrap();
        Self {
            root,
            key,
            store: Some(store),
            device,
        }
    }
    fn store(&mut self) -> &mut Store {
        self.store.as_mut().unwrap()
    }
    fn restart(&mut self) {
        let identity = self.store().identity();
        drop(self.store.take());
        let mut store = Store::open(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            identity,
            Limits::default(),
        )
        .unwrap();
        initialize(&mut store).unwrap();
        self.device = Device::open(&mut store, &self.device.actor).unwrap();
        self.store = Some(store);
    }
    fn roster(&self) -> EndpointCredential {
        self.device.credential(room())
    }
    fn context(&self, n: u8, epoch: u64) -> EncryptionContext {
        EncryptionContext {
            home: room().home,
            room: room(),
            operation_id: OperationId {
                window: id(70),
                operation: id(n),
            },
            actor: Actor::Direct {
                acting: self.device.actor.clone(),
            },
            operation: Operation::MessageSend,
            expected: BTreeMap::new(),
            approval: None,
            agreement: None,
            group: id(5),
            epoch,
            parent: None,
            causation: None,
        }
    }
    fn send(&mut self, n: u8, epoch: u64, roster: &ApprovedRoster, text: &str) -> PreparedMessage {
        let context = self.context(n, epoch);
        let device = self.device.clone();
        device
            .prepare_message(self.store(), &context, roster, text, |_, action| {
                crate::protocol::sign_action(
                    &action,
                    &crate::protocol::SigningKey::from_bytes(&[91; 32]),
                )
                .map_err(|_| Error::Invalid)
            })
            .unwrap()
    }
    fn receive(
        &mut self,
        message: &PreparedMessage,
        prior: u64,
        sequence: u64,
        roster: &ApprovedRoster,
    ) -> DeliveryOutcome {
        let device = self.device.clone();
        device
            .receive(
                self.store(),
                &incoming(message),
                &delivery(prior, sequence),
                roster,
            )
            .unwrap()
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn incoming(message: &PreparedMessage) -> IncomingMessage<'_> {
    IncomingMessage {
        context: &message.context,
        ciphertext: &message.ciphertext,
        action_digest: crate::protocol::action_digest(
            &message.context.action(message.ciphertext.clone()).unwrap(),
        )
        .unwrap(),
    }
}
fn delivery(prior: u64, sequence: u64) -> HomeDelivery {
    HomeDelivery {
        previous_sequence: prior,
        sequence,
        event: id(sequence as u8 + 100),
        event_digest: id(sequence as u8 + 130),
    }
}
fn roster(clients: &[&Client]) -> ApprovedRoster {
    ApprovedRoster::new(room(), clients.iter().map(|c| c.roster()).collect()).unwrap()
}
fn pair() -> (Client, Client, ApprovedRoster) {
    let mut alice = Client::new(10);
    let mut bob = Client::new(11);
    let first = roster(&[&alice]);
    let both = roster(&[&alice, &bob]);
    let a = alice.device.clone();
    let b = bob.device.clone();
    a.create_group(alice.store(), id(5), &first, 0).unwrap();
    let package = b.publish_key_package(bob.store(), room()).unwrap();
    let pending = a
        .prepare_transition(
            alice.store(),
            id(5),
            0,
            &first,
            &both,
            Change::Add(&[package]),
        )
        .unwrap();
    let receipt = a
        .accept_transition(
            alice.store(),
            TransitionOrder {
                group: id(5),
                epoch: 0,
                previous_sequence: 0,
                sequence: 1,
            },
            &pending.commit,
            &both,
        )
        .unwrap();
    b.join(
        bob.store(),
        id(5),
        1,
        1,
        receipt.welcome.as_ref().unwrap(),
        &both,
    )
    .unwrap();
    (alice, bob, both)
}

#[test]
fn durable_sender_outbox_receiver_restart_and_duplicates() {
    let (mut alice, mut bob, both) = pair();
    let message = alice.send(20, 1, &both, "hello e\u{301} 👨‍👩‍👧");
    let key = crate::protocol::SigningKey::from_bytes(&[91; 32]).verifying_key();
    let verified = crate::protocol::verify_action(&message.signed_action, &key).unwrap();
    assert_eq!(verified.digest(), incoming(&message).action_digest);
    assert_ne!(verified.digest(), digest(&message.signed_action));
    alice.restart();
    bob.restart();
    let retry = alice.send(20, 1, &both, "hello e\u{301} 👨‍👩‍👧");
    assert_eq!(message, retry);
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("hello e\u{301} 👨‍👩‍👧".into())
    );
    bob.restart();
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("hello e\u{301} 👨‍👩‍👧".into())
    );
    assert_eq!(
        alice.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("hello e\u{301} 👨‍👩‍👧".into())
    );
    let device = alice.device.clone();
    let context = alice.context(20, 1);
    assert!(matches!(
        device.prepare_message(alice.store(), &context, &both, "different", |_, a| encode(
            &a
        )),
        Err(Error::Conflict)
    ));
}

#[test]
fn transaction_failure_rolls_back_sender_receiver_and_finalization() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let context = alice.context(21, 1);
    assert!(
        a.prepare_message(alice.store(), &context, &both, "rollback", |_, _| Err(
            Error::Conflict
        ))
        .is_err()
    );
    let message = alice.send(21, 1, &both, "rollback");
    let b = bob.device.clone();
    assert!(
        b.receive_with(
            bob.store(),
            &incoming(&message),
            &delivery(1, 2),
            &both,
            |_, _| Err(Error::Conflict)
        )
        .is_err()
    );
    bob.restart();
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("rollback".into())
    );
}

#[test]
fn invalid_crypto_rolls_back_then_advances_only_rejected_cursor() {
    let (mut alice, mut bob, both) = pair();
    let good = alice.send(22, 1, &both, "valid after damaged transport");
    let mut bad = good.clone();
    *bad.ciphertext.last_mut().unwrap() ^= 1;
    assert_eq!(
        bob.receive(&bad, 1, 2, &both),
        DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
    );
    bob.restart();
    assert_eq!(
        bob.receive(&good, 2, 3, &both),
        DeliveryOutcome::Message("valid after damaged transport".into())
    );
}

#[test]
fn exact_approval_decrypts_once_and_pending_sender_blocks() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let b = bob.device.clone();
    let mut context = alice.context(23, 1);
    context.approval = Some(id(99));
    let message = a
        .prepare_message(
            alice.store(),
            &context,
            &both,
            "approve this exact text",
            |_, a| encode(&a),
        )
        .unwrap();
    assert_eq!(
        b.preview(bob.store(), &incoming(&message), &both, 1)
            .unwrap(),
        DeliveryOutcome::Message("approve this exact text".into())
    );
    bob.restart();
    let b = bob.device.clone();
    assert_eq!(
        b.preview(bob.store(), &incoming(&message), &both, 1)
            .unwrap(),
        DeliveryOutcome::Message("approve this exact text".into())
    );
    let next = alice.context(24, 1);
    assert!(matches!(
        a.prepare_message(alice.store(), &next, &both, "later", |_, a| encode(&a)),
        Err(Error::Conflict)
    ));
    b.decide_preview(bob.store(), &incoming(&message), true)
        .unwrap();
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("approve this exact text".into())
    );
    a.resolve_outbox(alice.store(), context.operation_id, true)
        .unwrap();
    let next = alice.send(24, 1, &both, "next generation");
    assert_eq!(
        bob.receive(&next, 2, 3, &both),
        DeliveryOutcome::Message("next generation".into())
    );
}

#[test]
fn third_endpoint_future_only_and_removal_stops_future_decryption() {
    let (mut alice, mut bob, both) = pair();
    let old = alice.send(25, 1, &both, "before third endpoint");
    alice.receive(&old, 1, 2, &both);
    bob.receive(&old, 1, 2, &both);
    let mut carol = Client::new(12);
    let all = roster(&[&alice, &bob, &carol]);
    let a = alice.device.clone();
    let b = bob.device.clone();
    let c = carol.device.clone();
    let package = c.publish_key_package(carol.store(), room()).unwrap();
    let pending = a
        .prepare_transition(
            alice.store(),
            id(5),
            1,
            &both,
            &all,
            Change::Add(&[package]),
        )
        .unwrap();
    let receipt = a
        .accept_transition(
            alice.store(),
            TransitionOrder {
                group: id(5),
                epoch: 1,
                previous_sequence: 2,
                sequence: 3,
            },
            &pending.commit,
            &all,
        )
        .unwrap();
    b.accept_transition(
        bob.store(),
        TransitionOrder {
            group: id(5),
            epoch: 1,
            previous_sequence: 2,
            sequence: 3,
        },
        &pending.commit,
        &all,
    )
    .unwrap();
    c.join(
        carol.store(),
        id(5),
        2,
        3,
        receipt.welcome.as_ref().unwrap(),
        &all,
    )
    .unwrap();
    assert_eq!(
        carol.receive(&old, 3, 4, &all),
        DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
    );
    let remove = a
        .prepare_transition(
            alice.store(),
            id(5),
            2,
            &all,
            &both,
            Change::Remove(&[c.actor.endpoint]),
        )
        .unwrap();
    a.accept_transition(
        alice.store(),
        TransitionOrder {
            group: id(5),
            epoch: 2,
            previous_sequence: 3,
            sequence: 5,
        },
        &remove.commit,
        &both,
    )
    .unwrap();
    b.accept_transition(
        bob.store(),
        TransitionOrder {
            group: id(5),
            epoch: 2,
            previous_sequence: 3,
            sequence: 5,
        },
        &remove.commit,
        &both,
    )
    .unwrap();
    let fresh = alice.send(26, 3, &both, "after removal");
    assert_eq!(
        bob.receive(&fresh, 5, 6, &both),
        DeliveryOutcome::Message("after removal".into())
    );
    assert_eq!(
        carol.receive(&fresh, 4, 6, &all),
        DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
    );
}

#[test]
fn competing_update_chooses_exact_home_winner() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let b = bob.device.clone();
    let winner = a
        .prepare_transition(alice.store(), id(5), 1, &both, &both, Change::Update)
        .unwrap();
    let loser = b
        .prepare_transition(bob.store(), id(5), 1, &both, &both, Change::Update)
        .unwrap();
    assert_ne!(winner.commit, loser.commit);
    a.accept_transition(
        alice.store(),
        TransitionOrder {
            group: id(5),
            epoch: 1,
            previous_sequence: 1,
            sequence: 2,
        },
        &winner.commit,
        &both,
    )
    .unwrap();
    b.accept_transition(
        bob.store(),
        TransitionOrder {
            group: id(5),
            epoch: 1,
            previous_sequence: 1,
            sequence: 2,
        },
        &winner.commit,
        &both,
    )
    .unwrap();
    let message = alice.send(27, 2, &both, "winner");
    assert_eq!(
        bob.receive(&message, 2, 3, &both),
        DeliveryOutcome::Message("winner".into())
    );
}

#[test]
fn public_home_validates_actual_roster_and_does_not_hold_member_secrets() {
    let mut alice = Client::new(10);
    let mut bob = Client::new(11);
    let mut home = Client::new(13);
    let first = roster(&[&alice]);
    let both = roster(&[&alice, &bob]);
    let a = alice.device.clone();
    let b = bob.device.clone();
    let info = a.create_group(alice.store(), id(5), &first, 0).unwrap();
    atomic(home.store(), "test public create", &info, |tx| {
        create_public_in(tx, id(5), &info, &first)?;
        Ok(((), info.clone()))
    })
    .unwrap();
    let package = b.publish_key_package(bob.store(), room()).unwrap();
    let pending = a
        .prepare_transition(
            alice.store(),
            id(5),
            0,
            &first,
            &both,
            Change::Add(&[package]),
        )
        .unwrap();
    assert!(
        atomic(home.store(), "test invalid roster", &pending.commit, |tx| {
            accept_public_in(tx, id(5), 0, &pending.commit, &a.actor, &first, &first)?;
            Ok(((), vec![1]))
        })
        .is_err()
    );
    assert!(
        atomic(
            home.store(),
            "test substituted author",
            &pending.commit,
            |tx| {
                accept_public_in(tx, id(5), 0, &pending.commit, &b.actor, &first, &both)?;
                Ok(((), vec![1]))
            }
        )
        .is_err()
    );
    atomic(home.store(), "test public accept", &pending.commit, |tx| {
        let result = accept_public_in(tx, id(5), 0, &pending.commit, &a.actor, &first, &both)?;
        Ok(((), encode(&result)?))
    })
    .unwrap();
    let secret_rows:i64=home.store().read(std::time::Duration::from_secs(1),|conn|conn.query_row("SELECT count(*) FROM openmls_group_data WHERE data_type IN ('message_secrets','group_epoch_secrets')",[],|r|r.get(0))).unwrap();
    assert_eq!(secret_rows, 0);
}

#[test]
fn forward_generation_eight_succeeds_nine_requires_resynchronisation() {
    for skipped in [8u8, 9] {
        let (mut alice, mut bob, both) = pair();
        let a = alice.device.clone();
        let mut latest = None;
        for n in 0..=skipped {
            let message = alice.send(40 + n, 1, &both, "bounded forward distance");
            a.resolve_outbox(alice.store(), message.context.operation_id, true)
                .unwrap();
            latest = Some(message);
        }
        bob.restart();
        let outcome = bob.receive(&latest.unwrap(), 1, 2, &both);
        if skipped == 8 {
            assert_eq!(
                outcome,
                DeliveryOutcome::Message("bounded forward distance".into())
            )
        } else {
            assert_eq!(
                outcome,
                DeliveryOutcome::Rejected(Rejection::ResynchronisationRequired)
            );
            let b = bob.device.clone();
            assert!(b.state(bob.store(), id(5)).unwrap().frozen);
        }
    }
}

#[test]
fn abandoned_candidates_are_bounded_and_epoch_update_restores_send() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let b = bob.device.clone();
    for n in 0..MAX_FORWARD_DISTANCE {
        let mut context = alice.context(50 + n as u8, 1);
        context.approval = Some(id(90));
        let message = a
            .prepare_message(
                alice.store(),
                &context,
                &both,
                "rejected preview",
                |_, a| encode(&a),
            )
            .unwrap();
        b.preview(bob.store(), &incoming(&message), &both, 1)
            .unwrap();
        b.decide_preview(bob.store(), &incoming(&message), false)
            .unwrap();
        a.resolve_outbox(alice.store(), context.operation_id, false)
            .unwrap();
    }
    let context = alice.context(59, 1);
    assert!(matches!(
        a.prepare_message(alice.store(), &context, &both, "limit", |_, a| encode(&a)),
        Err(Error::Resynchronise)
    ));
    let transition = a
        .prepare_transition(alice.store(), id(5), 1, &both, &both, Change::Update)
        .unwrap();
    a.accept_transition(
        alice.store(),
        TransitionOrder {
            group: id(5),
            epoch: 1,
            previous_sequence: 1,
            sequence: 2,
        },
        &transition.commit,
        &both,
    )
    .unwrap();
    b.accept_transition(
        bob.store(),
        TransitionOrder {
            group: id(5),
            epoch: 1,
            previous_sequence: 1,
            sequence: 2,
        },
        &transition.commit,
        &both,
    )
    .unwrap();
    let message = alice.send(60, 2, &both, "new epoch");
    assert_eq!(
        bob.receive(&message, 2, 3, &both),
        DeliveryOutcome::Message("new epoch".into())
    );
}

#[test]
fn welcome_failure_restores_one_use_package_and_durable_transition_retry() {
    let mut alice = Client::new(10);
    let mut bob = Client::new(11);
    let a = alice.device.clone();
    let b = bob.device.clone();
    let first = roster(&[&alice]);
    let both = roster(&[&alice, &bob]);
    let original = a.create_group(alice.store(), id(5), &first, 0).unwrap();
    alice.restart();
    assert_eq!(
        a.create_group(alice.store(), id(5), &first, 0).unwrap(),
        original
    );
    let package = b.publish_key_package(bob.store(), room()).unwrap();
    let transition = a
        .prepare_transition(
            alice.store(),
            id(5),
            0,
            &first,
            &both,
            Change::Add(&[package]),
        )
        .unwrap();
    let receipt = a
        .accept_transition(
            alice.store(),
            TransitionOrder {
                group: id(5),
                epoch: 0,
                previous_sequence: 0,
                sequence: 1,
            },
            &transition.commit,
            &both,
        )
        .unwrap();
    alice.restart();
    let retry = a
        .accept_transition(
            alice.store(),
            TransitionOrder {
                group: id(5),
                epoch: 0,
                previous_sequence: 0,
                sequence: 1,
            },
            &transition.commit,
            &both,
        )
        .unwrap();
    assert_eq!(receipt.welcome, retry.welcome);
    let welcome = receipt.welcome.unwrap();
    let mut substituted = alice.roster();
    substituted.actor.binding_digest = id(200);
    let bad = ApprovedRoster::new(room(), vec![substituted, bob.roster()]).unwrap();
    assert!(matches!(
        b.join(bob.store(), id(5), 1, 1, &welcome, &bad),
        Err(Error::Binding)
    ));
    bob.restart();
    b.join(bob.store(), id(5), 1, 1, &welcome, &both).unwrap();
    b.join(bob.store(), id(5), 1, 1, &welcome, &both).unwrap();
    let remaining: i64 = bob
        .store()
        .read(std::time::Duration::from_secs(1), |c| {
            c.query_row("SELECT count(*) FROM openmls_key_packages", [], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn authenticated_invalid_plaintext_consumes_generation_without_archiving() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let context = alice.context(61, 1);
    let ciphertext = atomic(
        alice.store(),
        "adversarial invalid content",
        b"invalid UTF8",
        |tx| {
            let provider = Provider::new(tx);
            let keys = signer(&provider, a.mls_key)?;
            let mut group = load(&provider, id(5))?;
            group.set_aad(context.aad()?);
            let bytes = tls(&group
                .create_message(&provider, &keys, &[0xff, 0xfe])
                .map_err(|_| Error::Verification)?)?;
            Ok((bytes.clone(), bytes))
        },
    )
    .unwrap();
    let message = PreparedMessage {
        context: context.clone(),
        signed_action: encode(&context.action(ciphertext.clone()).unwrap()).unwrap(),
        ciphertext,
    };
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Rejected(Rejection::InvalidContent)
    );
    let good = alice.send(62, 1, &both, "next valid generation");
    assert_eq!(
        bob.receive(&good, 2, 3, &both),
        DeliveryOutcome::Message("next valid generation".into())
    );
    let b = bob.device.clone();
    assert_eq!(b.state(bob.store(), id(5)).unwrap().cursor, 3);
}

#[test]
fn invalid_membership_transition_freezes_position_and_sends() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let b = bob.device.clone();
    let transition = a
        .prepare_transition(alice.store(), id(5), 1, &both, &both, Change::Update)
        .unwrap();
    let mut corrupt = transition.commit.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(
        b.accept_transition(
            bob.store(),
            TransitionOrder {
                group: id(5),
                epoch: 1,
                previous_sequence: 1,
                sequence: 2
            },
            &corrupt,
            &both
        )
        .is_err()
    );
    bob.restart();
    let state = b.state(bob.store(), id(5)).unwrap();
    assert!(state.frozen);
    assert_eq!(state.cursor, 1);
    assert_eq!(state.epoch, 1);
    let context = bob.context(63, 1);
    assert!(matches!(
        b.prepare_message(
            bob.store(),
            &context,
            &both,
            "must not send",
            |_, a| encode(&a)
        ),
        Err(Error::Suspended)
    ));
}

#[test]
fn retention_closes_retry_windows_and_never_rewinds_sender_or_cursor() {
    let (mut alice, mut bob, both) = pair();
    let message = alice.send(64, 1, &both, "expire local copies");
    alice.receive(&message, 1, 2, &both);
    bob.receive(&message, 1, 2, &both);
    for client in [&mut alice, &mut bob] {
        atomic(client.store(), "archive expiry", b"closed window", |tx| {
            let removed = prune_in(tx, id(5), 2, &[id(70)])?;
            assert_eq!(removed.deliveries, 1);
            Ok(((), encode(&removed)?))
        })
        .unwrap();
    }
    alice.restart();
    bob.restart();
    let a = alice.device.clone();
    let b = bob.device.clone();
    assert!(matches!(
        a.prepare_message(
            alice.store(),
            &message.context,
            &both,
            "expire local copies",
            |_, a| encode(&a)
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        b.receive(bob.store(), &incoming(&message), &delivery(1, 2), &both),
        Err(Error::Resynchronise)
    ));
    let mut context = alice.context(65, 1);
    context.operation_id.window = id(71);
    let next = a
        .prepare_message(alice.store(), &context, &both, "current window", |_, a| {
            encode(&a)
        })
        .unwrap();
    assert_eq!(
        bob.receive(&next, 2, 3, &both),
        DeliveryOutcome::Message("current window".into())
    );
}

#[path = "Coupling.rs"]
mod coupling;
