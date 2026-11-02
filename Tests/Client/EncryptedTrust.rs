// SPDX-License-Identifier: Apache-2.0
//! Pending admission cannot block admitted leaves or weaken selected-roster verification.
use super::*;
use crate::{
    client::{
        tests::{Fixture, action},
        trust,
    },
    storage::Commit,
};
use rusqlite::params;

fn client(fixture: &Fixture) -> Client {
    drop(fixture.create());
    fixture.profile();
    Client::open_offline(&fixture.root).unwrap()
}

fn participant(
    client: &mut Client,
    room: RoomId,
    n: u8,
) -> (crypto::Device, domain::Member, ContinuityRecord) {
    let mut actor = action().actor.acting().clone();
    actor.account.local = Id::from_bytes([n; 32]);
    actor.endpoint = Id::from_bytes([n + 64; 32]);
    let key = SigningKey::from_bytes(&[n; 32]);
    let registration = AccountRegistration {
        home: room.home,
        account: actor.account,
        endpoint: actor.endpoint,
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: Id::from_bytes([n + 1; 32]),
        recovery_key: Id::from_bytes(
            SigningKey::from_bytes(&[n + 2; 32])
                .verifying_key()
                .to_bytes(),
        ),
        classification: AccountClass::Human,
        invitation: Id::from_bytes([n + 3; 32]),
    };
    let record = ContinuityRecord {
        index: 1,
        previous: None,
        position: 1,
        change: IdentityChange::Registered,
        authorizations: vec![Blob(sign_registration(&registration, &key).unwrap())],
        state: IdentitySnapshot {
            home: room.home,
            account: actor.account,
            classification: AccountClass::Human,
            security_generation: 1,
            revision: 1,
            recovery_key: registration.recovery_key,
            recovery_generation: 1,
            head: None,
            legacy_anchor: false,
            endpoints: vec![EndpointView {
                actor: actor.clone(),
                key: registration.endpoint_key,
                principal: registration.transport_principal,
            }],
        },
    };
    let device = crypto::Device::provision(&mut client.store, actor.clone()).unwrap();
    let mut enrolment = action();
    enrolment.actor = Actor::Direct {
        acting: actor.clone(),
    };
    enrolment.operation = Operation::CryptoEnrolEndpoint;
    enrolment.target = Target::Account(actor.account);
    enrolment.body = Value::serialized(&domain::EnrolKey {
        mls_key: device.mls_key,
    })
    .unwrap();
    let member = domain::Member {
        actor: enrolment.actor.clone(),
        credential: device.credential(room),
        registration: Blob(sign_action(&enrolment, &key).unwrap()),
        delegation: None,
    };
    (device, member, record)
}

fn retain_contact(
    client: &mut Client,
    room: RoomId,
    record: ContinuityRecord,
    trusted: bool,
) -> ContactTrust {
    let checked = trust::check_chain(
        &SigningKey::from_bytes(&[11; 32]).verifying_key(),
        vec![record],
        |_, _| None,
    )
    .unwrap();
    let contact = checked.view(TrustState::UntrustedRegistration);
    client
        .store
        .write(|tx| {
            tx.execute(
                "INSERT INTO client_contacts VALUES(?1,?2,?3,0,0)",
                params![
                    contact.account.to_string(),
                    contact.anchor.as_bytes(),
                    contact.head.as_bytes()
                ],
            )?;
            tx.execute(
                "INSERT INTO client_contact_records VALUES(?1,1,?2)",
                params![
                    contact.account.to_string(),
                    cache::encode(&checked.records[0])?
                ],
            )?;
            tx.execute(
                "INSERT INTO client_contact_rooms VALUES(?1,?2)",
                params![room.to_string(), contact.account.to_string()],
            )?;
            Ok(Commit::new((), contact.head.as_bytes().to_vec()))
        })
        .unwrap();
    if trusted {
        client
            .trust_contact(contact.account, contact.anchor, false)
            .unwrap();
    }
    checked.view(if trusted {
        TrustState::Trusted
    } else {
        TrustState::UntrustedRegistration
    })
}

fn trust_refused(result: Result<()>) {
    assert!(
        matches!(result, Err(Error::Rejected { code: ErrorCode::Denied, detail }) if detail == "ContactTrustRequired")
    );
}

#[test]
fn pending_untrusted_contact_allows_current_crypto_but_requires_explicit_admission() {
    let alice_fixture = Fixture::new();
    let bob_fixture = Fixture::new();
    let candidate_fixture = Fixture::new();
    let mut alice = client(&alice_fixture);
    let mut bob = client(&bob_fixture);
    let mut candidate = client(&candidate_fixture);
    let Target::Room(room) = action().target else {
        unreachable!()
    };
    let (a, alice_member, alice_record) = participant(&mut alice, room, 30);
    let (b, bob_member, bob_record) = participant(&mut bob, room, 40);
    let (c, candidate_member, candidate_record) = participant(&mut candidate, room, 50);
    let contacts = vec![
        retain_contact(&mut alice, room, alice_record, true),
        retain_contact(&mut alice, room, bob_record, true),
        retain_contact(&mut alice, room, candidate_record, false),
    ];
    let first = alice
        .trusted_roster(room, std::slice::from_ref(&alice_member), true)
        .unwrap();
    let members = vec![alice_member.clone(), bob_member.clone()];
    let both = alice.trusted_roster(room, &members, true).unwrap();
    let group = Id::from_bytes([90; 32]);
    a.create_group(&mut alice.store, group, &first, 1).unwrap();
    let package = b.publish_key_package(&mut bob.store, room).unwrap();
    let pending = a
        .prepare_transition(
            &mut alice.store,
            group,
            0,
            &first,
            &both,
            crypto::Change::Add(&[package]),
        )
        .unwrap();
    let receipt = a
        .accept_transition(
            &mut alice.store,
            crypto::TransitionOrder {
                group,
                epoch: 0,
                previous_sequence: 1,
                sequence: 2,
            },
            &pending.commit,
            &both,
        )
        .unwrap();
    b.join(
        &mut bob.store,
        group,
        1,
        2,
        receipt.welcome.as_ref().unwrap(),
        &both,
    )
    .unwrap();
    let package = c.publish_key_package(&mut candidate.store, room).unwrap();
    let mut view = CryptoView {
        remote: domain::Inspection {
            room,
            confidentiality: RoomConfidentiality::PrivateGroup,
            group: Some(group),
            epoch: 1,
            commit_digest: Some(digest(&pending.commit)),
            sequence: 2,
            send_barrier: false,
            frozen: false,
            members,
            packages: vec![domain::Package {
                digest: digest(&package),
                member: candidate_member.clone(),
                package: Blob(package),
                expires_ms: u64::MAX,
            }],
            required_removals: Vec::new(),
            history_from_ms: 0,
            history_until_ms: u64::MAX,
            filter_revision: 0,
            ignored: Vec::new(),
        },
        local: Some(a.state(&mut alice.store, group).unwrap()),
        contacts,
        future_only: true,
    };

    // This is the shared trust gate used by sync, send preparation and removal.
    require_trust(&view).unwrap();
    archive::save_view(&mut alice.store, &view).unwrap();
    let visible = archive::view(&mut alice.store, room).unwrap().unwrap();
    assert_eq!(visible.remote.packages.len(), 1);
    assert_eq!(visible.contacts[2].state, TrustState::UntrustedRegistration);
    let mut selected = view.remote.members.clone();
    selected.push(candidate_member.clone());
    trust_refused(require_member_trust(&selected, &view.contacts));
    assert!(matches!(
        alice.trusted_roster(room, &selected, true),
        Err(Error::Rejected {
            code: ErrorCode::Denied,
            ..
        })
    ));
    assert_eq!(a.state(&mut alice.store, group).unwrap().epoch, 1);

    let context = crypto::EncryptionContext {
        home: room.home,
        room,
        operation_id: action().operation_id,
        actor: alice_member.actor.clone(),
        operation: Operation::MessageSend,
        expected: Default::default(),
        approval: None,
        agreement: None,
        group,
        epoch: 1,
        parent: None,
        causation: None,
    };
    let message = a
        .prepare_message(
            &mut alice.store,
            &context,
            &both,
            "current members remain available",
            |_, action| {
                sign_action(&action, &SigningKey::from_bytes(&[30; 32])).map_err(Into::into)
            },
        )
        .unwrap();
    let received = b
        .receive(
            &mut bob.store,
            &crypto::IncomingMessage {
                context: &context,
                ciphertext: &message.ciphertext,
                action_digest: digest(&message.signed_action),
            },
            &crypto::HomeDelivery {
                previous_sequence: 2,
                sequence: 3,
                event: Id::from_bytes([91; 32]),
                event_digest: Id::from_bytes([92; 32]),
            },
            &both,
        )
        .unwrap();
    assert!(
        matches!(received, crypto::DeliveryOutcome::Message(body) if body.text == "current members remain available")
    );
    a.resolve_outbox(&mut alice.store, context.operation_id, true)
        .unwrap();

    view.remote.required_removals.push(b.actor.endpoint);
    require_trust(&view).unwrap();
    require_member_trust(std::slice::from_ref(&alice_member), &view.contacts).unwrap();
    let removal = a
        .prepare_transition(
            &mut alice.store,
            group,
            1,
            &both,
            &first,
            crypto::Change::Remove(&[b.actor.endpoint]),
        )
        .unwrap();
    a.accept_transition(
        &mut alice.store,
        crypto::TransitionOrder {
            group,
            epoch: 1,
            previous_sequence: 2,
            sequence: 4,
        },
        &removal.commit,
        &first,
    )
    .unwrap();
    assert_eq!(a.state(&mut alice.store, group).unwrap().epoch, 2);

    // Explicit trust enables selection; endpoint evidence still has to verify.
    let contact = &mut view.contacts[2];
    alice
        .trust_contact(contact.account, contact.anchor, false)
        .unwrap();
    contact.state = TrustState::Trusted;
    require_member_trust(&selected, &view.contacts).unwrap();
    alice.trusted_roster(room, &selected, true).unwrap();
    selected[2].registration = Blob(vec![0]);
    assert!(alice.trusted_roster(room, &selected, true).is_err());
    view.contacts[0].state = TrustState::Changed;
    trust_refused(require_trust(&view));
}

#[test]
fn selected_delegated_member_requires_acting_represented_and_operator_trust() {
    let fixture = Fixture::new();
    let mut client = client(&fixture);
    let Target::Room(room) = action().target else {
        unreachable!()
    };
    let (_, mut member, record) = participant(&mut client, room, 60);
    let acting = member.actor.acting().clone();
    let mut represented = acting.account;
    represented.local = Id::from_bytes([61; 32]);
    let mut operator = acting.account;
    operator.local = Id::from_bytes([62; 32]);
    member.actor = Actor::Delegated {
        acting,
        operator,
        represented,
        represented_security_generation: 1,
        grant: GrantRef {
            id: Id::from_bytes([63; 32]),
            generation: 1,
        },
    };
    let contact = retain_contact(&mut client, room, record, true);
    let mut contacts = vec![
        contact.clone(),
        ContactTrust {
            account: represented,
            ..contact.clone()
        },
        ContactTrust {
            account: operator,
            ..contact
        },
    ];
    for index in 0..contacts.len() {
        contacts[index].state = TrustState::UntrustedRegistration;
        trust_refused(require_member_trust(
            std::slice::from_ref(&member),
            &contacts,
        ));
        contacts[index].state = TrustState::Trusted;
    }
    require_member_trust(std::slice::from_ref(&member), &contacts).unwrap();
    // A trusted contact alone cannot authorize the supplied delegated actor.
    assert!(client.trusted_roster(room, &[member], true).is_err());
}
