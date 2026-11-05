// SPDX-License-Identifier: Apache-2.0
//! Real signed remote requests retain their exact agreement through room discovery.
use super::*;

fn select(p: &mut Pair, agreement: FederationAgreement) {
    let (accepted, gateway) = accept_agreement(
        &mut p.home,
        &mut p.origin,
        &agreement,
        &SigningKey::from_bytes(&[70; 32]),
    );
    p.agreement = accepted;
    p.gateway = gateway;
}
fn relay() -> FederationPrivacy {
    FederationPrivacy {
        endpoint_mode: Some(3),
        relay_arrival: FederationRelay::ApprovedAttachment,
        relay_service: Some(id(150)),
        attachment_profile_digest: Some(id(151)),
        ..privacy()
    }
}
fn envelope_with_privacy(
    p: &mut Pair,
    remote: &RemoteParty,
    admission: AdmissionRef,
    action: &Action,
    source: FederationPrivacy,
) -> FederationEnvelope {
    let mut envelope = p.envelope(remote, admission, action);
    let mut assertion =
        verify_origin_assertion(&envelope.origin_assertion.0, &p.attestor.verifying_key())
            .unwrap()
            .value()
            .clone();
    assertion.source_privacy = source;
    envelope.origin_assertion = Blob(sign_origin_assertion(&assertion, &p.attestor).unwrap());
    envelope
}
fn execute(
    p: &mut Pair,
    remote: &RemoteParty,
    admission: AdmissionRef,
    action: &Action,
    paths: (FederationPrivacy, FederationPrivacy),
) -> Response {
    let envelope = envelope_with_privacy(p, remote, admission, action, paths.0);
    let verified = p
        .home
        .federation_verify(
            &p.gateway,
            &envelope,
            &paths.1,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    p.home
        .execute_remote(&verified, TimeBounds::test_now(), &|| true)
        .unwrap()
}
fn list(
    p: &mut Pair,
    remote: &RemoteParty,
    admission: AdmissionRef,
    after: Option<RoomId>,
    limit: u16,
    paths: (FederationPrivacy, FederationPrivacy),
) -> Vec<conversations::Summary> {
    let action = p.action(
        remote,
        Operation::RoomList,
        Target::Service,
        &conversations::List { after, limit },
    );
    match execute(p, remote, admission, &action, paths).outcome {
        Outcome::Result { body } => body.deserialized().unwrap(),
        other => panic!("room list: {other:?}"),
    }
}
fn invite(p: &mut Pair, remote: &RemoteParty) {
    let invitation = action(
        &p.local,
        Operation::RoomInvite,
        Target::Room(p.room),
        &crate::confidential::Invite {
            account: remote.record.acting.account,
        },
    );
    assert!(matches!(
        run(&mut p.home, &p.local, &invitation),
        Outcome::Committed { .. }
    ));
}
fn rooms(rows: &[conversations::Summary]) -> Vec<RoomId> {
    rows.iter().map(|row| row.room).collect()
}

#[test]
fn room_discovery_cannot_borrow_another_agreements_admission_or_private_invitation() {
    let mut p = Pair::with_mode(RoomConfidentiality::PrivateGroup);
    let a_room = room(&mut p.home, &p.local, "agreement-a");
    let b_room = room(&mut p.home, &p.local, "agreement-b");
    let unadmitted_room = room(&mut p.home, &p.local, "not-admitted");
    let mut agreement_b = p.agreement.agreement.clone();
    agreement_b.revision += 1;
    agreement_b.rooms.push(SharedRoom {
        room: b_room,
        confidentiality: RoomConfidentiality::Community,
        ..agreement_b.rooms[0].clone()
    });
    agreement_b.rooms.push(SharedRoom {
        room: unadmitted_room,
        confidentiality: RoomConfidentiality::Community,
        ..agreement_b.rooms[0].clone()
    });
    select(&mut p, agreement_b);
    let mut remote_b = p.remote.clone();
    let private_room = p.room;
    let admission_b = p.admit_rooms(&remote_b, vec![private_room, b_room], 0);
    p.bootstrap(&mut remote_b, admission_b.reference);
    invite(&mut p, &remote_b);
    let b = (p.agreement.clone(), p.gateway.clone());

    let mut agreement_a = p.agreement.agreement.clone();
    agreement_a.id = id(152);
    agreement_a.revision = 1;
    agreement_a.rooms.clear();
    select(&mut p, agreement_a.clone());
    let mut remote_a = p.remote.clone();
    let setup = p.admit_rooms(&remote_a, Vec::new(), 0);
    p.bootstrap(&mut remote_a, setup.reference);
    assert!(
        list(
            &mut p,
            &remote_a,
            setup.reference,
            None,
            50,
            (privacy(), privacy())
        )
        .is_empty()
    );

    agreement_a.revision = 2;
    agreement_a.rooms.push(SharedRoom {
        room: a_room,
        confidentiality: RoomConfidentiality::Community,
        ..b.0.agreement.rooms[0].clone()
    });
    select(&mut p, agreement_a);
    let scoped_a = p.admit_rooms(&remote_a, vec![a_room], setup.reference.revision);
    p.bootstrap(&mut remote_a, scoped_a.reference);
    let visible = list(
        &mut p,
        &remote_a,
        scoped_a.reference,
        None,
        50,
        (privacy(), privacy()),
    );
    assert_eq!(rooms(&visible), vec![a_room]);
    assert!(
        list(
            &mut p,
            &remote_a,
            scoped_a.reference,
            Some(a_room),
            1,
            (privacy(), privacy())
        )
        .is_empty()
    );

    (p.agreement, p.gateway) = b;
    let mut expected = vec![private_room, b_room];
    expected.sort();
    let visible = list(
        &mut p,
        &remote_b,
        admission_b.reference,
        None,
        50,
        (privacy(), privacy()),
    );
    assert_eq!(rooms(&visible), expected);
    let invited = visible.iter().find(|row| row.room == private_room).unwrap();
    assert_eq!(invited.name, "federation");
    assert!(invited.invited && !invited.joined);
    assert_eq!(invited.confidentiality, RoomConfidentiality::PrivateGroup);
    let first = list(
        &mut p,
        &remote_b,
        admission_b.reference,
        None,
        1,
        (privacy(), privacy()),
    );
    assert_eq!(rooms(&first), expected[..1]);
    let second = list(
        &mut p,
        &remote_b,
        admission_b.reference,
        Some(first[0].room),
        1,
        (privacy(), privacy()),
    );
    assert_eq!(rooms(&second), expected[1..]);
    assert!(
        list(
            &mut p,
            &remote_b,
            admission_b.reference,
            Some(second[0].room),
            1,
            (privacy(), privacy())
        )
        .is_empty()
    );

    let invalid = p.action(
        &remote_b,
        Operation::RoomList,
        Target::Service,
        &conversations::List {
            after: None,
            limit: 0,
        },
    );
    assert!(
        matches!(execute(&mut p, &remote_b, admission_b.reference, &invalid, (privacy(), privacy())).outcome,
        Outcome::Rejected { code: ErrorCode::InvalidInput, ref detail } if detail == "PageLimit")
    );

    let ban = action(
        &p.local,
        Operation::ModerationBan,
        Target::Room(private_room),
        &moderation::Restriction {
            subject: remote_b.record.acting.account,
            enabled: true,
            duration_ms: 60_000,
            reason: "Discovery policy".into(),
        },
    );
    assert!(matches!(
        run(&mut p.home, &p.local, &ban),
        Outcome::Committed { .. }
    ));
    assert_eq!(
        rooms(&list(
            &mut p,
            &remote_b,
            admission_b.reference,
            None,
            50,
            (privacy(), privacy())
        )),
        vec![b_room]
    );

    let local = action(
        &p.local,
        Operation::RoomList,
        Target::Service,
        &conversations::List {
            after: None,
            limit: 50,
        },
    );
    let Outcome::Result { body } = run(&mut p.home, &p.local, &local) else {
        panic!("local list")
    };
    let local: Vec<conversations::Summary> = body.deserialized().unwrap();
    let mut expected = vec![a_room, b_room, private_room, unadmitted_room];
    expected.sort();
    assert_eq!(rooms(&local), expected);
}

#[test]
fn discovery_checks_both_privacy_legs_and_the_same_room_mode_as_targeted_actions() {
    let mut p = Pair::with_mode(RoomConfidentiality::PrivateGroup);
    let mut agreement = p.agreement.agreement.clone();
    agreement.revision += 1;
    agreement.rooms[0].privacy = PrivacyRequirement::AttestedRelayArrival;
    select(&mut p, agreement);
    let mut remote = p.remote.clone();
    let admission = p.admit(&remote);
    p.bootstrap(&mut remote, admission.reference);
    invite(&mut p, &remote);
    for paths in [
        (privacy(), privacy()),
        (relay(), privacy()),
        (privacy(), relay()),
    ] {
        assert!(list(&mut p, &remote, admission.reference, None, 50, paths).is_empty());
    }
    assert_eq!(
        rooms(&list(
            &mut p,
            &remote,
            admission.reference,
            None,
            50,
            (relay(), relay())
        )),
        vec![p.room]
    );
    let inspect = p.action(
        &remote,
        Operation::RoomInspect,
        Target::Room(p.room),
        &Empty {},
    );
    let envelope = envelope_with_privacy(&mut p, &remote, admission.reference, &inspect, privacy());
    assert!(matches!(
        p.home.federation_verify(
            &p.gateway,
            &envelope,
            &relay(),
            TimeBounds::test_now(),
            &|| true
        ),
        Err(fed::Error::Refused {
            detail: "FederationPrivacy",
            ..
        })
    ));

    // Simulate stored room metadata diverging from the consented mode.
    p.home
        .store
        .write(|db| {
            db.execute(
                "UPDATE hrc_rooms SET mode=0 WHERE id=?1",
                [p.room.to_string()],
            )?;
            Ok(Commit::new((), b"mismatched room mode fixture".to_vec()))
        })
        .unwrap();
    assert!(
        list(
            &mut p,
            &remote,
            admission.reference,
            None,
            50,
            (relay(), relay())
        )
        .is_empty()
    );
    let inspect = p.action(
        &remote,
        Operation::RoomInspect,
        Target::Room(p.room),
        &Empty {},
    );
    let envelope = envelope_with_privacy(&mut p, &remote, admission.reference, &inspect, relay());
    assert!(matches!(
        p.home.federation_verify(
            &p.gateway,
            &envelope,
            &relay(),
            TimeBounds::test_now(),
            &|| true
        ),
        Err(fed::Error::Refused {
            detail: "FederationRoomMode",
            ..
        })
    ));
}
