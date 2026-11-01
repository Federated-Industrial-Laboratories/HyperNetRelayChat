// SPDX-License-Identifier: Apache-2.0
//! Admission budgets leave sufficient wire space for full filters and signed responses.
use super::*;
use crate::confidential::{Inspection, Package};
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn member(n: u8) -> Member {
    let origin = NetworkId {
        network: id(1),
        incarnation: id(2),
    };
    let home = ServiceId {
        network: origin,
        service: id(3),
    };
    let acting = EndpointActor {
        account: AccountId {
            origin,
            local: id(n),
        },
        endpoint: id(n),
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: id(n),
    };
    Member {
        actor: Actor::Direct {
            acting: acting.clone(),
        },
        credential: EndpointCredential {
            room: RoomId { home, local: id(4) },
            actor: acting,
            mls_key: id(n),
        },
        registration: Blob(vec![7; 1024]),
        delegation: None,
    }
}
#[test]
fn bounded_roster_and_pending_packages_remain_inspectable_with_full_filters() {
    let first = member(10);
    let mut members = vec![];
    for n in 10..74 {
        members.push(member(n));
        if roster(&members).is_err() {
            members.pop();
            break;
        }
    }
    assert!(
        members.len() >= 16,
        "the pilot fits with realistic registration proofs"
    );
    let mut packages = vec![];
    for n in 80..144 {
        packages.push(Package {
            digest: id(n),
            member: member(n),
            package: Blob(vec![8; 2048]),
            expires_ms: u64::MAX,
        });
        if bounded(&packages, PACKAGE_BYTES - 256).is_err() {
            packages.pop();
            break;
        }
    }
    let snapshot = Inspection {
        room: first.credential.room,
        confidentiality: RoomConfidentiality::PrivateGroup,
        group: Some(id(5)),
        epoch: u64::MAX,
        commit_digest: Some(id(6)),
        sequence: u64::MAX,
        send_barrier: true,
        frozen: true,
        required_removals: members.iter().map(|m| m.actor.acting().endpoint).collect(),
        members,
        packages,
        history_from_ms: 0,
        history_until_ms: u64::MAX,
        filter_revision: u64::MAX,
        ignored: (0..=255)
            .map(|n| AccountId {
                origin: first.actor.acting().account.origin,
                local: id(n),
            })
            .collect(),
    };
    let response = Response {
        home: first.credential.room.home,
        operation_id: OperationId {
            window: id(7),
            operation: id(8),
        },
        action_digest: id(9),
        outcome: Outcome::Result {
            body: Value::serialized(&snapshot).unwrap(),
        },
    };
    let key = SigningKey::from_bytes(&[9; 32]);
    let bytes = sign_crypto_response(&response, &key).unwrap();
    assert!(bytes.len() < TRANSITION_BYTES);
    let verified = verify_crypto_response(&bytes, &key.verifying_key()).unwrap();
    let Outcome::Result { body } = &verified.value().outcome else {
        panic!("inspection result")
    };
    let decoded: Inspection = body.deserialized().unwrap();
    assert_eq!(decoded.members.len(), snapshot.members.len());
    assert_eq!(decoded.ignored.len(), 256);
    let mut excessive = first.clone();
    excessive.registration = Blob(vec![0; MEMBER_BYTES]);
    assert!(roster(&[excessive]).is_err());
    assert!(roster(&vec![first.clone(); 65]).is_err());
    assert!(
        Value::Bytes(vec![0; MEMBER_BYTES + 1])
            .deserialized::<Member>()
            .is_err()
    );
    let json = serde_json::to_value(&first).unwrap();
    assert!(json.get("actor").is_some());
    assert_eq!(
        serde_json::from_value::<Member>(json).unwrap().actor,
        first.actor
    );
}
