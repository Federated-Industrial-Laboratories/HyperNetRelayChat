// SPDX-License-Identifier: Apache-2.0
//! Pinned service selection and cache isolation retain one endpoint identity.
use super::*;
use crate::{
    client::{self, cache},
    conversations, moderation, service,
};

fn selection(origin: &service::Descriptor) -> client::federation::Selection {
    let key = SigningKey::from_bytes(&[50; 32]);
    let gateway = Id::from_bytes(SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes());
    let home = ServiceId {
        network: NetworkId {
            network: id(41),
            incarnation: id(42),
        },
        service: id(43),
    };
    let binding = |destination: ServiceId| GatewayBinding {
        network: destination.network,
        destination,
        principal: id(44),
        service_endpoint: id(45),
        signing_key: gateway,
        protocol: PROTOCOL.into(),
    };
    let agreement = FederationAgreement {
        profile: FEDERATION_PROFILE,
        id: id(46),
        revision: 1,
        home,
        origin: origin.home,
        home_gateway: binding(home),
        origin_gateway: binding(origin.home),
        home_service_key: Id::from_bytes(key.verifying_key().to_bytes()),
        origin_service_key: origin.signing_key,
        origin_attestor_key: gateway,
        not_before_ms: 1,
        expires_ms: 2,
        rooms: (0..32)
            .map(|n| SharedRoom {
                room: RoomId {
                    home,
                    local: id(n + 60),
                },
                history_from_ms: 1,
                retention_ms: 86400000,
                storage: StorageLocations::HomeOnly,
                confidentiality: RoomConfidentiality::Community,
                privacy: PrivacyRequirement::SupportedHyperNetRoute,
                moderator_accounts: vec![],
            })
            .collect(),
    };
    let home_signature = sign_agreement(&agreement, &key).unwrap();
    let checked = verify_agreement(&home_signature, &key.verifying_key()).unwrap();
    client::federation::Selection {
        home: service::Descriptor {
            version: 1,
            home,
            signing_key: agreement.home_service_key,
            protocol: PROTOCOL.into(),
            text_profile: crate::text::PROFILE.into(),
        },
        origin: origin.clone(),
        agreement: AgreementRef {
            id: agreement.id,
            revision: 1,
            digest: checked.digest(),
        },
        home_signature: Blob(home_signature),
        origin_signature: Blob(
            sign_agreement(&agreement, &SigningKey::from_bytes(&[11; 32])).unwrap(),
        ),
    }
}
#[test]
fn foreign_selection_keeps_origin_keys_and_rejects_substitution_under_explicit_pins() {
    let fixture = Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let original = client::Profile::load(&fixture.root).unwrap();
    let selected = selection(&original.server);
    assert!(selected.validate().is_ok());
    let key_before = service::files::key(&fixture.root.join("Endpoint.key"))
        .unwrap()
        .verifying_key();
    client::federation::select(&fixture.root, Some(selected.clone()), true).unwrap();
    let changed = client::Profile::load(&fixture.root).unwrap();
    assert_eq!(changed.registration, original.registration);
    assert_eq!(changed.server.home, original.server.home);
    assert_eq!(changed.active_server().home, selected.home.home);
    assert_eq!(
        service::files::key(&fixture.root.join("Endpoint.key"))
            .unwrap()
            .verifying_key(),
        key_before
    );
    assert!(
        std::fs::metadata(fixture.root.join("Profile.json"))
            .unwrap()
            .len()
            > 16384
    );
    let mut substituted = selected.clone();
    substituted.home.signing_key = original.server.signing_key;
    assert!(client::federation::select(&fixture.root, Some(substituted), true).is_err());
    let mut substituted = selected.clone();
    substituted.origin_signature = substituted.home_signature.clone();
    assert!(client::federation::select(&fixture.root, Some(substituted), true).is_err());
    assert_eq!(
        client::Profile::load(&fixture.root).unwrap().federation,
        Some(selected.agreement)
    );
    client::federation::select(&fixture.root, None, false).unwrap();
    let local = client::Profile::load(&fixture.root).unwrap();
    assert_eq!(local.active_server().home, original.server.home);
    assert_eq!(local.agreements.len(), 1);
}
#[test]
fn service_switching_keeps_other_room_history_filters_and_drafts_partitioned() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let home = action().home;
    cache::initialize(&mut store, home).unwrap();
    let other = ServiceId {
        network: NetworkId {
            network: id(41),
            incarnation: id(42),
        },
        service: id(43),
    };
    let summary = |home| conversations::Summary {
        room: RoomId { home, local: id(9) },
        name: "room".into(),
        topic: String::new(),
        revision: 1,
        sequence: 0,
        joined: true,
        unread: 0,
        confidentiality: RoomConfidentiality::Community,
        invited: false,
    };
    let first = summary(home);
    let second = summary(other);
    cache::save_rooms(&mut store, home, std::slice::from_ref(&first)).unwrap();
    cache::save_rooms(&mut store, other, std::slice::from_ref(&second)).unwrap();
    let filter = moderation::FilterState {
        subject: action().actor.represented(),
        ignored: true,
        muted: false,
    };
    cache::save_filters(&mut store, home, &[filter]).unwrap();
    cache::save_filters(&mut store, other, &[]).unwrap();
    assert!(cache::filters(&mut store, home).unwrap()[0].ignored);
    assert!(cache::filters(&mut store, other).unwrap().is_empty());
    outbox::save_draft(&mut store, first.room, "origin draft").unwrap();
    outbox::save_draft(&mut store, second.room, "foreign draft").unwrap();
    cache::save_rooms(&mut store, home, &[]).unwrap();
    let retained = cache::rooms(&mut store).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].room, second.room);
    assert_eq!(
        outbox::draft(&mut store, first.room).unwrap().as_deref(),
        Some("origin draft")
    );
    assert_eq!(
        outbox::draft(&mut store, second.room).unwrap().as_deref(),
        Some("foreign draft")
    );
    assert!(cache::save_rooms(&mut store, home, &[second]).is_err());
}
#[test]
fn old_filter_schema_migrates_to_origin_once_without_widening_foreign_filters() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let home = action().home;
    cache::initialize(&mut store, home).unwrap();
    let subject = action().actor.represented();
    store.write(|db| { db.execute_batch("DROP TABLE client_filters; CREATE TABLE client_filters(subject TEXT PRIMARY KEY,ignored INTEGER NOT NULL,muted INTEGER NOT NULL); UPDATE client_cache_meta SET version=1;")?;
        db.execute("INSERT INTO client_filters VALUES(?1,1,0)", [subject.to_string()])?;
        Ok(storage::Commit::new((), b"old filter fixture".to_vec())) }).unwrap();
    cache::initialize(&mut store, home).unwrap();
    assert_eq!(
        cache::filters(&mut store, home).unwrap()[0].subject,
        subject
    );
    let other = ServiceId {
        service: id(55),
        ..home
    };
    assert!(cache::filters(&mut store, other).unwrap().is_empty());
    let before = store.usage().unwrap().commit_counter;
    cache::initialize(&mut store, home).unwrap();
    assert_eq!(store.usage().unwrap().commit_counter, before);
}
