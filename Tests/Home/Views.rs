// SPDX-License-Identifier: Apache-2.0
//! Grouped reads preserve domain decisions, pagination and atomic admission.
use super::*;
use crate::home::views::*;

fn body<T: serde::de::DeserializeOwned>(outcome: Outcome) -> T {
    match outcome {
        Outcome::Result { body } => body.deserialized().unwrap(),
        other => panic!("{other:?}"),
    }
}
#[test]
fn grouped_views_match_owned_metadata_and_filtered_room_history() {
    let fixture = Fixture::new();
    let mut h = fixture.create();
    let alice = enrol(&mut h, 10, AccountClass::Human);
    let bob = enrol(&mut h, 20, AccountClass::Human);
    let r = room(&mut h, &alice, "Views");
    run(
        &mut h,
        &bob,
        &action(&bob, Operation::RoomJoin, Target::Room(r), &Empty {}),
    );
    run(&mut h, &bob, &send(&bob, r, "filtered"));
    run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::ModerationIgnore,
            Target::Account(alice.record.acting.account),
            &moderation::Filter {
                subject: bob.record.acting.account,
                enabled: true,
            },
        ),
    );
    let request = CommunityRequest {
        filters: Some(InspectPage::default()),
        history: Some(messaging::Page {
            cursor: None,
            limit: 32,
        }),
        restrictions: Some(InspectPage::default()),
        context: None,
    };
    let page: CommunityPage = body(run(
        &mut h,
        &alice,
        &action(&alice, Operation::CommunitySync, Target::Room(r), &request),
    ));
    assert_eq!(
        page.inspection.confidentiality,
        RoomConfidentiality::Community
    );
    assert!(page.history.as_ref().unwrap().members.is_empty());
    assert!(
        !page
            .history
            .as_ref()
            .unwrap()
            .events
            .iter()
            .any(|e| e.actor.acting().account == bob.record.acting.account)
    );
    assert_eq!(page.filters.as_ref().unwrap().items.len(), 1);
    let individual: messaging::PageResult = body(run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::EventsResume,
            Target::Room(r),
            request.history.as_ref().unwrap(),
        ),
    ));
    assert_eq!(individual.events, page.history.unwrap().events);
    let metadata: MetadataPage = body(run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::ClientMetadata,
            Target::Account(alice.record.acting.account),
            &MetadataRequest {
                filters: Some(InspectPage::default()),
                ..Default::default()
            },
        ),
    ));
    assert_eq!(
        metadata.filters.unwrap().items[0].subject,
        bob.record.acting.account
    );
    let denied = run(
        &mut h,
        &bob,
        &action(
            &bob,
            Operation::ClientMetadata,
            Target::Account(alice.record.acting.account),
            &MetadataRequest::default(),
        ),
    );
    assert!(matches!(
        denied,
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
}
#[test]
fn grouped_budget_and_final_authority_are_atomic() {
    let fixture = Fixture::new();
    let mut h = fixture.create();
    let alice = enrol(&mut h, 10, AccountClass::Human);
    let request = MetadataRequest {
        rooms: Some(conversations::List {
            after: None,
            limit: 16,
        }),
        filters: Some(InspectPage::default()),
        grants: Some(InspectPage::default()),
        agents: Some(InspectPage::default()),
        filter_revision: None,
    };
    let a = action(
        &alice,
        Operation::ClientMetadata,
        Target::Account(alice.record.acting.account),
        &request,
    );
    let before = h.usage().unwrap().commit_counter;
    let calls = Cell::new(0);
    let response = h
        .execute(
            &verified(&alice, &a),
            &alice.session,
            TimeBounds::test_now(),
            &|| {
                calls.set(calls.get() + 1);
                calls.get() < 3
            },
        )
        .unwrap();
    assert!(matches!(response.outcome, Outcome::Refused { .. }));
    assert_eq!(h.usage().unwrap().commit_counter, before);
    assert!(matches!(run(&mut h, &alice, &a), Outcome::Result { .. }));
    let key = format!("operation:{}", alice.record.acting.account);
    let credit: u64 = h
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row("SELECT credit FROM hrc_budgets WHERE key=?1", [&key], |r| {
                r.get(0)
            })
        })
        .unwrap();
    assert_eq!(
        credit, 26_000,
        "six component operations, not one cheap grouped read"
    );
    let continuation = action(
        &alice,
        Operation::ClientMetadata,
        Target::Account(alice.record.acting.account),
        &MetadataRequest {
            rooms: Some(conversations::List {
                after: None,
                limit: 16,
            }),
            ..Default::default()
        },
    );
    assert_eq!(super::super::views::cost(&continuation), 3);
}
#[test]
fn a_shared_short_room_page_continues_with_the_full_component_allowance() {
    let fixture = Fixture::new();
    let mut h = fixture.create();
    let alice = enrol(&mut h, 10, AccountClass::Human);
    let mut rooms = Vec::new();
    for i in 0..18 {
        rooms.push(room(&mut h, &alice, &format!("Room{i}")));
    }
    h.store
        .write(|db| {
            db.execute("UPDATE hrc_rooms SET topic=?1", ["t".repeat(1024)])?;
            Ok(Commit::new((), b"long topics".to_vec()))
        })
        .unwrap();
    let first: MetadataPage = body(run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::ClientMetadata,
            Target::Account(alice.record.acting.account),
            &MetadataRequest {
                rooms: Some(conversations::List {
                    after: None,
                    limit: 16,
                }),
                agents: Some(InspectPage::default()),
                ..Default::default()
            },
        ),
    ));
    let first = first.rooms.unwrap();
    assert!(first.items.len() < 16);
    assert!(first.next.is_some());
    let next: MetadataPage = body(run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::ClientMetadata,
            Target::Account(alice.record.acting.account),
            &MetadataRequest {
                rooms: Some(conversations::List {
                    after: first.next,
                    limit: 16,
                }),
                ..Default::default()
            },
        ),
    ));
    let next = next.rooms.unwrap();
    assert!(next.next.is_none());
    let mut observed: Vec<_> = first
        .items
        .into_iter()
        .chain(next.items)
        .map(|r| r.room)
        .collect();
    observed.sort();
    rooms.sort();
    assert_eq!(observed, rooms);
}
#[test]
fn strict_view_mode_and_context_are_not_legacy_defaults_or_authority() {
    let fixture = Fixture::new();
    let mut h = fixture.create();
    let alice = enrol(&mut h, 10, AccountClass::Human);
    let r = room(&mut h, &alice, "Context");
    let request = CommunityRequest::default();
    let page: CommunityPage = body(run(
        &mut h,
        &alice,
        &action(&alice, Operation::CommunitySync, Target::Room(r), &request),
    ));
    let mut encoded = serde_json::to_value(&page).unwrap();
    encoded["inspection"]
        .as_object_mut()
        .unwrap()
        .remove("confidentiality");
    assert!(serde_json::from_value::<CommunityPage>(encoded).is_err());
    let mut missing = Value::serialized(&MetadataRequest::default()).unwrap();
    let Value::Map(ref mut fields) = missing else {
        unreachable!()
    };
    fields.retain(|(key, _)| key != &Value::Text("rooms".into()));
    assert!(crate::home::views::decode::<MetadataRequest>(&missing).is_none());
    let mut malformed = action(
        &alice,
        Operation::ClientMetadata,
        Target::Account(alice.record.acting.account),
        &MetadataRequest::default(),
    );
    malformed.body = missing;
    assert!(
        matches!(run(&mut h, &alice, &malformed), Outcome::Rejected { code: ErrorCode::InvalidInput, ref detail } if detail == "ViewBody")
    );
    let nested: Value = Value::serialized(&serde_json::json!({"rooms":null,"filters":{"limit":16},"grants":null,"agents":null,"filterRevision":null})).unwrap();
    assert!(crate::home::views::decode::<MetadataRequest>(&nested).is_none());
    let mut response = Value::serialized(&page).unwrap();
    let Value::Map(ref mut fields) = response else {
        unreachable!()
    };
    fields.retain(|(key, _)| key != &Value::Text("history".into()));
    assert!(crate::home::views::decode::<CommunityPage>(&response).is_none());
    let changed = run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::CommunitySync,
            Target::Room(r),
            &CommunityRequest {
                context: Some(id(99)),
                ..Default::default()
            },
        ),
    );
    assert!(
        matches!(changed, Outcome::Rejected { code: ErrorCode::Conflict, ref detail } if detail == "ViewContextChanged")
    );
    h.information.motd = "x".repeat(ORDINARY_FRAME_BYTES);
    let large = run(
        &mut h,
        &alice,
        &action(
            &alice,
            Operation::ClientMetadata,
            Target::Account(alice.record.acting.account),
            &MetadataRequest::default(),
        ),
    );
    assert!(
        matches!(large, Outcome::Rejected { code: ErrorCode::Overloaded, ref detail } if detail == "ViewRepresentation")
    );
}
