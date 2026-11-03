// SPDX-License-Identifier: Apache-2.0
//! Selective text queries stay usable when unrelated retained history grows.
use super::*;

#[test]
fn selective_sixteen_term_search_uses_retained_index_with_current_authority() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "indexed history");
    // Retained history is seeded in bounded commits, independently of live send rates.
    for _ in 0..16 {
        home.store
            .write(|db| {
                for _ in 0..256 {
                    let action = send(&owner, room, "unrelated retained message");
                    messaging::record(
                        db,
                        &action,
                        room,
                        action.body.clone(),
                        "unrelated retained message",
                        TimeBounds::test_now(),
                    )
                    .map_err(sql_fault)?;
                }
                Ok(Commit::new((), b"retained indexed history".to_vec()))
            })
            .unwrap();
    }
    let terms: Vec<String> = (0..16).map(|i| format!("term{i}")).collect();
    let sent = run(&mut home, &owner, &send(&owner, room, &terms.join(" ")));
    let Outcome::Committed {
        event: Some(event), ..
    } = sent
    else {
        panic!("message not committed: {sent:?}");
    };
    let query = messaging::Search {
        terms,
        sender: Some(owner.record.acting.account),
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 50,
    };
    let result = run(
        &mut home,
        &owner,
        &action(&owner, Operation::SearchQuery, Target::Room(room), &query),
    );
    let Outcome::Result { body } = result else {
        panic!("indexed search did not finish with current authority: {result:?}");
    };
    let page: messaging::PageResult = body.deserialized().unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event, event);
    assert!(!page.has_more);
}
