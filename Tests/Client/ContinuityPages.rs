// SPDX-License-Identifier: Apache-2.0
//! Authenticated continuity responses must make bounded, contiguous progress.
use super::*;
use crate::client::tests::action;

fn page(after: u64, count: usize, next: Option<String>) -> identity::PublicIdentity {
    let action = action();
    let state = IdentitySnapshot {
        home: action.home,
        account: action.actor.represented(),
        classification: AccountClass::Human,
        security_generation: 1,
        revision: 1,
        recovery_key: Id::from_bytes([20; 32]),
        recovery_generation: 1,
        head: Some(Id::from_bytes([21; 32])),
        legacy_anchor: false,
        endpoints: Vec::new(),
    };
    identity::PublicIdentity {
        origin_checkpoint: None,
        identity: state.clone(),
        continuity: crate::home::InspectionPage {
            items: (1..=count)
                .map(|offset| ContinuityRecord {
                    index: after + offset as u64,
                    previous: None,
                    position: after + offset as u64,
                    change: IdentityChange::Registered,
                    authorizations: Vec::new(),
                    state: state.clone(),
                })
                .collect(),
            next,
        },
    }
}

#[test]
fn empty_advancing_continuity_response_stops_after_one_request() {
    let a = action();
    let mut requests = 0;
    let result = read_continuity(Vec::new(), a.actor.represented(), a.home, |after, limit| {
        requests += 1;
        assert_eq!(limit, 4);
        assert_eq!(requests, 1, "empty response caused another network request");
        Ok(page(after, 0, Some((after + 1).to_string())))
    });
    assert!(matches!(result, Err(Error::Input)));
    assert_eq!(requests, 1);
}

#[test]
fn continuity_rejects_cursor_mismatch_gaps_duplicates_and_oversized_pages() {
    let a = action();
    let mut cases = vec![
        page(2, 1, Some("2".into())),
        page(2, 1, Some("4".into())),
        page(2, 1, Some("invalid".into())),
        page(2, 5, None),
        page(3, 1, None),
    ];
    let mut duplicate = page(2, 2, None);
    duplicate.continuity.items[1].index = 3;
    cases.push(duplicate);
    let mut reordered = page(2, 2, None);
    reordered.continuity.items.swap(0, 1);
    cases.push(reordered);
    for response in cases {
        let retained = page(0, 2, None).continuity.items;
        let mut response = Some(response);
        let result = read_continuity(retained, a.actor.represented(), a.home, |after, _| {
            assert_eq!(after, 2);
            Ok(response.take().expect("malformed response was continued"))
        });
        assert!(matches!(result, Err(Error::Input)));
    }
}

#[test]
fn continuity_accepts_short_pages_retained_prefix_and_unchanged_chain() {
    let a = action();
    let mut requests = Vec::new();
    let (_, records) = read_continuity(
        page(0, 2, None).continuity.items,
        a.actor.represented(),
        a.home,
        |after, limit| {
            requests.push((after, limit));
            Ok(match after {
                2 => page(2, 2, Some("4".into())),
                4 => page(4, 1, None),
                _ => panic!("cursor did not follow returned records"),
            })
        },
    )
    .unwrap();
    assert_eq!(requests, vec![(2, 4), (4, 4)]);
    assert_eq!(
        records.iter().map(|r| r.index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    let (_, unchanged) = read_continuity(
        records.clone(),
        a.actor.represented(),
        a.home,
        |after, _| {
            assert_eq!(after, 5);
            Ok(page(after, 0, None))
        },
    )
    .unwrap();
    assert_eq!(
        cache::encode(&unchanged).unwrap(),
        cache::encode(&records).unwrap()
    );
}

#[test]
fn continuity_record_budget_bounds_nonterminating_responses() {
    let a = action();
    let mut requests = 0;
    let result = read_continuity(Vec::new(), a.actor.represented(), a.home, |after, _| {
        requests += 1;
        assert!(
            requests <= 1024,
            "continuity fetch exceeded its record budget"
        );
        Ok(page(after, 1, Some((after + 1).to_string())))
    });
    assert!(matches!(result, Err(Error::Input)));
    assert_eq!(requests, 1024);
    let retained = page(0, 1024, None).continuity.items;
    let (_, full) = read_continuity(retained, a.actor.represented(), a.home, |after, _| {
        assert_eq!(after, 1024);
        Ok(page(after, 0, None))
    })
    .unwrap();
    assert_eq!(full.len(), 1024);
    assert!(matches!(
        read_continuity(
            page(0, 1025, None).continuity.items,
            a.actor.represented(),
            a.home,
            |_, _| panic!("oversized retained chain caused a network request")
        ),
        Err(Error::Input)
    ));
}

#[test]
fn continuity_rejects_changed_head_or_response_identity() {
    let a = action();
    for mismatch in 0..3 {
        let result = read_continuity(Vec::new(), a.actor.represented(), a.home, |after, _| {
            let mut response = page(after, 1, Some((after + 1).to_string()));
            if after == 1 {
                match mismatch {
                    0 => response.identity.head = None,
                    1 => response.identity.account.local = Id::from_bytes([22; 32]),
                    _ => response.identity.home.service = Id::from_bytes([22; 32]),
                }
            }
            assert!(after <= 1, "inconsistent response was continued");
            Ok(response)
        });
        if mismatch == 0 {
            assert!(matches!(
                result,
                Err(Error::Rejected {
                    code: ErrorCode::Conflict,
                    ..
                })
            ));
        } else {
            assert!(matches!(result, Err(Error::Input)));
        }
    }
}
