use super::*;
fn snapshot() -> Snapshot {
    let id = |byte| Id::from_bytes([byte; 32]);
    let origin = NetworkId {
        network: id(1),
        incarnation: id(2),
    };
    let account = AccountId {
        origin,
        local: id(3),
    };
    let home = ServiceId {
        network: origin,
        service: id(4),
    };
    let summary = hrc::conversations::Summary {
        confidentiality: RoomConfidentiality::Community,
        invited: false,
        room: RoomId { home, local: id(5) },
        name: "room".into(),
        topic: String::new(),
        revision: 1,
        sequence: 0,
        joined: true,
        unread: 0,
    };
    Snapshot {
        revision: 0,
        account,
        home,
        services: Vec::new(),
        classification: AccountClass::Human,
        nickname: "Alice".into(),
        motd: String::new(),
        connection: hrc::client::ConnectionState::Offline,
        privacy: None,
        federation_privacy: None,
        rooms: vec![summary.clone()],
        selected: Some(hrc::client::RoomView {
            crypto: None,
            content: std::collections::BTreeMap::new(),
            summary,
            members: vec![hrc::conversations::Member {
                account,
                nickname: "Alice".into(),
                classification: AccountClass::Human,
                present: false,
                moderator: false,
            }],
            events: vec![],
            draft: String::new(),
            draft_mentions: vec![],
            stale: true,
            gap: None,
            has_more: false,
            read_sequence: 0,
            preferences: Default::default(),
            focus: None,
        }),
        search: None,
        deliveries: vec![],
        inspection: Default::default(),
        preferences: Default::default(),
        notifications: vec![],
        status: None,
        completions: vec![],
    }
}
#[test]
fn command_case_does_not_change_filter_effect_and_ambiguous_names_fail() {
    let mut view = snapshot();
    let Interaction::Request(command) = parse("/IGNORE ALICE", &[], &view, None).unwrap() else {
        panic!("expected request")
    };
    assert!(
        matches!(*command,Command::SetFilter{subject,ignored:Some(true),muted:None} if subject==view.account)
    );
    let mut duplicate = view.selected.as_ref().unwrap().members[0].clone();
    duplicate.nickname = "alice".into();
    duplicate.account.local = Id::from_bytes([9; 32]);
    view.selected.as_mut().unwrap().members.push(duplicate);
    assert!(parse("/ignore Alice", &[], &view, None).is_err());
    assert!(parse(&format!("/ignore {}", view.account), &[], &view, None).is_ok());
}
#[test]
fn slash_rewriting_preserves_selected_mention_identity_and_exact_text() {
    let view = snapshot();
    let mention = messaging::Mention {
        account: view.account,
        start: 4,
        end: 10,
    };
    let Interaction::Request(command) =
        parse("/me @Alice e\u{301} 👩‍🚀", &[mention], &view, None).unwrap()
    else {
        panic!("expected send")
    };
    let Command::Send {
        text,
        mentions,
        action: true,
        ..
    } = *command
    else {
        panic!("expected action")
    };
    assert_eq!(text, "@Alice e\u{301} 👩‍🚀");
    assert_eq!(
        mentions[0],
        messaging::Mention {
            account: view.account,
            start: 0,
            end: 6
        }
    );
    let query = search(&format!(
        "--sender {} --from 100 --until 200 -- --literal text",
        view.account
    ))
    .unwrap();
    assert_eq!(query.sender, Some(view.account));
    assert_eq!(query.terms, vec!["--literal text"]);
    assert!(parse("/approve missing changed-digest", &[], &view, None).is_err());
}
