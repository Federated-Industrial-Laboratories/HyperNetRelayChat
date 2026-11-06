// SPDX-License-Identifier: Apache-2.0
//! Room memory controls require the direct operator or a current room moderator.
use super::*;
use crate::conversations::Member;

fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn account(n: u8) -> AccountId {
    AccountId {
        origin: NetworkId {
            network: id(1),
            incarnation: id(2),
        },
        local: id(n),
    }
}
fn acting(n: u8) -> EndpointActor {
    EndpointActor {
        account: account(n),
        endpoint: id(n + 1),
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: id(n + 2),
    }
}
fn room() -> RoomId {
    RoomId {
        home: ServiceId {
            network: account(1).origin,
            service: id(3),
        },
        local: id(4),
    }
}
fn event(n: u8) -> Event {
    Event {
        home: room().home,
        room: room(),
        event: id(50),
        sequence: 10,
        timestamp_ms: 100,
        actor: Actor::Direct { acting: acting(n) },
        operation_id: OperationId {
            window: id(5),
            operation: id(6),
        },
        action_digest: id(7),
        kind: Operation::MessageSend,
        body: Value::Null,
    }
}
fn fixture() -> (Context, Config) {
    let config = Config {
        profile: "/tmp/hrc-context-test".into(),
        rooms: vec![room()],
        help: "Help".into(),
        poll_interval_ms: 1000,
        grant: None,
        resynchronise: false,
        model: None,
        memory: Some(Policy::default()),
    };
    let mut memory = Memory::default();
    memory.reset(id(9), 1);
    memory.summary = "An older shared fact.".into();
    memory.summary_source_ms = 100;
    memory.summary_through = 2;
    memory.observed = 9;
    let members = [20, 30, 40]
        .map(|n| Member {
            account: account(n),
            nickname: "Member".into(),
            classification: AccountClass::Human,
            present: true,
            moderator: n == 30,
        })
        .to_vec();
    (
        Context {
            memory,
            guard: SendGuard {
                room_revision: 2,
                filter_revision: 0,
            },
            enabled: true,
            policy: Policy::default(),
            encrypted: false,
            fingerprint: id(9),
            head: 10,
            own_account: account(10),
            operator: account(20),
            members,
            generated_until_ms: None,
            sampled: TimeBounds::test_now(),
        },
        config,
    )
}
#[test]
fn shared_reset_is_operator_or_moderator_only_and_cannot_be_delegated() {
    for n in [20, 30, 40] {
        let (mut context, config) = fixture();
        let response = context
            .generate(&config, &event(n), Reply::Forget, &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        if n == 40 {
            assert!(response.contains("Only the bot operator"));
            assert!(!context.memory.summary.is_empty());
        } else {
            assert!(response.contains("memory cleared"));
            assert!(context.memory.summary.is_empty());
            assert_eq!(context.memory.floor, 10);
        }
    }
    let (mut context, config) = fixture();
    let mut delegated = event(20);
    delegated.actor = Actor::Delegated {
        acting: acting(50),
        operator: account(20),
        represented: account(20),
        represented_security_generation: 1,
        grant: GrantRef {
            id: id(90),
            generation: 1,
        },
    };
    assert!(!context.control_allowed(&delegated));
    context
        .generate(&config, &delegated, Reply::Forget, &AtomicBool::new(false))
        .unwrap();
    assert!(!context.memory.summary.is_empty());
}
#[test]
fn summary_inspection_requires_privilege_but_counts_do_not() {
    let (mut context, config) = fixture();
    let stop = AtomicBool::new(false);
    let denied = context
        .generate(&config, &event(40), Reply::Memory { show: true }, &stop)
        .unwrap()
        .unwrap();
    assert!(!denied.contains("An older shared fact"));
    let status = context
        .generate(&config, &event(40), Reply::Memory { show: false }, &stop)
        .unwrap()
        .unwrap();
    assert!(status.contains("summary available"));
    assert!(!status.contains("An older shared fact"));
    let shown = context
        .generate(&config, &event(30), Reply::Memory { show: true }, &stop)
        .unwrap()
        .unwrap();
    assert!(shown.contains("An older shared fact"));
}
#[test]
fn generation_cannot_publish_after_its_oldest_source_expiry() {
    let (mut context, _) = fixture();
    let now = TimeBounds::test_now();
    context.generated_until_ms = Some(now.upper_ms);
    assert!(context.generation_expired(now));
    context.generated_until_ms = Some(now.upper_ms + 1);
    assert!(!context.generation_expired(now));
}
