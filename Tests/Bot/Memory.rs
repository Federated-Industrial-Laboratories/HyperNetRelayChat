// SPDX-License-Identifier: Apache-2.0
//! Derived context retains source expiry, audience boundaries and bounded encrypted persistence.
use super::*;
use crate::storage;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn id(value: u64) -> Id {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Id::from_bytes(bytes)
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
fn entry(sequence: u64, timestamp_ms: u64) -> Entry {
    Entry {
        event: id(sequence + 100),
        sequence,
        timestamp_ms,
        speaker: format!("Participant{sequence}"),
        assistant: sequence.is_multiple_of(2),
        text: format!("Conversation message {sequence}: cafe\u{301} 👩‍🚀"),
    }
}
struct Fixture {
    root: PathBuf,
    key: storage::Key,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hrc-bot-memory-{}", Id::random().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(root.join("Key")).unwrap();
        Self { root, key }
    }
    fn store(&self, create: bool) -> Store {
        let open = if create { Store::create } else { Store::open };
        open(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            [10; 32],
            storage::Limits::default(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn encrypted_memory_reopens_with_provenance_and_disclosure_floor_intact() {
    let fixture = Fixture::new();
    let mut store = fixture.store(true);
    initialise(&mut store, Some(room())).unwrap();
    let mut memory = Memory::default();
    memory.reset(id(9), 10);
    memory.ingest(
        (11..=42).map(|sequence| entry(sequence, 100_000 + sequence)),
        42,
    );
    let compaction = memory.compaction(4096, 43).unwrap();
    memory
        .compacted(
            &compaction,
            "Retained project preference: cafe\u{301} and 👩‍🚀.",
        )
        .unwrap();
    save(&mut store, room(), &memory).unwrap();
    drop(store);
    let raw = rusqlite::Connection::open_with_flags(
        fixture.root.join("Data/History.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert!(
        raw.query_row("SELECT payload FROM bot_memory", [], |row| row
            .get::<_, Vec<u8>>(0))
            .is_err(),
        "derived plaintext must not be readable without the SQLCipher key"
    );
    drop(raw);
    let mut store = fixture.store(false);
    initialise(&mut store, Some(room())).unwrap();
    let restored = load(&mut store, room()).unwrap();
    assert_eq!(
        serde_json::to_value(&restored).unwrap(),
        serde_json::to_value(&memory).unwrap()
    );
    assert_eq!(restored.floor, 10);
    assert_eq!(restored.observed, 42);
    assert_eq!(restored.summary_source_ms, 100_011);
}

#[test]
fn oversized_or_corrupt_rows_are_errors_instead_of_a_silent_memory_reset() {
    let fixture = Fixture::new();
    let mut store = fixture.store(true);
    initialise(&mut store, Some(room())).unwrap();
    assert_eq!(load(&mut store, room()).unwrap().observed, 0);
    store
        .write(|db| {
            db.execute(
                "INSERT INTO bot_memory VALUES(?1,zeroblob(?2))",
                params![room().to_string(), RECORD_LIMIT + 1],
            )?;
            Ok(Commit::new((), b"oversized derived record".to_vec()))
        })
        .unwrap();
    assert!(matches!(
        load(&mut store, room()),
        Err(Error::InvalidState(_))
    ));
    store
        .write(|db| {
            db.execute("UPDATE bot_memory SET payload=?1", [b"{invalid".as_slice()])?;
            Ok(Commit::new((), b"corrupt derived record".to_vec()))
        })
        .unwrap();
    assert!(matches!(
        load(&mut store, room()),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn configured_retention_is_thirty_days_or_the_shorter_encrypted_limit() {
    let policy = Policy::default();
    policy.validate().unwrap();
    assert_eq!(policy.retention_days, 30);
    assert_eq!(policy.lifetime(false), 30 * DAY);
    assert_eq!(policy.lifetime(true), 7 * DAY);
    let shorter = Policy {
        retention_days: 3,
        ..policy.clone()
    };
    assert_eq!(shorter.lifetime(false), 3 * DAY);
    assert_eq!(shorter.lifetime(true), 3 * DAY);
    for invalid in [
        Policy {
            retention_days: 0,
            ..policy.clone()
        },
        Policy {
            retention_days: 31,
            ..policy.clone()
        },
        Policy {
            max_bytes: 16_383,
            ..policy.clone()
        },
        Policy {
            max_bytes: RECORD_LIMIT + 1,
            ..policy.clone()
        },
    ] {
        assert!(matches!(invalid.validate(), Err(Error::Configuration)));
    }
    let now = 100 * DAY;
    let mut memory = Memory::default();
    memory.ingest(
        [
            entry(1, now - 30 * DAY - 1),
            entry(2, now - 30 * DAY),
            entry(3, now - 7 * DAY),
            entry(4, now + 1),
        ],
        4,
    );
    let mut encrypted = memory.clone();
    memory.prune(now, policy.lifetime(false), policy.max_bytes);
    encrypted.prune(now, policy.lifetime(true), policy.max_bytes);
    assert_eq!(
        memory
            .entries
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        encrypted
            .entries
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        vec![3]
    );
}

#[test]
fn storage_and_prompt_budgets_keep_recent_complete_unicode_messages() {
    let now = 100 * DAY;
    let text = "quoted \\\" cafe\u{301} 👩‍🚀 ".repeat(32);
    let mut memory = Memory::default();
    memory.ingest(
        (1..=80).map(|sequence| Entry {
            text: text.clone(),
            ..entry(sequence, now)
        }),
        80,
    );
    memory.prune(now, 30 * DAY, 16_384);
    assert!(memory.bytes() <= 16_384);
    assert!(memory.entries.len() <= MAX_EVENTS);
    assert!(memory.discarded > 0);
    assert_eq!(memory.entries.last().unwrap().sequence, 80);
    assert!(memory.entries.iter().all(|e| e.text == text));
    let current = entry(81, now);
    let prompt = memory.prompt(&current, 4096);
    assert_eq!(prompt.first().unwrap().role, Role::System);
    assert_eq!(prompt.last().unwrap().role, Role::User);
    assert_eq!(
        prompt.last().unwrap().content,
        format!("{}: {}", current.speaker, current.text)
    );
    assert!(prompt.iter().map(|m| m.content.len() + 32).sum::<usize>() <= 4096);
    assert!(
        prompt.len() < memory.entries.len() + 2,
        "stored history must fit the per-request budget"
    );
    for message in &prompt[1..prompt.len() - 1] {
        let original = memory
            .entries
            .iter()
            .find(|entry| message.content.starts_with(&format!("{}: ", entry.speaker)))
            .unwrap();
        assert_eq!(
            message.content,
            format!("{}: {}", original.speaker, original.text)
        );
        assert_eq!(
            message.role,
            if original.assistant {
                Role::Assistant
            } else {
                Role::User
            }
        );
    }
}

#[test]
fn excerpts_and_compacted_summaries_never_split_combining_or_emoji_graphemes() {
    let source = "e\u{301}👩‍🚀".repeat(200);
    let boundaries: std::collections::BTreeSet<_> = source
        .grapheme_indices(true)
        .map(|(index, _)| index)
        .chain(std::iter::once(source.len()))
        .collect();
    for budget in [0, 1, 2, 3, 4, 10, 13, 14, 15, 1024] {
        let text = excerpt(&source, budget);
        assert!(text.len() <= budget && source.starts_with(&text));
        assert!(boundaries.contains(&text.len()));
    }
    let mut memory = Memory::default();
    memory.ingest(
        (1..=32).map(|sequence| entry(sequence, 1000 + sequence)),
        32,
    );
    let compaction = memory.compaction(4096, 33).unwrap();
    assert!(
        compaction
            .messages
            .iter()
            .map(|m| m.content.len() + 32)
            .sum::<usize>()
            <= 4096
    );
    memory.compacted(&compaction, &source).unwrap();
    assert!(memory.summary.len() <= SUMMARY_BYTES);
    assert!(boundaries.contains(&memory.summary.len()));
}

#[test]
fn recursive_summary_expires_with_its_oldest_source_not_its_regeneration_time() {
    let base = 100 * DAY;
    let mut memory = Memory::default();
    memory.ingest(
        (1..=32).map(|sequence| entry(sequence, base + sequence * 1000)),
        32,
    );
    let first = memory.compaction(4096, 33).unwrap();
    memory
        .compacted(&first, "Older participant preferences.")
        .unwrap();
    let oldest = memory.summary_source_ms;
    assert_eq!(oldest, base + 1000);
    memory.ingest(
        (33..=48).map(|sequence| entry(sequence, base + sequence * 1000)),
        48,
    );
    let second = memory.compaction(4096, 49).unwrap();
    assert!(
        second
            .messages
            .iter()
            .any(|m| m.content.contains("Older participant preferences."))
    );
    memory
        .compacted(&second, "Older preferences and later decisions.")
        .unwrap();
    assert_eq!(memory.summary_source_ms, oldest);
    assert!(memory.summary_through > first.through);
    memory.prune(oldest + 30 * DAY, 30 * DAY, Policy::default().max_bytes);
    assert!(
        !memory.summary.is_empty(),
        "the source remains valid at the exact retention boundary"
    );
    memory.prune(oldest + 30 * DAY + 1, 30 * DAY, Policy::default().max_bytes);
    assert!(memory.summary.is_empty());
    assert_eq!((memory.summary_source_ms, memory.summary_through), (0, 0));
    assert!(
        !memory.entries.is_empty(),
        "newer direct context retains its own lifetime"
    );
}

#[test]
fn compaction_and_prompts_cannot_include_a_later_turn_or_summary() {
    let mut memory = Memory::default();
    memory.ingest(
        (1..=40).map(|sequence| Entry {
            text: format!("[source-{sequence}]"),
            ..entry(sequence, 1000 + sequence)
        }),
        40,
    );
    let compact = memory.compaction(4096, 30).unwrap();
    assert!(compact.through < 30);
    assert!(
        !compact
            .messages
            .iter()
            .any(|m| m.content.contains("[source-30]") || m.content.contains("[source-40]"))
    );
    memory
        .compacted(&compact, "summary-boundary-marker")
        .unwrap();
    let through = memory.summary_through;
    for sequence in [through, through.saturating_sub(1)] {
        assert!(memory.compaction(4096, sequence).is_none());
        let prompt = memory.prompt(&entry(sequence, 2000), 4096);
        assert!(
            !prompt
                .iter()
                .any(|m| m.content.contains("summary-boundary-marker")
                    || m.content.contains("[source-40]"))
        );
    }
    let prompt = memory.prompt(&entry(through + 1, 2000), 4096);
    assert!(
        prompt
            .iter()
            .any(|m| m.content.contains("summary-boundary-marker"))
    );
}

#[test]
fn changed_audience_and_explicit_reset_never_reintroduce_pre_boundary_history() {
    let mut memory = Memory::default();
    assert!(memory.bind(id(1), 10));
    memory.ingest((1..=10).map(|sequence| entry(sequence, 1000)), 10);
    assert!(
        memory.entries.is_empty(),
        "initial enrollment does not backfill old messages"
    );
    memory.ingest((11..=15).map(|sequence| entry(sequence, 1000)), 15);
    assert_eq!(memory.entries.len(), 5);
    assert!(!memory.bind(id(1), 20));
    memory.ingest((11..=20).map(|sequence| entry(sequence, 1000)), 20);
    assert_eq!(memory.entries.len(), 10);
    memory.summary = "Old audience fact".into();
    memory.summary_source_ms = 1000;
    memory.summary_through = 12;
    assert!(memory.bind(id(2), 20));
    assert_eq!((memory.floor, memory.observed), (20, 20));
    assert!(memory.summary.is_empty() && memory.entries.is_empty());
    memory.ingest((1..=21).map(|sequence| entry(sequence, 1000)), 21);
    assert_eq!(
        memory
            .entries
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        vec![21]
    );
    memory.reset(id(2), 25);
    memory.ingest((1..=26).map(|sequence| entry(sequence, 1000)), 26);
    assert_eq!(
        memory
            .entries
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        vec![26]
    );
    assert_eq!(memory.floor, 25);
}
