use super::*;
use rusqlite::params;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    data: PathBuf,
    guard: PathBuf,
    key_path: PathBuf,
    key: Key,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let data = root.join("Data");
        let guard = root.join("Guard");
        for p in [&data, &guard] {
            fs::create_dir(p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key_path = root.join("Key");
        let key = Key::create(&key_path).unwrap();
        Self {
            root,
            data,
            guard,
            key_path,
            key,
        }
    }
    fn create(&self) -> Store {
        Store::create(
            &self.data,
            &self.guard,
            &self.key,
            [7; 32],
            Limits::default(),
        )
        .unwrap()
    }
    fn open(&self) -> Result<Store> {
        Store::open(
            &self.data,
            &self.guard,
            &self.key,
            [7; 32],
            Limits::default(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn add(store: &mut Store, text: &str) -> Result<()> {
    store.write(|tx| {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,body TEXT NOT NULL)",
            [],
        )?;
        tx.execute("INSERT INTO messages(body) VALUES(?1)", [text])?;
        Ok(Commit::new((), text.as_bytes().to_vec()))
    })
}
fn count(store: &mut Store) -> i64 {
    store
        .read(Duration::from_secs(1), |c| {
            c.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
        })
        .unwrap()
}
#[test]
fn encrypted_roundtrip_restart_and_checked_engine() {
    let f = Fixture::new();
    let mut store = f.create();
    let marker = "Private HRC storage marker 28edce9739a64b9b";
    add(&mut store, marker).unwrap();
    assert_eq!(store.commit_counter(), 1);
    assert_eq!(
        store
            .read(Duration::from_secs(1), |c| c.query_row(
                "SELECT body FROM messages",
                [],
                |r| r.get::<_, String>(0)
            ))
            .unwrap(),
        marker
    );
    let db = fs::read(f.data.join("History.db")).unwrap();
    assert!(!db.starts_with(b"SQLite format 3"));
    assert!(!db.windows(marker.len()).any(|x| x == marker.as_bytes()));
    for path in files::database_files(&f.data) {
        if path.exists() {
            let bytes = fs::read(path).unwrap();
            assert!(!bytes.windows(marker.len()).any(|x| x == marker.as_bytes()));
        }
    }
    drop(store);
    let mut reopened = f.open().unwrap();
    assert_eq!(count(&mut reopened), 1);
    assert_eq!(reopened.commit_counter(), 1);
    assert_eq!(SQLCIPHER_VERSION, "4.20.0 community");
}
#[test]
fn wrong_key_and_missing_guard_do_not_reinitialise_storage() {
    let f = Fixture::new();
    let mut s = f.create();
    add(&mut s, "retained").unwrap();
    drop(s);
    let before = fs::read(f.data.join("History.db")).unwrap();
    let wrong = Key::create(f.root.join("WrongKey")).unwrap();
    assert!(matches!(
        Store::open(&f.data, &f.guard, &wrong, [7; 32], Limits::default()),
        Err(Error::Key)
    ));
    assert_eq!(fs::read(f.data.join("History.db")).unwrap(), before);
    fs::remove_file(f.guard.join("Continuity.json")).unwrap();
    assert!(matches!(f.open(), Err(Error::Continuity)));
    assert_eq!(fs::read(f.data.join("History.db")).unwrap(), before);
}
#[test]
fn one_durable_transaction_ahead_recovers_and_older_snapshot_refuses() {
    let f = Fixture::new();
    let mut s = f.create();
    add(&mut s, "first").unwrap();
    let old = fs::read(f.data.join("History.db")).unwrap();
    s.fail_after_commit = true;
    assert!(matches!(
        add(&mut s, "committed before guard"),
        Err(Error::Fenced)
    ));
    assert!(s.is_fenced());
    let wal = fs::read(f.data.join("History.db-wal")).unwrap();
    assert!(!wal.is_empty());
    assert!(
        !wal.windows(b"committed before guard".len())
            .any(|part| part == b"committed before guard")
    );
    assert!(matches!(add(&mut s, "must not happen"), Err(Error::Fenced)));
    drop(s);
    let mut recovered = f.open().unwrap();
    assert_eq!(count(&mut recovered), 2);
    assert_eq!(recovered.commit_counter(), 2);
    drop(recovered);
    fs::write(f.data.join("History.db"), old).unwrap();
    assert!(matches!(f.open(), Err(Error::Continuity)));
}
#[test]
fn uncommitted_sql_and_invalid_change_records_rollback() {
    let f = Fixture::new();
    let mut s = f.create();
    add(&mut s, "first").unwrap();
    let result = s.write(|tx| {
        tx.execute("INSERT INTO messages(body) VALUES('rolled back')", [])?;
        Err::<Commit<()>, _>(rusqlite::Error::InvalidQuery)
    });
    assert!(result.is_err());
    assert!(!s.is_fenced());
    assert_eq!(count(&mut s), 1);
    assert_eq!(s.commit_counter(), 1);
    let result = s.write(|tx| {
        tx.execute("INSERT INTO messages(body) VALUES('empty change')", [])?;
        Ok(Commit::new((), vec![]))
    });
    assert!(matches!(result, Err(Error::InvalidInput)));
    assert_eq!(count(&mut s), 1);
    assert!(
        s.write(|tx| {
            tx.execute("DELETE FROM _hrc_continuity", [])?;
            Ok(Commit::new((), b"forbidden".to_vec()))
        })
        .is_err()
    );
    assert_eq!(s.commit_counter(), 1);
}
#[test]
fn private_files_symlinks_and_writer_lease_are_enforced() {
    let f = Fixture::new();
    let s = f.create();
    assert!(matches!(f.open(), Err(Error::Busy)));
    drop(s);
    let alias = f.root.join("Alias");
    symlink(&f.data, &alias).unwrap();
    assert!(matches!(
        Store::open(&alias, &f.guard, &f.key, [7; 32], Limits::default()),
        Err(Error::Path)
    ));
    fs::set_permissions(&f.key_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Key::load(&f.key_path), Err(Error::Permissions)));
    fs::set_permissions(f.data.join("History.db"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(f.open(), Err(Error::Permissions)));
}
#[test]
fn read_cannot_write_attach_or_disable_boundary_and_costly_query_cancels() {
    let f = Fixture::new();
    let mut s = f.create();
    add(&mut s, "first").unwrap();
    for sql in [
        "DELETE FROM messages",
        "PRAGMA synchronous=OFF",
        "ATTACH ':memory:' AS extra",
        "COMMIT",
    ] {
        assert!(
            s.read(Duration::from_secs(1), |c| c.execute_batch(sql))
                .is_err(),
            "{sql}"
        );
    }
    assert_eq!(count(&mut s), 1);
    let expensive=s.read(Duration::from_millis(2),|c|c.query_row("WITH RECURSIVE x(v) AS (VALUES(1) UNION ALL SELECT v+1 FROM x WHERE v<100000000) SELECT sum(v) FROM x",[],|r|r.get::<_,i64>(0)));
    assert!(matches!(expensive, Err(Error::Deadline)));
    assert_eq!(count(&mut s), 1);
}
#[test]
fn page_quota_rejects_without_losing_previous_history() {
    let f = Fixture::new();
    let limits = Limits {
        max_database_bytes: 128 * 1024,
        ..Limits::default()
    };
    let mut s = Store::create(&f.data, &f.guard, &f.key, [7; 32], limits).unwrap();
    add(&mut s, "retained").unwrap();
    let large = vec![42u8; 256 * 1024];
    let result = s.write(|tx| {
        tx.execute("INSERT INTO messages(body) VALUES(?1)", params![large])?;
        Ok(Commit::new((), b"too large".to_vec()))
    });
    assert!(matches!(result, Err(Error::Quota)));
    assert_eq!(count(&mut s), 1);
    assert_eq!(s.commit_counter(), 1);
}

#[test]
fn encrypted_fts_index_survives_restart() {
    let f = Fixture::new();
    let mut s = f.create();
    s.write(|tx| {
        tx.execute_batch(
            "CREATE VIRTUAL TABLE search USING fts5(body, tokenize='trigram case_sensitive 1');",
        )?;
        tx.execute(
            "INSERT INTO search(body) VALUES(?1)",
            ["normalized searchable phrase"],
        )?;
        Ok(Commit::new(
            (),
            b"create bounded searchable fixture".to_vec(),
        ))
    })
    .unwrap();
    drop(s);
    let mut reopened = f.open().unwrap();
    let count: i64 = reopened
        .read(Duration::from_secs(1), |c| {
            c.query_row(
                "SELECT count(*) FROM search WHERE search MATCH ?1",
                ["searchable"],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn replacing_a_live_directory_or_database_fences_before_new_effects() {
    for replace_database in [false, true] {
        let f = Fixture::new();
        let mut store = f.create();
        add(&mut store, "original").unwrap();
        if replace_database {
            let original = f.data.join("History.db");
            let held = f.data.join("Prior.db");
            fs::rename(&original, &held).unwrap();
            fs::copy(&held, &original).unwrap();
        } else {
            fs::rename(&f.guard, f.root.join("PreviousGuard")).unwrap();
            fs::create_dir(&f.guard).unwrap();
            fs::set_permissions(&f.guard, fs::Permissions::from_mode(0o700)).unwrap();
            fs::copy(
                f.root.join("PreviousGuard/Continuity.json"),
                f.guard.join("Continuity.json"),
            )
            .unwrap();
        }
        assert!(matches!(
            add(&mut store, "must not commit"),
            Err(Error::Continuity)
        ));
        assert!(store.is_fenced());
        assert_eq!(store.commit_counter(), 1);
    }
}
