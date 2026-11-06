// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::{fs::File, os::unix::net::UnixListener, path::PathBuf};

struct Fixture {
    root: PathBuf,
    profile: PathBuf,
    source: PathBuf,
    destination: PathBuf,
    lock: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-companion-{}",
            hrc::protocol::Id::random().unwrap().as_hex()
        ));
        files::directory(&root, true).unwrap();
        files::directory(&root.join("Routes"), true).unwrap();
        let profile = root.join("Network.json");
        files::create(&profile, b"retained network identity").unwrap();
        files::create(&root.join("Requester"), b"retained exact pending operation").unwrap();
        let endpoint = json!({
            "format":"HyperNetRelayEndpoint/1", "profile":profile,
            "route":{"network":vec![1u8;32],"incarnation":vec![2u8;32],
                "destination":{"service":vec![3u8;32]},"protocol":7,
                "limits":{"bytes":8192},"voucher":[1]}
        });
        let destination = root
            .join("Routes")
            .join(format!("{}.json", "03".repeat(32)));
        files::create(&destination, &serde_json::to_vec(&endpoint).unwrap()).unwrap();
        let mut renewed = endpoint;
        renewed["route"]["voucher"] = json!([2]);
        let source = root.join("Renewed.json");
        files::create(&source, &serde_json::to_vec(&renewed).unwrap()).unwrap();
        let lock = root.join(format!("Network{}.lock", digest(b"Agent.lock")));
        files::create(&lock, b"").unwrap();
        Self {
            root,
            profile,
            source,
            destination,
            lock,
        }
    }
    fn apply(&self) -> Result<()> {
        replace_target(
            &self.root,
            &self.profile,
            &"03".repeat(32),
            &"01".repeat(32),
            &"02".repeat(32),
            &self.source,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn reviewed_replacement_preserves_identity_pending_request_and_lock_inode() {
    let f = Fixture::new();
    let inode = fs::metadata(&f.lock).unwrap().ino();
    f.apply().unwrap();
    f.apply().unwrap();
    assert_eq!(
        files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap(),
        files::read(&f.source, MAXIMUM_ENDPOINT).unwrap()
    );
    assert_eq!(
        files::read(&f.profile, 128).unwrap(),
        b"retained network identity"
    );
    assert_eq!(
        files::read(&f.root.join("Requester"), 128).unwrap(),
        b"retained exact pending operation"
    );
    assert_eq!(fs::metadata(&f.lock).unwrap().ino(), inode);
}

#[test]
fn running_agent_or_live_socket_prevents_replacement() {
    let f = Fixture::new();
    let before = files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap();
    let lock = File::open(&f.lock).unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(matches!(f.apply(), Err(Error::Busy)));
    drop(lock);
    let _socket = UnixListener::bind(f.root.join("Control.sock")).unwrap();
    assert!(matches!(f.apply(), Err(Error::Busy)));
    assert_eq!(
        files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap(),
        before
    );
}

#[test]
fn changed_identity_or_privacy_budget_is_not_a_voucher_replacement() {
    for field in ["network", "limits", "profile", "voucher"] {
        let f = Fixture::new();
        let before = files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap();
        let mut source: Value =
            serde_json::from_slice(&files::read(&f.source, MAXIMUM_ENDPOINT).unwrap()).unwrap();
        match field {
            "network" => source["route"][field] = json!(vec![4u8; 32]),
            "limits" => source["route"][field]["bytes"] = json!(16384),
            "profile" => source[field] = json!(f.root.join("Requester")),
            _ => source["route"][field] = json!([]),
        }
        fs::write(&f.source, serde_json::to_vec(&source).unwrap()).unwrap();
        assert!(matches!(f.apply(), Err(Error::State)));
        assert_eq!(
            files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap(),
            before
        );
    }
}

#[test]
fn symlinked_target_is_preserved_and_refused() {
    let f = Fixture::new();
    fs::remove_file(&f.destination).unwrap();
    std::os::unix::fs::symlink(&f.source, &f.destination).unwrap();
    assert!(matches!(f.apply(), Err(Error::State)));
    assert!(
        fs::symlink_metadata(&f.destination)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn malformed_retained_endpoint_returns_a_bounded_error() {
    let f = Fixture::new();
    fs::write(&f.destination, b"[]").unwrap();
    assert!(matches!(f.apply(), Err(Error::State)));
    assert_eq!(
        files::read(&f.destination, MAXIMUM_ENDPOINT).unwrap(),
        b"[]"
    );
}
