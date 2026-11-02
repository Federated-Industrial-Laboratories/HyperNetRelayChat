// SPDX-License-Identifier: Apache-2.0
//! Bounded encrypted-room metadata shares the home's guarded SQLCipher writer.
use crate::storage::{self, Commit, Store};
use std::time::Duration;

pub(crate) fn initialize(store: &mut Store) -> storage::Result<()> {
    crate::crypto::initialize(store).map_err(|_| storage::Error::InvalidInput)?;
    let current = store.read(Duration::from_secs(2), |db| {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='hrc_encryption_schema' AND type='table')",
            [],
            |r| r.get(0),
        )?;
        if exists {
            db.query_row("SELECT version FROM hrc_encryption_schema WHERE singleton=1", [], |r| r.get::<_, u32>(0)).map(Some)
        } else {
            Ok(None)
        }
    })?;
    match current {
        Some(1) => Ok(()),
        Some(_) => Err(storage::Error::InvalidInput),
        None => store.write(|db| {
            db.execute_batch(SQL)?;
            Ok(Commit::new((), b"HRC.Encryption.Schema.1".to_vec()))
        }),
    }
}

pub(super) const SQL: &str = r#"
CREATE TABLE hrc_encryption_schema(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
INSERT INTO hrc_encryption_schema VALUES(1,1);
CREATE TABLE hrc_mls_grants(grant_id TEXT PRIMARY KEY,authorization BLOB NOT NULL,position INTEGER NOT NULL);
CREATE TABLE hrc_mls_keys(account TEXT NOT NULL,endpoint TEXT NOT NULL,actor BLOB NOT NULL,key BLOB NOT NULL,registration BLOB NOT NULL,PRIMARY KEY(account,endpoint),UNIQUE(key));
CREATE TABLE hrc_encrypted_rooms(room TEXT PRIMARY KEY,group_id BLOB,epoch INTEGER NOT NULL DEFAULT 0,commit_digest BLOB,sequence INTEGER NOT NULL DEFAULT 0,barrier INTEGER NOT NULL DEFAULT 1 CHECK(barrier IN(0,1)),frozen INTEGER NOT NULL DEFAULT 0 CHECK(frozen IN(0,1)));
CREATE TABLE hrc_encrypted_roster(room TEXT NOT NULL,endpoint TEXT NOT NULL,account TEXT NOT NULL,represented TEXT NOT NULL,operator TEXT,grant_id TEXT,actor BLOB NOT NULL,credential BLOB NOT NULL,registration BLOB NOT NULL,delegation BLOB,PRIMARY KEY(room,endpoint));
CREATE INDEX hrc_encrypted_account ON hrc_encrypted_roster(account,represented,operator);
CREATE TABLE hrc_room_invitations(room TEXT NOT NULL,account TEXT NOT NULL,inviter TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(room,account));
CREATE TABLE hrc_mls_packages(digest TEXT PRIMARY KEY,room TEXT NOT NULL,endpoint TEXT NOT NULL,actor BLOB NOT NULL,credential BLOB NOT NULL,registration BLOB NOT NULL,delegation BLOB,package BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0 CHECK(used IN(0,1)));
CREATE INDEX hrc_mls_package_room ON hrc_mls_packages(room,endpoint,used,expires);
CREATE TABLE hrc_mls_welcomes(room TEXT NOT NULL,group_id BLOB NOT NULL,epoch INTEGER NOT NULL,endpoint TEXT NOT NULL,package_digest TEXT NOT NULL,commit_digest BLOB NOT NULL,sequence INTEGER NOT NULL,welcome BLOB NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(group_id,epoch,endpoint));
CREATE TABLE hrc_mls_ready(room TEXT NOT NULL,group_id BLOB NOT NULL,epoch INTEGER NOT NULL,endpoint TEXT NOT NULL,commit_digest BLOB NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(group_id,epoch,endpoint));
"#;
