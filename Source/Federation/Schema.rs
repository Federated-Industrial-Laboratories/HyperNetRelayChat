// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::time::Duration;
pub(crate) fn initialize(store: &mut storage::Store) -> storage::Result<()> {
    let version = store.read(Duration::from_secs(2), |db| {
        let present: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='federation_schema')",
            [],
            |r| r.get(0),
        )?;
        if present {
            db.query_row("SELECT version FROM federation_schema", [], |r| {
                r.get::<_, u64>(0)
            })
            .map(Some)
        } else {
            Ok(None)
        }
    })?;
    if let Some(v) = version {
        return if v == 1 {
            Ok(())
        } else {
            Err(rusqlite::Error::InvalidQuery.into())
        };
    }
    store.write(|db|{db.execute_batch("CREATE TABLE federation_schema(version INTEGER NOT NULL);INSERT INTO federation_schema VALUES(1);
CREATE TABLE federation_agreements(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,digest BLOB NOT NULL,data BLOB NOT NULL,expires INTEGER NOT NULL,withdrawn INTEGER NOT NULL);
CREATE TABLE federation_room_origins(room TEXT PRIMARY KEY,origin BLOB NOT NULL);
CREATE TABLE federation_checkpoints(digest TEXT PRIMARY KEY,account TEXT NOT NULL,agreement TEXT NOT NULL,signed BLOB NOT NULL,data BLOB NOT NULL,complete INTEGER NOT NULL DEFAULT 0);
CREATE TABLE federation_records(account TEXT NOT NULL,number INTEGER NOT NULL,digest BLOB NOT NULL,data BLOB NOT NULL,PRIMARY KEY(account,number));
CREATE TABLE federation_identities(account TEXT PRIMARY KEY,origin BLOB NOT NULL,checkpoint TEXT NOT NULL,anchor BLOB NOT NULL,head BLOB NOT NULL,records INTEGER NOT NULL);
CREATE TABLE federation_admissions(id TEXT PRIMARY KEY,agreement TEXT NOT NULL,account TEXT NOT NULL,endpoint TEXT NOT NULL,revision INTEGER NOT NULL,expires INTEGER NOT NULL,withdrawn INTEGER NOT NULL,data BLOB NOT NULL,UNIQUE(agreement,account,endpoint));
CREATE TABLE federation_windows(id TEXT PRIMARY KEY,agreement TEXT NOT NULL,admission TEXT NOT NULL,admission_revision INTEGER NOT NULL,actor BLOB NOT NULL);
CREATE TABLE federation_challenges(nonce TEXT PRIMARY KEY,boot TEXT NOT NULL,gateway TEXT NOT NULL,subject BLOB NOT NULL,deadline INTEGER NOT NULL,expires INTEGER NOT NULL,signed BLOB NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE federation_bootstrap(request TEXT PRIMARY KEY,digest BLOB NOT NULL,receipt BLOB NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE federation_controls(request TEXT PRIMARY KEY,digest BLOB NOT NULL,result BLOB NOT NULL,created INTEGER NOT NULL);
CREATE TABLE federation_withdrawal_acks(agreement TEXT PRIMARY KEY,revision INTEGER NOT NULL,request BLOB NOT NULL,result BLOB NOT NULL);
CREATE TABLE federation_watches(agreement TEXT NOT NULL,account TEXT NOT NULL,acknowledged TEXT,dirty INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(agreement,account));
CREATE TABLE federation_freshness(agreement TEXT NOT NULL,revision INTEGER NOT NULL,account TEXT NOT NULL,checkpoint TEXT NOT NULL,expires INTEGER NOT NULL,deadline INTEGER NOT NULL,PRIMARY KEY(agreement,account));
CREATE TABLE federation_bindings(account TEXT NOT NULL,endpoint TEXT NOT NULL,binding BLOB NOT NULL,PRIMARY KEY(account,endpoint));
CREATE TABLE federation_exports(account TEXT PRIMARY KEY,digest TEXT NOT NULL,signed BLOB NOT NULL,expires INTEGER NOT NULL);
ALTER TABLE hrc_grants ADD COLUMN operator TEXT;UPDATE hrc_grants SET operator=owner;
CREATE TABLE federation_grant_proofs(grant_id TEXT PRIMARY KEY,evidence BLOB NOT NULL);")?;Ok(Commit::new((),b"HRC.Federation.Schema.1".to_vec()))})
}
