//! Bounded continuity chain outside the database snapshot set.
use super::{Error, Result, files};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const DOMAIN: &[u8] = b"HRC storage continuity v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Head {
    pub(super) version: u32,
    pub(super) identity: [u8; 32],
    pub(super) generation: u64,
    pub(super) counter: u64,
    pub(super) previous_digest: [u8; 32],
    pub(super) change_digest: [u8; 32],
    pub(super) digest: [u8; 32],
}
impl Head {
    pub(super) fn initial(identity: [u8; 32]) -> Self {
        let mut head = Self {
            version: 1,
            identity,
            generation: 1,
            counter: 0,
            previous_digest: [0; 32],
            change_digest: Sha256::digest(b"HRC initialise storage v1").into(),
            digest: [0; 32],
        };
        head.digest = head.compute();
        head
    }
    fn compute(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.version.to_be_bytes());
        hash.update(self.identity);
        hash.update(self.generation.to_be_bytes());
        hash.update(self.counter.to_be_bytes());
        hash.update(self.previous_digest);
        hash.update(self.change_digest);
        hash.finalize().into()
    }
    pub(super) fn next(&self, change: &[u8]) -> Result<Self> {
        let counter = self
            .counter
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Continuity)?;
        let mut result = Self {
            counter,
            previous_digest: self.digest,
            change_digest: Sha256::digest(change).into(),
            ..self.clone()
        };
        result.digest = result.compute();
        Ok(result)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.identity == [0; 32]
            || self.generation != 1
            || self.counter > i64::MAX as u64
            || self.compute() != self.digest
        {
            return Err(Error::Continuity);
        }
        Ok(())
    }
    pub(super) fn load_guard(directory: &Path) -> Result<Self> {
        let bytes = files::read_bounded(&directory.join("Continuity.json"), 2048)
            .map_err(|_| Error::Continuity)?;
        let head: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Continuity)?;
        head.validate()?;
        Ok(head)
    }
    pub(super) fn persist(&self, directory: &Path) -> Result<()> {
        let mut bytes = serde_json::to_vec(self).map_err(|_| Error::Continuity)?;
        bytes.push(b'\n');
        files::replace(directory, &directory.join("Continuity.json"), &bytes)
    }
    pub(super) fn create(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch("CREATE TABLE _hrc_continuity (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, identity BLOB NOT NULL, generation INTEGER NOT NULL, counter INTEGER NOT NULL, previous_digest BLOB NOT NULL, change_digest BLOB NOT NULL, digest BLOB NOT NULL) STRICT;")?;
        conn.execute(
            "INSERT INTO _hrc_continuity VALUES(1,?1,?2,?3,?4,?5,?6,?7)",
            params![
                self.version,
                self.identity.as_slice(),
                self.generation,
                self.counter,
                self.previous_digest.as_slice(),
                self.change_digest.as_slice(),
                self.digest.as_slice()
            ],
        )?;
        Ok(())
    }
    pub(super) fn load(conn: &Connection) -> Result<Self> {
        let result = conn.query_row("SELECT version,identity,generation,counter,previous_digest,change_digest,digest FROM _hrc_continuity WHERE singleton=1", [], |row| {
            Ok(Self {version:row.get(0)?,identity:row.get(1)?,generation:row.get(2)?,counter:row.get(3)?,previous_digest:row.get(4)?,change_digest:row.get(5)?,digest:row.get(6)?})
        }).map_err(|_| Error::Continuity)?;
        result.validate()?;
        Ok(result)
    }
    pub(super) fn update(&self, conn: &Connection, previous: &Self) -> Result<()> {
        if Self::load(conn)? != *previous {
            return Err(Error::Continuity);
        }
        let changed = conn.execute("UPDATE _hrc_continuity SET counter=?1,previous_digest=?2,change_digest=?3,digest=?4 WHERE singleton=1 AND counter=?5 AND digest=?6",
            params![self.counter,self.previous_digest.as_slice(),self.change_digest.as_slice(),self.digest.as_slice(),previous.counter,previous.digest.as_slice()])?;
        if changed != 1 {
            return Err(Error::Continuity);
        }
        Ok(())
    }
    pub(super) fn reconcile(&self, guard: &Self) -> Result<bool> {
        if self.identity != guard.identity || self.generation != guard.generation {
            return Err(Error::Continuity);
        }
        if self == guard {
            return Ok(false);
        }
        if self.counter == guard.counter.checked_add(1).ok_or(Error::Continuity)?
            && self.previous_digest == guard.digest
        {
            return Ok(true);
        }
        Err(Error::Continuity)
    }
}
