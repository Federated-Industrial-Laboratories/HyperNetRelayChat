// SPDX-License-Identifier: Apache-2.0
//! Serialized admission, deduplication and durable feature dispatch.
#[path = "Budgets.rs"]
mod budgets;
#[path = "Execution.rs"]
mod execution;
#[path = "Retention.rs"]
mod retention;
#[path = "Schema.rs"]
mod schema;
#[path = "Types.rs"]
pub(crate) mod types;
use crate::{
    clock::TimeBounds,
    protocol::*,
    storage::{self, Commit, Store},
};
pub use execution::read_operation as is_read_operation;
pub use execution::{Resolve, ResolveResult};
pub(crate) use execution::{check_revision, committed, next_position, read_operation};
use rusqlite::{OptionalExtension, params};
use std::time::Duration;
use types::*;
pub use types::{
    AuthenticatedSession, Cancellation, Empty, EndpointRecord, Error, Invitation, Result,
};

pub struct Home {
    pub(crate) store: Store,
    pub(crate) home: ServiceId,
    pub(crate) signer: SigningKey,
}
impl Home {
    pub fn create(mut store: Store, home: ServiceId, signer: SigningKey) -> Result<Self> {
        if store.identity() != *home.service.as_bytes() {
            return Err(Error::Invalid);
        }
        let encoded = encode(&home).map_err(storage::Error::from)?;
        let key = signer.verifying_key().to_bytes();
        store.write(|db| {
            db.execute_batch(schema::SQL)?;
            db.execute(
                "INSERT INTO hrc_meta(singleton,version,home,signer) VALUES(1,1,?1,?2)",
                params![encoded, key],
            )?;
            Ok(Commit::new((), encode(&("HRC.Schema", 1u64, home, key))?))
        })?;
        Ok(Self {
            store,
            home,
            signer,
        })
    }
    pub fn open(mut store: Store, home: ServiceId, signer: SigningKey) -> Result<Self> {
        if store.identity() != *home.service.as_bytes() {
            return Err(Error::Invalid);
        }
        let valid = store.read(Duration::from_secs(2), |db| {
            let (version, saved, key): (u64, Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT version,home,signer FROM hrc_meta WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            Ok(version == 1
                && decode::<ServiceId>(&saved)? == home
                && key == signer.verifying_key().to_bytes())
        })?;
        if !valid {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            home,
            signer,
        })
    }
    pub fn service_id(&self) -> ServiceId {
        self.home
    }
    pub fn signing_key(&self) -> &SigningKey {
        &self.signer
    }
    pub fn usage(&self) -> storage::Result<storage::Usage> {
        self.store.usage()
    }
    pub fn issue_invitation(
        &mut self,
        principal: Id,
        classification: AccountClass,
        clock: TimeBounds,
    ) -> Result<Invitation> {
        let now = clock
            .refresh()
            .map_err(|_| Error::Refused("ClockUnavailable"))?;
        let invitation = Invitation {
            home: self.home,
            service_key: Id::from_bytes(self.signer.verifying_key().to_bytes()),
            id: Id::random().map_err(|_| Error::Invalid)?,
            principal,
            classification,
            expires_ms: now.lower_ms + DAY,
        };
        let class = encode(&invitation.classification).map_err(storage::Error::from)?;
        let outcome = self.store.write(|db| {
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            let now = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            if now.after_floor(floor).is_err() {
                return Ok(Commit::new(false, b"HRC.Invitation.Clock".to_vec()));
            }
            let count: u64 = db.query_row(
                "SELECT count(*) FROM hrc_invitations WHERE expires>?1",
                [now.lower_ms],
                |r| r.get(0),
            )?;
            if count >= 128 {
                return Ok(Commit::new(false, b"HRC.Invitation.Capacity".to_vec()));
            }
            db.execute(
                "INSERT INTO hrc_invitations(id,principal,class,expires) VALUES(?1,?2,?3,?4)",
                params![
                    invitation.id.as_hex(),
                    principal.as_hex(),
                    class,
                    invitation.expires_ms
                ],
            )?;
            db.execute(
                "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
                [now.lower_ms],
            )?;
            Ok(Commit::new(true, encode(&invitation)?))
        })?;
        if !outcome {
            return Err(Error::Refused("InvitationUnavailable"));
        }
        Ok(invitation)
    }
    pub fn accept_registration(
        &mut self,
        registration: &Verified<AccountRegistration>,
        clock: TimeBounds,
    ) -> Result<EndpointRecord> {
        let home = self.home;
        let signer = &self.signer;
        let result = self.store.write(|db| {
            let now = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if now.after_floor(floor).is_err() {
                return Ok(Commit::new(
                    Err("ClockUnavailable"),
                    registration.digest().as_bytes().to_vec(),
                ));
            }
            crate::identity::register(db, home, signer, registration, now)
        })?;
        result.map_err(Error::Refused)
    }
    pub fn endpoint(&mut self, account: AccountId, endpoint: Id) -> Result<Option<EndpointRecord>> {
        Ok(self.store.read(Duration::from_secs(2), |db| {
            crate::identity::endpoint(db, account, endpoint)
        })?)
    }
    pub fn open_window(
        &mut self,
        endpoint: &EndpointRecord,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<RetryWindow> {
        let id = Id::random().map_err(|_| Error::Invalid)?;
        let result=self.store.write(|db|{
            let now=clock.refresh().map_err(|_|rusqlite::Error::InvalidQuery)?;
            let current=crate::identity::endpoint(db,endpoint.acting.account,endpoint.acting.endpoint)?;
            let floor:u64=db.query_row("SELECT clock_floor FROM hrc_meta WHERE singleton=1",[],|r|r.get(0))?;
            let valid=current.is_some_and(|c|c.acting==endpoint.acting&&c.principal==endpoint.principal&&c.key==endpoint.key);
            if !valid||!permit()||now.after_floor(floor).is_err(){return Ok(Commit::new(None,id.as_bytes().to_vec()));}
            let existing:Option<RetryWindow>=db.query_row("SELECT id,expires FROM hrc_windows WHERE account=?1 AND endpoint=?2 AND expires>?3 ORDER BY expires DESC LIMIT 1",params![endpoint.acting.account.to_string(),endpoint.acting.endpoint.as_hex(),now.upper_ms+300_000],|r|Ok(RetryWindow{id:id_column(r,0)?,expires_ms:r.get(1)?})).optional()?;
            if let Some(window)=existing{return Ok(Commit::new(Some(window),encode(&("HRC.Window.Reuse",id))?));}
            let count:u64=db.query_row("SELECT count(*) FROM hrc_windows WHERE account=?1 AND endpoint=?2 AND expires>?3",params![endpoint.acting.account.to_string(),endpoint.acting.endpoint.as_hex(),now.lower_ms],|r|r.get(0))?;
            if count>=4{return Ok(Commit::new(None,id.as_bytes().to_vec()));}
            let window=RetryWindow{id,expires_ms:now.lower_ms+DAY};
            db.execute("INSERT INTO hrc_windows VALUES(?1,?2,?3,?4)",params![id.as_hex(),endpoint.acting.account.to_string(),endpoint.acting.endpoint.as_hex(),window.expires_ms])?;
            db.execute("UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",[now.lower_ms])?;
            Ok(Commit::new(Some(window),encode(&("HRC.Window",id,endpoint.acting.account,endpoint.acting.endpoint))?))
        })?;
        result.ok_or(Error::Refused("WindowUnavailable"))
    }
    pub fn maintain(&mut self, clock: TimeBounds) -> Result<()> {
        self.store.write(|db| {
            let now = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if now.after_floor(floor).is_err() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            retention::clean(db, now.upper_ms)?;
            db.execute(
                "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
                [now.lower_ms],
            )?;
            Ok(Commit::new((), encode(&("HRC.Expiry", now.lower_ms))?))
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Home/Workflow.rs"]
mod tests;
