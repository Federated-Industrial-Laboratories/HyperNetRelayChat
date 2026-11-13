// SPDX-License-Identifier: Apache-2.0
//! Atomic live enrolment with exact retry and server-enforced restricted scopes.
#[path = "Types.rs"]
mod types;
pub use types::{
    Action, AgentAccess, Artifact, Classification, Consent, ConsentReceipt, FORMAT, Identity,
    MAXIMUM, Policy, Prepare, Request, Response, Scope, Status,
};
#[path = "Claims.rs"]
mod claims;
#[path = "Consent.rs"]
mod consent;
#[path = "Retirement.rs"]
mod retirement;
#[path = "Scopes.rs"]
pub(crate) mod scopes;
use super::{
    Home,
    types::{self as domain, *},
};
use crate::{
    clock::TimeBounds,
    protocol::{self, *},
    storage::{self, Commit, Store},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::time::Duration;

pub(crate) fn initialize(store: &mut Store) -> storage::Result<()> {
    let exists = store.read(Duration::from_secs(2), |db| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='hrc_admission_policy')",
            [],
            |r| r.get::<_, bool>(0),
        )
    })?;
    let retired = store.read(Duration::from_secs(2), |db| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='hrc_admission_retired')",
            [],
            |r| r.get::<_, bool>(0),
        )
    })?;
    if exists && retired {
        return Ok(());
    }
    store.write(|db| {
        db.execute_batch("CREATE TABLE IF NOT EXISTS hrc_admission_retired(claim TEXT PRIMARY KEY,result BLOB NOT NULL,affected BLOB NOT NULL)")?;
        if exists { return Ok(Commit::new((),b"HRC.Admission.Retirement.Schema.1".to_vec())); }

        db.execute_batch("CREATE TABLE hrc_admission_policy(singleton INTEGER PRIMARY KEY CHECK(singleton=1),policy BLOB NOT NULL);
        CREATE TABLE hrc_admission_claims(id TEXT PRIMARY KEY,request BLOB NOT NULL,invitation BLOB NOT NULL,registration BLOB,result BLOB,expires INTEGER NOT NULL);
        CREATE TABLE hrc_agent_consents(id TEXT PRIMARY KEY,request BLOB NOT NULL,actor BLOB NOT NULL,receipt BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE hrc_account_scopes(account TEXT PRIMARY KEY,operator TEXT,original BLOB NOT NULL,scope BLOB NOT NULL);")?;
        Ok(Commit::new((), b"HRC.Admission.Schema.1".to_vec()))
    })
}
fn policy(db: &Connection) -> Domain<Policy> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT policy FROM hrc_admission_policy WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    bytes
        .map(|b| domain::decode(&b))
        .transpose()?
        .ok_or(Fault::Reject(ErrorCode::Denied, "AdmissionDisabled"))
}
fn now(db: &Connection, clock: TimeBounds) -> rusqlite::Result<TimeBounds> {
    let time = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let floor: u64 = db.query_row(
        "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    time.after_floor(floor)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(time)
}
fn rooms(db: &Connection, home: ServiceId, rooms: &[RoomId]) -> Domain<()> {
    if rooms.is_empty() || rooms.len() > 16 || rooms.windows(2).any(|v| v[0] >= v[1]) {
        return invalid("AdmissionRooms");
    }
    for room in rooms {
        if room.home != home {
            return invalid("AdmissionRoomHome");
        }
        let mode: Option<u8> = db
            .query_row(
                "SELECT mode FROM hrc_rooms WHERE id=?1",
                [room.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if mode != Some(0) {
            return deny("AdmissionCommunityRooms");
        }
    }
    Ok(())
}
fn validate_prepare(db: &Connection, home: ServiceId, p: &Policy, request: &Prepare) -> Domain<()> {
    if !p.enabled {
        return deny("AdmissionDisabled");
    }
    rooms(db, home, &request.rooms)?;
    if request.rooms.iter().any(|r| !p.rooms.contains(r))
        || request.identity.account.origin != home.network
        || request.identity.endpoint_key == request.identity.recovery_key
    {
        return deny("AdmissionBinding");
    }
    for key in [request.identity.endpoint_key, request.identity.recovery_key] {
        if VerifyingKey::from_bytes(key.as_bytes()).map_or(true, |k| k.is_weak()) {
            return invalid("AdmissionKey");
        }
    }
    match request.classification {
        Classification::Person
            if request.operator_consent.is_some()
                || request.successor
                || request.allow_agent_replies =>
        {
            invalid("PersonConsent")
        }
        Classification::Agent { operator }
            if !p.agents_enabled
                || operator.origin != home.network
                || operator == request.identity.account =>
        {
            deny("AgentAdmissionDisabled")
        }
        _ => Ok(()),
    }
}
fn fault(error: Fault) -> rusqlite::Result<Response> {
    match error {
        Fault::Sql(e) => Err(e),
        Fault::Reject(_, code) => Ok(Response::new(Status::Refused { code: code.into() })),
    }
}
impl Home {
    pub fn configure_admission(&mut self, policy: Policy, clock: TimeBounds) -> super::Result<()> {
        self.configure_admission_inner(policy, clock, false)
    }
    pub(crate) fn configure_host_admission(
        &mut self,
        policy: Policy,
        clock: TimeBounds,
    ) -> super::Result<()> {
        self.configure_admission_inner(policy, clock, true)
    }
    fn configure_admission_inner(
        &mut self,
        policy: Policy,
        clock: TimeBounds,
        once: bool,
    ) -> super::Result<()> {
        let home = self.home;
        let result = self.store.write(|db| {
            let encoded = domain::encode(&policy)?;
            if once {
                db.execute_batch("CREATE TABLE IF NOT EXISTS hrc_host_admission(singleton INTEGER PRIMARY KEY CHECK(singleton=1),policy BLOB NOT NULL)")?;
                let retained: Option<Vec<u8>> = db.query_row("SELECT policy FROM hrc_host_admission WHERE singleton=1", [], |r| r.get(0)).optional()?;
                if let Some(retained) = retained {
                    return Ok(Commit::new(if retained == encoded { Ok(()) } else { Err("HostAdmissionConfigurationMismatch") }, b"HRC.Host.AdmissionRetry".to_vec()));
                }
            }
            let checked = (|| -> Domain<()> {
                rooms(db, home, &policy.rooms)?;
                if !(1..=8).contains(&policy.max_agents_per_operator) || VerifyingKey::from_bytes(policy.registrar_key.as_bytes()).map_or(true, |k|k.is_weak()) { return invalid("AdmissionPolicy"); }
                Ok(())
            })();
            match checked { Err(Fault::Sql(e)) => return Err(e), Err(Fault::Reject(_,s)) => return Ok(Commit::new(Err(s), b"HRC.Admission.PolicyRefused".to_vec())), Ok(()) => () }
            let time=now(db,clock)?;
            db.execute("UPDATE hrc_meta SET version=2 WHERE singleton=1",[])?;
            db.execute("INSERT INTO hrc_admission_policy VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET policy=excluded.policy", [&encoded])?;
            if once { db.execute("INSERT INTO hrc_host_admission VALUES(1,?1)", [&encoded])?; }
            db.execute("UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1", [time.lower_ms])?;
            Ok(Commit::new(Ok(()), domain::encode(&("HRC.Admission.Policy",&policy))?))
        })?;
        result.map_err(super::Error::Refused)
    }
    /// Only the private registrar may attest the exact certified native principal.
    pub fn admission_request(
        &mut self,
        request: &Request,
        registrar: Id,
        clock: TimeBounds,
    ) -> super::Result<Response> {
        if request.format != FORMAT {
            return Err(super::Error::Invalid);
        }
        let home = self.home;
        let signer = &self.signer;
        Ok(self.store.write(|db| {
            db.execute_batch("SAVEPOINT hrc_domain_effects")?;
            let result = (|| -> Domain<Response> {
                let p = policy(db)?;
                if p.registrar_key != registrar {
                    return deny("RegistrarBinding");
                }
                let time = now(db, clock)?;
                let result = claims::handle(db, home, signer, &p, request, time)?;
                db.execute(
                    "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
                    [time.lower_ms],
                )?;
                Ok(result)
            })();
            let response = match result {
                Ok(r) => {
                    db.execute_batch("RELEASE hrc_domain_effects")?;
                    r
                }
                Err(e) => {
                    db.execute_batch("ROLLBACK TO hrc_domain_effects; RELEASE hrc_domain_effects")?;
                    fault(e)?
                }
            };
            Ok(Commit::new(
                response.clone(),
                domain::encode(&(
                    "HRC.Admission",
                    protocol::digest(&domain::encode(request)?),
                    &response,
                ))?,
            ))
        })?)
    }
}
pub(crate) use consent::operate;
