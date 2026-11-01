// SPDX-License-Identifier: Apache-2.0
//! Durable public account continuity and bounded endpoint lifecycle state.
use crate::{
    home::{self, types::*},
    protocol::*,
    storage::{self, Commit, Store},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::time::Duration;

pub(crate) fn initialize(store: &mut Store, home: ServiceId) -> storage::Result<()> {
    let present = store.read(Duration::from_secs(2), |db| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='identity_schema')",
            [],
            |r| r.get::<_, bool>(0),
        )
    })?;
    if present {
        let version: u64 = store.read(Duration::from_secs(2), |db| {
            db.query_row(
                "SELECT version FROM identity_schema WHERE singleton=1",
                [],
                |r| r.get(0),
            )
        })?;
        if version != 1 {
            return Err(rusqlite::Error::InvalidQuery.into());
        }
        return Ok(());
    }
    store.write(|db|{
  db.execute_batch("CREATE TABLE identity_schema(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);INSERT INTO identity_schema VALUES(1,1);
   CREATE TABLE identity_accounts(account TEXT PRIMARY KEY,recovery_generation INTEGER NOT NULL,head BLOB,records INTEGER NOT NULL DEFAULT 0,bytes INTEGER NOT NULL DEFAULT 0,legacy_anchor INTEGER NOT NULL);
   CREATE TABLE identity_records(account TEXT NOT NULL,number INTEGER NOT NULL,digest BLOB NOT NULL,record BLOB NOT NULL,PRIMARY KEY(account,number));
   CREATE TABLE identity_tickets(request TEXT PRIMARY KEY,digest BLOB NOT NULL,request_bytes BLOB NOT NULL,controller BLOB NOT NULL,authorization BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,account TEXT NOT NULL,endpoint TEXT NOT NULL,controller_account TEXT NOT NULL,controller_endpoint TEXT NOT NULL,target_generation INTEGER NOT NULL);
   CREATE INDEX identity_ticket_target ON identity_tickets(account,endpoint);CREATE INDEX identity_ticket_controller ON identity_tickets(controller_account,controller_endpoint);
   CREATE TABLE identity_receipts(request TEXT PRIMARY KEY,digest BLOB NOT NULL,account TEXT NOT NULL,endpoint TEXT NOT NULL,receipt BLOB NOT NULL,expires INTEGER NOT NULL);")?;
  let accounts=db.prepare("SELECT account FROM hrc_accounts ORDER BY id LIMIT 257")?.query_map([],|r|decode::<AccountId>(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
  if accounts.len()>256{return Err(rusqlite::Error::InvalidQuery)}
  for account in accounts {anchor(db,home,account,None)?;}
  Ok(Commit::new((),b"HRC.Identity.Schema.1".to_vec()))
 })
}
pub(crate) fn snapshot(
    db: &Connection,
    home: ServiceId,
    account: AccountId,
) -> rusqlite::Result<IdentitySnapshot> {
    let (classification, security_generation, revision, recovery_key): (
        Vec<u8>,
        u64,
        u64,
        Vec<u8>,
    ) = db.query_row(
        "SELECT class,security,revision,recovery FROM hrc_accounts WHERE id=?1",
        [account.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let (recovery_generation, head): (u64, Option<Vec<u8>>) = db.query_row(
        "SELECT recovery_generation,head FROM identity_accounts WHERE account=?1",
        [account.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let endpoints=db.prepare("SELECT actor,key,principal FROM hrc_endpoints WHERE account=?1 AND disabled=0 ORDER BY endpoint LIMIT 9")?.query_map([account.to_string()],|r|Ok(EndpointView{actor:decode(&r.get::<_,Vec<u8>>(0)?)?,key:Id::from_bytes(r.get::<_,Vec<u8>>(1)?.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?),principal:r.get::<_,String>(2)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
    if endpoints.len() > 8 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(IdentitySnapshot {
        home,
        account,
        classification: decode(&classification)?,
        security_generation,
        revision,
        recovery_key: Id::from_bytes(
            recovery_key
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        recovery_generation,
        legacy_anchor: db.query_row(
            "SELECT legacy_anchor FROM identity_accounts WHERE account=?1",
            [account.to_string()],
            |r| r.get(0),
        )?,
        head: head
            .map(|b| {
                b.try_into()
                    .map(Id::from_bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?,
        endpoints,
    })
}
pub(crate) fn append(
    db: &Transaction<'_>,
    home: ServiceId,
    account: AccountId,
    change: IdentityChange,
    authorizations: Vec<Blob>,
) -> rusqlite::Result<u64> {
    let state = snapshot(db, home, account)?;
    let (count, bytes): (u64, u64) = db.query_row(
        "SELECT records,bytes FROM identity_accounts WHERE account=?1",
        [account.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let position = home::next_position(db)?;
    let record = ContinuityRecord {
        index: count + 1,
        previous: state.head,
        position,
        change,
        authorizations,
        state,
    };
    let encoded = encode(&record)?;
    if count >= 1024
        || bytes + encoded.len() as u64 > 16 * 1024 * 1024
        || encoded.len() > ORDINARY_FRAME_BYTES - 8192
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let hash = digest(&encoded);
    db.execute(
        "INSERT INTO identity_records VALUES(?1,?2,?3,?4)",
        params![account.to_string(), count + 1, hash.as_bytes(), encoded],
    )?;
    db.execute(
        "UPDATE identity_accounts SET head=?1,records=records+1,bytes=bytes+?2 WHERE account=?3",
        params![hash.as_bytes(), encoded.len(), account.to_string()],
    )?;
    Ok(position)
}
pub(crate) fn anchor(
    db: &Transaction<'_>,
    home: ServiceId,
    account: AccountId,
    registration: Option<&[u8]>,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO identity_accounts(account,recovery_generation,legacy_anchor) VALUES(?1,1,?2)",
        params![account.to_string(), registration.is_none()],
    )?;
    append(
        db,
        home,
        account,
        if registration.is_some() {
            IdentityChange::Registered
        } else {
            IdentityChange::LegacyServiceAnchor
        },
        registration
            .map(|b| vec![Blob(b.to_vec())])
            .unwrap_or_default(),
    )?;
    Ok(())
}
pub(crate) fn controller(db: &Connection, actor: &Actor, account: AccountId) -> Domain<()> {
    let Actor::Direct { acting } = actor else {
        return deny("AccountController");
    };
    if acting.account == account {
        return Ok(());
    }
    let class: Option<Vec<u8>> = db
        .query_row(
            "SELECT class FROM hrc_accounts WHERE id=?1",
            [account.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if class.map(|c| decode::<AccountClass>(&c)).transpose()?
        != Some(AccountClass::Agent {
            operator: acting.account,
        })
    {
        return deny("AccountController");
    }
    Ok(())
}
/// Every security withdrawal and its affected grant/approval state share the caller's transaction.
pub(crate) fn invalidate(db: &Transaction<'_>, account: AccountId) -> rusqlite::Result<()> {
    let grants = db
        .prepare("SELECT grant_data FROM hrc_grants WHERE state!=2 ORDER BY id LIMIT 16385")?
        .query_map([], |r| {
            decode::<crate::delegation::Grant>(&r.get::<_, Vec<u8>>(0)?)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if grants.len() > 16384 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for mut grant in grants {
        if grant.owner != account
            && grant.scope.agent.account != account
            && grant.operator != account
        {
            continue;
        }
        grant.reference.generation = grant
            .reference
            .generation
            .checked_add(1)
            .ok_or(rusqlite::Error::InvalidQuery)?;
        grant.state = crate::delegation::State::Paused;
        db.execute(
            "UPDATE hrc_grants SET generation=?1,state=1,grant_data=?2 WHERE id=?3",
            params![
                grant.reference.generation,
                encode(&grant)?,
                grant.reference.id.as_hex()
            ],
        )?;
        db.execute(
            "UPDATE hrc_approvals SET state=2 WHERE grant_id=?1 AND state IN(0,1)",
            [grant.reference.id.as_hex()],
        )?;
    }
    db.execute(
        "UPDATE hrc_approvals SET state=2 WHERE owner=?1 AND state IN(0,1)",
        [account.to_string()],
    )?;
    crate::confidential::invalidate_accounts(db, &[account])
}
