// SPDX-License-Identifier: Apache-2.0
//! Explicit trust anchors and checked continuity extensions in the endpoint's guarded private store.
use super::{
    Client, Error, Result, cache,
    trust::{self, CheckedChain, ContactTrust, TrustState},
};
use crate::{delegation, identity, protocol::*, storage::Commit};
use rusqlite::{OptionalExtension, params};
use std::time::Duration;
impl Client {
    pub fn contact_trust(
        &mut self,
        room: RoomId,
        account: AccountId,
        grant: Option<&delegation::Grant>,
    ) -> Result<ContactTrust> {
        self.check_contact(room, account, grant, 0, None)
    }
    pub(super) fn historical_contact(
        &mut self,
        room: RoomId,
        account: AccountId,
        grant: Option<&delegation::Grant>,
        evidence: Id,
    ) -> Result<ContactTrust> {
        self.check_contact(room, account, grant, 0, Some(evidence))
    }
    fn check_contact(
        &mut self,
        room: RoomId,
        account: AccountId,
        grant: Option<&delegation::Grant>,
        depth: u8,
        evidence: Option<Id>,
    ) -> Result<ContactTrust> {
        if depth > 1 {
            return Err(Error::Input);
        }
        let capacity = self
            .store
            .read(Duration::from_secs(1), |db| {
                let exists: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM client_contacts WHERE account=?1)",
                    [account.to_string()],
                    |r| r.get(0),
                )?;
                let count: u64 =
                    db.query_row("SELECT count(*) FROM client_contacts", [], |r| r.get(0))?;
                Ok(exists || count < 256)
            })
            .map_err(|_| Error::Storage)?;
        if !capacity {
            return Err(Error::Rejected {
                code: ErrorCode::Overloaded,
                detail: "ContactCapacityExceeded".into(),
            });
        }
        let records:Vec<ContinuityRecord>=self.store.read(Duration::from_secs(1),|db| {
            db.prepare("SELECT record FROM client_contact_records WHERE account=?1 ORDER BY number LIMIT 1025")?.query_map([account.to_string()],|r|cache::decode(&r.get::<_,Vec<u8>>(0)?))?.collect()
        }).map_err(|_|Error::Storage)?;
        let retained = records.len();
        let (snapshot, records) = read_continuity(records, account, room.home, |after, limit| {
            self.read_as(
                Operation::AccountPublicIdentity,
                Target::Account(account),
                &identity::PublicIdentityRequest {
                    room,
                    after,
                    limit,
                    evidence,
                },
                grant,
            )
        })?;
        let associated=self.store.read(Duration::from_secs(1),|db|db.query_row("SELECT EXISTS(SELECT 1 FROM client_contact_rooms WHERE room=?1 AND account=?2)",params![room.to_string(),account.to_string()],|r|r.get::<_,bool>(0))).map_err(|_|Error::Storage)?;
        if !associated {
            self.store
                .write(|tx| {
                    tx.execute(
                        "INSERT INTO client_contact_rooms VALUES(?1,?2)",
                        params![room.to_string(), account.to_string()],
                    )?;
                    Ok(Commit::new(
                        (),
                        cache::encode(&("HRC.ContactRoom", room, account))?,
                    ))
                })
                .map_err(|_| Error::Storage)?;
        }
        let operator = if let AccountClass::Agent { operator } = snapshot.classification {
            if operator == account {
                return Err(Error::Input);
            }
            self.check_contact(room, operator, grant, depth + 1, evidence)?;
            Some(self.stored_chain(operator, false)?)
        } else {
            None
        };
        let key = VerifyingKey::from_bytes(self.profile.server.signing_key.as_bytes())
            .map_err(|_| Error::Configuration)?;
        let checked = trust::check_chain(&key, records, |account, position| {
            operator
                .as_ref()
                .filter(|c| c.latest().account == account)
                .and_then(|c| c.at(position))
        })
        .map_err(|_| Error::Rejected {
            code: ErrorCode::Denied,
            detail: "ContactContinuityInvalid".into(),
        })?;
        let last = checked.latest();
        let mut expected = last.clone();
        expected.head = checked.hashes.last().copied();
        expected.revision = snapshot.revision;
        if snapshot.revision < last.revision
            || cache::encode(&snapshot).map_err(|_| Error::Input)?
                != cache::encode(&expected).map_err(|_| Error::Input)?
        {
            return Err(Error::Input);
        }
        let unchanged: Option<(Vec<u8>, Vec<u8>, bool)> = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT anchor,head,trusted FROM client_contacts WHERE account=?1",
                    [account.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
            })
            .map_err(|_| Error::Storage)?;
        if let Some((anchor, head, trusted)) = unchanged {
            if anchor != checked.hashes[0].as_bytes()
                || !checked
                    .hashes
                    .iter()
                    .any(|h| h.as_bytes().as_slice() == head)
            {
                return Ok(checked.view(TrustState::Changed));
            }
            if checked
                .hashes
                .last()
                .is_some_and(|h| h.as_bytes().as_slice() == head)
            {
                return Ok(checked.view(if trusted {
                    TrustState::Trusted
                } else if snapshot.legacy_anchor {
                    TrustState::LegacyAnchor
                } else {
                    TrustState::UntrustedRegistration
                }));
            }
        }
        let view=self.store.write(|tx|{
            let old:Option<(Vec<u8>,Vec<u8>,bool)>=tx.query_row("SELECT anchor,head,trusted FROM client_contacts WHERE account=?1",[account.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let mut state=if snapshot.legacy_anchor{TrustState::LegacyAnchor}else{TrustState::UntrustedRegistration};
            if let Some((anchor,head,trusted))=old {
                if anchor!=checked.hashes[0].as_bytes() || !checked.hashes.iter().any(|h|h.as_bytes().as_slice()==head){return Ok(Commit::new(checked.view(TrustState::Changed),b"HRC.ContactChangedRefused".to_vec()))}
                if trusted{state=TrustState::Trusted;}
            }else{
                let count:u64=tx.query_row("SELECT count(*) FROM client_contacts",[],|r|r.get(0))?;if count>=256{return Err(rusqlite::Error::InvalidQuery)}
            }
            let view=checked.view(state.clone());
            tx.execute("INSERT INTO client_contacts VALUES(?1,?2,?3,?4,?5) ON CONFLICT(account) DO UPDATE SET head=excluded.head",params![account.to_string(),view.anchor.as_bytes(),view.head.as_bytes(),snapshot.legacy_anchor,state==TrustState::Trusted])?;
            for record in checked.records.iter().skip(retained) {
                tx.execute("INSERT INTO client_contact_records VALUES(?1,?2,?3)",params![account.to_string(),record.index,cache::encode(record)?])?;
            }
            Ok(Commit::new(view,checked.hashes.last().ok_or(rusqlite::Error::InvalidQuery)?.as_bytes().to_vec()))
        }).map_err(|_|Error::Storage)?;
        Ok(view)
    }
    /// Only the exact visible first-contact anchor can be accepted; an existing pin is immutable.
    pub fn trust_contact(&mut self, account: AccountId, anchor: Id, legacy: bool) -> Result<()> {
        self.store
            .write(|tx| {
                let (saved, old_legacy, trusted): (Vec<u8>, bool, bool) = tx.query_row(
                    "SELECT anchor,legacy,trusted FROM client_contacts WHERE account=?1",
                    [account.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                if saved != anchor.as_bytes() || legacy != old_legacy {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                if !trusted {
                    tx.execute(
                        "UPDATE client_contacts SET trusted=1 WHERE account=?1",
                        [account.to_string()],
                    )?;
                }
                Ok(Commit::new(
                    (),
                    cache::encode(&("HRC.ContactTrust", account, anchor, legacy))?,
                ))
            })
            .map_err(|_| Error::Storage)
    }
    pub(super) fn trusted_chain(&mut self, account: AccountId) -> Result<CheckedChain> {
        self.stored_chain(account, true)
    }
    pub(super) fn stored_chain(
        &mut self,
        account: AccountId,
        require_trust: bool,
    ) -> Result<CheckedChain> {
        let (records,trusted):(Vec<ContinuityRecord>,bool)=self.store.read(Duration::from_secs(1),|db|{
            let trusted=db.query_row("SELECT trusted FROM client_contacts WHERE account=?1",[account.to_string()],|r|r.get(0))?;
            let records=db.prepare("SELECT record FROM client_contact_records WHERE account=?1 ORDER BY number LIMIT 1025")?.query_map([account.to_string()],|r|cache::decode(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((records,trusted))
        }).map_err(|_|Error::Storage)?;
        if (require_trust && !trusted) || records.is_empty() || records.len() > 1024 {
            return Err(trust_required());
        }
        // Records were checked before this guarded write; every extension is checked again before admission.
        let hashes = records
            .iter()
            .map(|r| cache::encode(r).map(|b| digest(&b)))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| Error::Storage)?;
        Ok(CheckedChain { records, hashes })
    }
}
/// Continuation cursors name the last returned record, including byte-limited short pages.
fn read_continuity(
    mut records: Vec<ContinuityRecord>,
    account: AccountId,
    home: ServiceId,
    mut read: impl FnMut(u64, u16) -> Result<identity::PublicIdentity>,
) -> Result<(IdentitySnapshot, Vec<ContinuityRecord>)> {
    const RECORD_LIMIT: usize = 1024;
    const PAGE_LIMIT: u16 = 4;
    if records.len() > RECORD_LIMIT {
        return Err(Error::Input);
    }
    let mut after = records.len() as u64;
    let mut head = None;
    // Each continuation consumes at least one remaining record. One final empty
    // page is allowed when the retained chain already matches the current head.
    for _ in 0..(RECORD_LIMIT - records.len()).max(1) {
        let page = read(after, PAGE_LIMIT)?;
        if page.identity.account != account || page.identity.home != home {
            return Err(Error::Input);
        }
        if head.is_some_and(|old| old != page.identity.head) {
            return Err(Error::Rejected {
                code: ErrorCode::Conflict,
                detail: "ContactChangedDuringInspection".into(),
            });
        }
        head = Some(page.identity.head);
        let items = page.continuity.items;
        if items.len() > usize::from(PAGE_LIMIT)
            || records.len() + items.len() > RECORD_LIMIT
            || items
                .iter()
                .enumerate()
                .any(|(offset, record)| record.index != after + offset as u64 + 1)
        {
            return Err(Error::Input);
        }
        let end = after + items.len() as u64;
        if let Some(next) = page.continuity.next {
            let next: u64 = next.parse().map_err(|_| Error::Input)?;
            if items.is_empty() || next != end || end >= RECORD_LIMIT as u64 {
                return Err(Error::Input);
            }
        } else {
            records.extend(items);
            return Ok((page.identity, records));
        }
        records.extend(items);
        after = end;
    }
    Err(Error::Input)
}

#[cfg(test)]
#[path = "../../Tests/Client/ContinuityPages.rs"]
mod pagination_tests;
pub(super) fn trust_required() -> Error {
    Error::Rejected {
        code: ErrorCode::Denied,
        detail: "ContactTrustRequired".into(),
    }
}

impl Client {
    pub(super) fn room_contacts(&mut self, room: RoomId) -> Result<Vec<ContactTrust>> {
        let accounts:Vec<(String,bool)>=self.store.read(Duration::from_secs(1),|db|db.prepare("SELECT c.account,c.trusted FROM client_contacts c JOIN client_contact_rooms r ON r.account=c.account WHERE r.room=?1 ORDER BY c.account LIMIT 257")?.query_map([room.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?.collect()).map_err(|_|Error::Storage)?;
        if accounts.len() > 256 {
            return Err(Error::Input);
        }
        accounts
            .into_iter()
            .map(|(account, trusted)| {
                let chain = self.stored_chain(account.parse().map_err(|_| Error::Input)?, false)?;
                Ok(chain.view(if trusted {
                    TrustState::Trusted
                } else if chain.latest().legacy_anchor {
                    TrustState::LegacyAnchor
                } else {
                    TrustState::UntrustedRegistration
                }))
            })
            .collect()
    }
}
