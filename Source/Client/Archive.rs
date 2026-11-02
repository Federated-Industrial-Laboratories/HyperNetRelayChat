// SPDX-License-Identifier: Apache-2.0
//! Local decrypted content stays separate from authenticated events and expires with their cache rows.
use super::{cache, trust};
use crate::{
    crypto,
    protocol::*,
    storage::{self, Commit, Store},
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageContent {
    Decrypted(crypto::ApplicationMessage),
    Rejected(crypto::Rejection),
    Unavailable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoView {
    pub remote: crate::confidential::Inspection,
    pub local: Option<crypto::GroupState>,
    pub contacts: Vec<trust::ContactTrust>,
    pub future_only: bool,
}
impl CryptoView {
    pub(super) fn history_visible(&self, event: &Event) -> bool {
        event.room == self.remote.room
            && event.timestamp_ms >= self.remote.history_from_ms
            && event.timestamp_ms <= self.remote.history_until_ms
            && (!matches!(
                event.kind,
                Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
            ) || !crate::conversations::subjects(&event.actor)
                .iter()
                .any(|account| self.remote.ignored.contains(account)))
    }
}
pub(super) fn ready_key(group: Id, epoch: u64, commit: Id) -> String {
    format!("ready:{group}:{epoch}:{commit}")
}
// Independently bounded objects avoid coupling a maximum filter list to the
// recursive-node cost of an unrelated maximum contact list.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredView {
    version: u8,
    remote: Blob,
    local: Option<crypto::GroupState>,
    contacts: Vec<Blob>,
    future_only: bool,
}
impl StoredView {
    fn encode(view: &CryptoView) -> rusqlite::Result<Vec<u8>> {
        if view.contacts.len() > 256
            || view.remote.ignored.len() > 256
            || view
                .contacts
                .iter()
                .map(|c| c.account)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != view.contacts.len()
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let contacts = view
            .contacts
            .iter()
            .map(|c| {
                canonical_encode(
                    &Value::serialized(c).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    2048,
                )
                .map(Blob)
                .map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        cache::encode(&Self {
            version: 1,
            remote: Blob(cache::encode(&view.remote)?),
            local: view.local.clone(),
            contacts,
            future_only: view.future_only,
        })
    }
    fn decode(bytes: &[u8]) -> rusqlite::Result<CryptoView> {
        let saved: Self = cache::decode(bytes)?;
        if saved.version != 1 || saved.contacts.len() > 256 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let view = CryptoView {
            remote: cache::decode(&saved.remote.0)?,
            local: saved.local,
            contacts: saved
                .contacts
                .into_iter()
                .map(|b| {
                    canonical_decode(&b.0, 2048)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?
                        .deserialized()
                        .map_err(|_| rusqlite::Error::InvalidQuery)
                })
                .collect::<rusqlite::Result<Vec<_>>>()?,
            future_only: saved.future_only,
        };
        if view.remote.ignored.len() > 256
            || view
                .contacts
                .iter()
                .map(|c| c.account)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != view.contacts.len()
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(view)
    }
}
pub(super) fn initialize(store: &mut Store) -> storage::Result<()> {
    let version = store.read(Duration::from_secs(1), |db| {
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='client_encrypted_meta')",
            [],
            |r| r.get(0),
        )?;
        if exists {
            db.query_row("SELECT version FROM client_encrypted_meta", [], |r| {
                r.get::<_, u32>(0)
            })
            .map(Some)
        } else {
            Ok(None)
        }
    })?;
    if version == Some(1) {
        return Ok(());
    }
    if version.is_some() {
        return Err(storage::Error::InvalidInput);
    }
    store.write(|tx|{
        tx.execute_batch("CREATE TABLE client_encrypted_meta(version INTEGER NOT NULL CHECK(version=1));INSERT INTO client_encrypted_meta VALUES(1);
        CREATE TABLE client_crypto_rooms(room TEXT PRIMARY KEY,view BLOB NOT NULL);
        CREATE TABLE client_crypto_epochs(group_id BLOB NOT NULL,epoch INTEGER NOT NULL,members BLOB NOT NULL,PRIMARY KEY(group_id,epoch));
        CREATE TABLE client_mls_registration(endpoint BLOB PRIMARY KEY,action BLOB NOT NULL);
        CREATE TABLE client_contacts(account TEXT PRIMARY KEY,anchor BLOB NOT NULL,head BLOB NOT NULL,legacy INTEGER NOT NULL,trusted INTEGER NOT NULL);
        CREATE TABLE client_contact_rooms(room TEXT NOT NULL,account TEXT NOT NULL,PRIMARY KEY(room,account));
        CREATE TABLE client_contact_records(account TEXT NOT NULL,number INTEGER NOT NULL,record BLOB NOT NULL,PRIMARY KEY(account,number));
        CREATE TABLE client_cleartext(position INTEGER PRIMARY KEY,event TEXT NOT NULL UNIQUE REFERENCES client_events(id) ON DELETE CASCADE,room TEXT NOT NULL,sequence INTEGER NOT NULL,created INTEGER NOT NULL,actor TEXT NOT NULL,represented TEXT NOT NULL,operator TEXT,normal TEXT NOT NULL,result BLOB NOT NULL);
        CREATE INDEX client_cleartext_room ON client_cleartext(room,sequence);
        CREATE VIRTUAL TABLE client_cleartext_search USING fts5(normal,content='client_cleartext',content_rowid='position',tokenize='trigram case_sensitive 1');
        CREATE TRIGGER client_crypto_delivery_expire AFTER DELETE ON client_events BEGIN DELETE FROM crypto_deliveries WHERE lower(hex(event))=old.id;END;
        CREATE TRIGGER client_cleartext_insert AFTER INSERT ON client_cleartext BEGIN INSERT INTO client_cleartext_search(rowid,normal) VALUES(new.position,new.normal);END;
        CREATE TRIGGER client_cleartext_delete AFTER DELETE ON client_cleartext BEGIN INSERT INTO client_cleartext_search(client_cleartext_search,rowid,normal) VALUES('delete',old.position,old.normal);END;")?;
        Ok(Commit::new((),b"HRC.LocalEncrypted.Schema.1".to_vec()))
    })
}
pub(super) fn save_view(store: &mut Store, view: &CryptoView) -> storage::Result<()> {
    let bytes = StoredView::encode(view)?;
    let old: Option<Vec<u8>> = store.read(Duration::from_secs(1), |db| {
        db.query_row(
            "SELECT view FROM client_crypto_rooms WHERE room=?1",
            [view.remote.room.to_string()],
            |r| r.get(0),
        )
        .optional()
    })?;
    if old.as_ref() == Some(&bytes) {
        return Ok(());
    }
    store.write(|tx|{
        tx.execute("INSERT INTO client_crypto_rooms VALUES(?1,?2) ON CONFLICT(room) DO UPDATE SET view=excluded.view",params![view.remote.room.to_string(),bytes])?;
        Ok(Commit::new((),digest(&bytes).as_bytes().to_vec()))
    })
}
pub(super) fn view(store: &mut Store, room: RoomId) -> storage::Result<Option<CryptoView>> {
    store.read(Duration::from_secs(1), |db| {
        db.query_row(
            "SELECT view FROM client_crypto_rooms WHERE room=?1",
            [room.to_string()],
            |r| StoredView::decode(&r.get::<_, Vec<u8>>(0)?),
        )
        .optional()
    })
}
pub(super) fn content(
    store: &mut Store,
    events: &[Event],
) -> storage::Result<BTreeMap<Id, MessageContent>> {
    if events.len() > 256 {
        return Err(storage::Error::InvalidInput);
    }
    store.read(Duration::from_secs(1), |db| {
        let mut result = BTreeMap::new();
        let mut q = db.prepare("SELECT result FROM client_cleartext WHERE event=?1")?;
        for event in events {
            if let Some(content) = q
                .query_row([event.event.as_hex()], |r| {
                    cache::decode(&r.get::<_, Vec<u8>>(0)?)
                })
                .optional()?
            {
                result.insert(event.event, content);
            }
        }
        Ok(result)
    })
}
pub(super) fn persist(
    tx: &Transaction<'_>,
    event: &Event,
    outcome: &crypto::DeliveryOutcome,
) -> crypto::Result<()> {
    persist_content(
        tx,
        event,
        &match outcome {
            crypto::DeliveryOutcome::Message(message) => MessageContent::Decrypted(message.clone()),
            crypto::DeliveryOutcome::Rejected(reason) => MessageContent::Rejected(reason.clone()),
        },
    )
}
pub(super) fn persist_content(
    tx: &Transaction<'_>,
    event: &Event,
    result: &MessageContent,
) -> crypto::Result<()> {
    let encoded = cache::encode(event)?;
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT event FROM client_events WHERE id=?1 OR (room=?2 AND sequence=?3)",
            params![event.event.as_hex(), event.room.to_string(), event.sequence],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_ref().is_some_and(|old| old != &encoded) {
        return Err(crypto::Error::Conflict);
    }
    tx.execute(
        "INSERT OR IGNORE INTO client_events VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            event.event.as_hex(),
            event.room.to_string(),
            event.sequence,
            event.timestamp_ms,
            encoded,
            encoded.len()
        ],
    )?;
    let normal = match result {
        MessageContent::Decrypted(message) => {
            crate::text::lookup(&message.text, 32768).map_err(|_| crypto::Error::Invalid)?
        }
        _ => String::new(),
    };
    let operator = match event.actor {
        Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } => {
            Some(operator.to_string())
        }
        _ => None,
    };
    let bytes = cache::encode(result)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT result FROM client_cleartext WHERE event=?1",
            [event.event.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != bytes {
            return Err(crypto::Error::Conflict);
        }
        return Ok(());
    }
    tx.execute("INSERT INTO client_cleartext(event,room,sequence,created,actor,represented,operator,normal,result) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![event.event.as_hex(),event.room.to_string(),event.sequence,event.timestamp_ms,event.actor.acting().account.to_string(),event.actor.represented().to_string(),operator,normal,bytes])?;
    Ok(())
}

pub(super) fn serialize_content<S: serde::Serializer>(
    content: &BTreeMap<Id, MessageContent>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(content.len()))?;
    for (id, value) in content {
        map.serialize_entry(&id.as_hex(), value)?;
    }
    map.end()
}
