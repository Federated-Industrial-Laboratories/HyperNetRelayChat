// SPDX-License-Identifier: Apache-2.0
//! One public history/search/context view retains signed events and separate local plaintext.
use super::{Client, Error, MessageContent, Result, archive, cache};
use crate::{conversations, delegation, home, messaging, protocol::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationPage {
    pub events: Vec<Event>,
    #[serde(serialize_with = "super::archive::serialize_content")]
    pub content: BTreeMap<Id, MessageContent>,
    pub cursor: Blob,
    pub has_more: bool,
    pub members: Vec<conversations::Member>,
    pub room_revision: u64,
    pub stale: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCursor {
    room: RoomId,
    binding: Id,
    after: u64,
}
impl Client {
    pub fn history_messages(
        &mut self,
        room: RoomId,
        page: &messaging::Page,
        grant: Option<&delegation::Grant>,
    ) -> Result<ConversationPage> {
        let inspection: conversations::Inspection = self.read_as(
            Operation::RoomInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        let encrypted = inspection.confidentiality != RoomConfidentiality::Community;
        if encrypted {
            self.crypto_sync(room, grant)?;
        }
        let result: messaging::PageResult = self.read_as(
            if encrypted {
                Operation::CryptoHistory
            } else {
                Operation::HistoryPage
            },
            Target::Room(room),
            page,
            grant,
        )?;
        let content = if encrypted {
            archive::content(&mut self.store, &result.events).map_err(|_| Error::Storage)?
        } else {
            BTreeMap::new()
        };
        Ok(ConversationPage {
            events: result.events,
            content,
            cursor: result.cursor,
            has_more: result.has_more,
            members: result.members,
            room_revision: result.room_revision,
            stale: false,
        })
    }
    pub fn search_messages(
        &mut self,
        room: RoomId,
        query: &messaging::Search,
        grant: Option<&delegation::Grant>,
        cancel: &AtomicBool,
    ) -> Result<ConversationPage> {
        let inspection: conversations::Inspection = self.read_as(
            Operation::RoomInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        if inspection.confidentiality == RoomConfidentiality::Community {
            let action =
                self.prepare_as(Operation::SearchQuery, Target::Room(room), query, grant)?;
            let response = self.search_cancellable(&action, cancel)?;
            let page: messaging::PageResult = match response.outcome {
                Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input)?,
                outcome => return Err(Error::from_outcome(outcome)),
            };
            return Ok(ConversationPage {
                events: page.events,
                content: BTreeMap::new(),
                cursor: page.cursor,
                has_more: page.has_more,
                members: page.members,
                room_revision: page.room_revision,
                stale: false,
            });
        }
        let view = self.crypto_inspect(room, grant)?;
        self.query_archive(room, query, &view.remote, inspection, cancel, false)
    }
    /// Explicit retained archive inspection. Current network authority is not asserted.
    pub fn search_retained(
        &mut self,
        room: RoomId,
        query: &messaging::Search,
        cancel: &AtomicBool,
    ) -> Result<ConversationPage> {
        let view = archive::view(&mut self.store, room)
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Input)?;
        let cached = cache::room(&mut self.store, room).map_err(|_| Error::Storage)?;
        let inspection = conversations::Inspection {
            members: cached.members,
            read_sequence: 0,
            room_revision: 0,
            filter_revision: view.remote.filter_revision,
            moderator: false,
            confidentiality: view.remote.confidentiality,
        };
        self.query_archive(room, query, &view.remote, inspection, cancel, true)
    }
    fn query_archive(
        &mut self,
        room: RoomId,
        query: &messaging::Search,
        authority: &crate::confidential::Inspection,
        inspection: conversations::Inspection,
        cancel: &AtomicBool,
        stale: bool,
    ) -> Result<ConversationPage> {
        if query.limit == 0 || query.limit > 32 {
            return Err(Error::Input);
        }
        let terms = crate::text::query(&query.terms).map_err(|_| Error::Input)?;
        let start = query.from_ms.unwrap_or(0).max(authority.history_from_ms);
        let end = query
            .until_ms
            .unwrap_or(i64::MAX as u64)
            .min(authority.history_until_ms)
            .min(i64::MAX as u64);
        if start > end {
            return Err(Error::Input);
        }
        let binding = digest(
            &cache::encode(&(
                "HRC.LocalEncryptedSearch",
                room,
                &terms,
                query.sender,
                query.represented,
                start,
                end,
                authority.filter_revision,
                &authority.ignored,
                inspection.room_revision,
                stale,
            ))
            .map_err(|_| Error::Input)?,
        );
        let after = if let Some(cursor) = &query.cursor {
            let c: LocalCursor = canonical_decode(&cursor.0, 4096)
                .map_err(|_| Error::Input)?
                .deserialized()
                .map_err(|_| Error::Input)?;
            if c.room != room || c.binding != binding {
                return Err(Error::Rejected {
                    code: ErrorCode::ResynchronisationRequired,
                    detail: "LocalSearchContextChanged".into(),
                });
            }
            c.after
        } else {
            0
        };
        let expression = crate::text::match_expression(&terms);
        let (events,last,more)=self.store.read(Duration::from_millis(500),|db|{
            let from=if expression.is_some(){"client_cleartext_search s JOIN client_cleartext c ON c.position=s.rowid JOIN client_events e ON e.id=c.event"}else{"client_cleartext c JOIN client_events e ON e.id=c.event"};
            let index=if expression.is_some(){" AND client_cleartext_search MATCH ?7"}else{" AND ?7 IS NULL"};
            let sql=format!("SELECT c.sequence,e.event,c.normal FROM {from} WHERE c.room=?1 AND c.sequence>?2 AND c.created>=?3 AND c.created<=?4 AND (?5 IS NULL OR c.actor=?5) AND (?6 IS NULL OR c.represented=?6){index} ORDER BY c.sequence LIMIT 257");
            let mut stmt=db.prepare(&sql)?;let mut rows=stmt.query(rusqlite::params![room.to_string(),after,start,end,query.sender.map(|a|a.to_string()),query.represented.map(|a|a.to_string()),expression])?;
            let mut events=Vec::new();let mut last=after;let mut more=false;let mut scanned=0;let mut count=0;
            while let Some(row)=rows.next()? {
                if cancel.load(Ordering::Acquire){return Err(rusqlite::Error::InvalidQuery)}
                let data:Vec<u8>=row.get(1)?;
                if events.len()>=query.limit as usize || count>=256 || scanned+data.len()>1024*1024 {more=true;break;}
                count+=1;scanned+=data.len();last=row.get(0)?;let event:Event=cache::decode(&data)?;
                let normal:String=row.get(2)?;
                if terms.iter().all(|t|normal.contains(t)) && !conversations::subjects(&event.actor).iter().any(|a|authority.ignored.contains(a)){events.push(event);}
            }
            Ok((events,last,more))
        }).map_err(|_|if cancel.load(Ordering::Acquire){Error::Rejected{code:ErrorCode::Unavailable,detail:"Cancelled".into()}}else{Error::Storage})?;
        let content = archive::content(&mut self.store, &events).map_err(|_| Error::Storage)?;
        let cursor = Blob(
            cache::encode(&LocalCursor {
                room,
                binding,
                after: last,
            })
            .map_err(|_| Error::Storage)?,
        );
        Ok(ConversationPage {
            events,
            content,
            cursor,
            has_more: more,
            members: inspection.members,
            room_revision: inspection.room_revision,
            stale,
        })
    }
    pub fn message_context(
        &mut self,
        room: RoomId,
        event: Id,
        grant: Option<&delegation::Grant>,
    ) -> Result<ConversationPage> {
        let inspection: conversations::Inspection = self.read_as(
            Operation::RoomInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        if inspection.confidentiality == RoomConfidentiality::Community {
            let result: messaging::ContextResult = self.read_as(
                Operation::HistoryContext,
                Target::Room(room),
                &messaging::Context { event },
                grant,
            )?;
            return Ok(ConversationPage {
                events: result.events,
                content: BTreeMap::new(),
                cursor: Blob(Vec::new()),
                has_more: false,
                members: result.members,
                room_revision: result.room_revision,
                stale: false,
            });
        }
        let view = self.crypto_inspect(room, grant)?;
        let events=self.store.read(Duration::from_secs(1),|db|{
            let target:Vec<u8>=db.query_row("SELECT e.event FROM client_events e JOIN client_cleartext c ON c.event=e.id WHERE e.id=?1 AND e.room=?2 AND c.created>=?3 AND c.created<=?4",rusqlite::params![event.as_hex(),room.to_string(),view.remote.history_from_ms,view.remote.history_until_ms.min(i64::MAX as u64)],|r|r.get(0))?;
            let target:Event=cache::decode(&target)?;
            if conversations::subjects(&target.actor).iter().any(|a|view.remote.ignored.contains(a)){return Err(rusqlite::Error::InvalidQuery)}
            let mut events=db.prepare("SELECT e.event FROM client_events e JOIN client_cleartext c ON c.event=e.id WHERE e.room=?1 AND c.sequence>=?2 AND c.sequence<=?3 AND c.created>=?4 AND c.created<=?5 ORDER BY c.sequence LIMIT 5")?.query_map(rusqlite::params![room.to_string(),target.sequence.saturating_sub(2),target.sequence.saturating_add(2),view.remote.history_from_ms,view.remote.history_until_ms.min(i64::MAX as u64)],|r|cache::decode::<Event>(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
            events.retain(|e|!conversations::subjects(&e.actor).iter().any(|a|view.remote.ignored.contains(a)));Ok(events)
        }).map_err(|_|Error::Rejected{code:ErrorCode::Denied,detail:"EncryptedLocalContextUnavailable".into()})?;
        let content = archive::content(&mut self.store, &events).map_err(|_| Error::Storage)?;
        Ok(ConversationPage {
            events,
            content,
            cursor: Blob(Vec::new()),
            has_more: false,
            members: inspection.members,
            room_revision: inspection.room_revision,
            stale: false,
        })
    }
}
