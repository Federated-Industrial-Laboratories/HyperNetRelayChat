// SPDX-License-Identifier: Apache-2.0
//! Ordered public transitions and encrypted deliveries advance only durable local MLS state.
use super::{
    Client, CryptoView, Error, MessageContent, Result, archive, cache,
    encrypted::{failure, require_trust},
};
use crate::{
    confidential as domain, crypto, delegation, home, messaging, protocol::*, storage::Commit,
};
use rusqlite::{OptionalExtension, params};
use std::time::Duration;
impl Client {
    pub(super) fn own_member(&mut self, room: RoomId) -> Result<domain::Member> {
        let device = self.crypto_device()?;
        let registration = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT action FROM client_mls_registration WHERE endpoint=?1",
                    [device.actor.endpoint.as_bytes()],
                    |r| r.get::<_, Vec<u8>>(0),
                )
            })
            .map_err(|_| Error::Rejected {
                code: ErrorCode::Denied,
                detail: "MlsEnrolmentRequired".into(),
            })?;
        let actor = self
            .prepare(Operation::CryptoInspect, Target::Room(room), Value::Null)?
            .actor;
        Ok(domain::Member {
            actor,
            credential: device.credential(room),
            registration: Blob(registration),
            delegation: None,
        })
    }
    fn epoch_members(&mut self, group: Id, epoch: u64) -> Result<Vec<domain::Member>> {
        self.store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT members FROM client_crypto_epochs WHERE group_id=?1 AND epoch=?2",
                    params![group.as_bytes(), epoch],
                    |r| cache::decode(&r.get::<_, Vec<u8>>(0)?),
                )
            })
            .map_err(|_| Error::Storage)
    }
    /// Catch-up is bounded to eight pages per request. Repeating it continues the signed cursor.
    pub fn crypto_sync(
        &mut self,
        room: RoomId,
        grant: Option<&delegation::Grant>,
    ) -> Result<CryptoView> {
        self.effects_ready()?;
        let room_exists = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM client_rooms WHERE id=?1)",
                    [room.to_string()],
                    |r| r.get::<_, bool>(0),
                )
            })
            .map_err(|_| Error::Storage)?;
        if !room_exists {
            let inspection: crate::conversations::Inspection = self.read_as(
                Operation::RoomInspect,
                Target::Room(room),
                &home::Empty {},
                grant,
            )?;
            let summary = crate::conversations::Summary {
                room,
                name: room.to_string(),
                topic: String::new(),
                revision: inspection.room_revision,
                sequence: 0,
                joined: true,
                unread: 0,
                confidentiality: inspection.confidentiality,
                invited: false,
            };
            self.store
                .write(|tx| {
                    tx.execute(
                        "INSERT INTO client_rooms(id,summary) VALUES(?1,?2)",
                        params![room.to_string(), cache::encode(&summary)?],
                    )?;
                    Ok(Commit::new((), cache::encode(&summary)?))
                })
                .map_err(|_| Error::Storage)?;
        }
        let mut view = self.crypto_inspect(room, grant)?;
        require_trust(&view)?;
        let Some(group) = view.remote.group else {
            return Ok(view);
        };
        let device = self.crypto_device()?;
        if view.local.is_none()
            && view
                .remote
                .members
                .iter()
                .any(|m| m.credential.actor == device.actor)
        {
            let welcome: domain::Welcome = self.read_as(
                Operation::CryptoWelcome,
                Target::Room(room),
                &home::Empty {},
                grant,
            )?;
            if welcome.group != group
                || welcome.epoch > view.remote.epoch
                || welcome.sequence > view.remote.sequence
            {
                return Err(Error::Input);
            }
            let package=self.store.read(Duration::from_secs(1),|db|db.query_row("SELECT EXISTS(SELECT 1 FROM crypto_packages WHERE digest=?1 AND endpoint=?2)",params![welcome.package_digest.as_bytes(),device.actor.endpoint.as_bytes()],|r|r.get::<_,bool>(0))).map_err(|_|Error::Storage)?;
            if !package {
                return Err(Error::Input);
            }
            self.check_members_contacts(room, &welcome.members, grant, welcome.event)?;
            let roster = self.trusted_roster(room, &welcome.members, false)?;
            let state = device
                .join_with(
                    &mut self.store,
                    crypto::WelcomeJoin {
                        group,
                        epoch: welcome.epoch,
                        cursor: welcome.sequence,
                        welcome: &welcome.welcome.0,
                        roster: &roster,
                    },
                    |tx, state| epoch_in(tx, group, state.epoch, &welcome.members),
                )
                .map_err(failure)?;
            view.local = Some(state);
        }
        let key = VerifyingKey::from_bytes(self.profile.server.signing_key.as_bytes())
            .map_err(|_| Error::Configuration)?;
        let mut restarted = false;
        for attempt in 0..8 {
            let cached = cache::room(&mut self.store, room).map_err(|_| Error::Storage)?;
            let had_cursor = cached.cursor.is_some();
            let page = self.read_as::<messaging::PageResult, _>(
                Operation::CryptoHistory,
                Target::Room(room),
                &messaging::Page {
                    cursor: cached.cursor,
                    limit: 16,
                },
                grant,
            );
            let page = match page {
                Ok(page) => page,
                Err(error)
                    if had_cursor
                        && !restarted
                        && attempt < 7
                        && cache::cursor_context_changed(&error) =>
                {
                    // Restart only the signed history continuation, never MLS state.
                    // The next read checks current authority and shares this call's
                    // eight-request ceiling. A second context change is explicit.
                    cache::restart_cursor(&mut self.store, room).map_err(|_| Error::Storage)?;
                    restarted = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let now = self
                .profile
                .clock
                .sample()
                .map_err(|_| Error::Clock)?
                .upper_ms;
            let verified = verify_cursor(&page.cursor.0, &key).map_err(|_| Error::Input)?;
            if verified.value().room != room
                || verified.value().account
                    != grant
                        .map(|g| g.owner)
                        .unwrap_or(self.profile.registration.account)
                || page.events.len() > 16
            {
                return Err(Error::Input);
            }
            for event in &page.events {
                if event.room != room || event.sequence > verified.value().sequence {
                    return Err(Error::Input);
                }
                if matches!(
                    event.kind,
                    Operation::CryptoPropose | Operation::CryptoCommit | Operation::CryptoRecover
                ) {
                    self.receive_transition(event, grant)?;
                } else if matches!(
                    event.kind,
                    Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
                ) {
                    self.receive_encrypted(event)?;
                }
            }
            cache::receive(
                &mut self.store,
                room,
                verified.value().account,
                &page,
                &key,
                now,
            )
            .map_err(|_| Error::Storage)?;
            if !page.has_more {
                break;
            }
        }
        view = self.crypto_inspect(room, grant)?;
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        if let Some(local) = &view.local
            && local.active
            && !local.frozen
            && local.epoch == view.remote.epoch
            && !view
                .remote
                .required_removals
                .contains(&device.actor.endpoint)
            && now.lower_ms >= view.remote.history_from_ms
            && now.upper_ms <= view.remote.history_until_ms
        {
            let commit = view.remote.commit_digest.ok_or(Error::Input)?;
            let receipt: Option<Vec<u8>> = self
                .store
                .read(Duration::from_secs(1), |db| {
                    db.query_row(
                        "SELECT result FROM crypto_transitions WHERE group_id=?1 AND sequence=?2",
                        params![group.as_bytes(), view.remote.sequence],
                        |r| r.get(0),
                    )
                    .optional()
                })
                .map_err(|_| Error::Storage)?;
            let welcome = receipt
                .map(|bytes| cache::decode::<crypto::EpochReceipt>(&bytes))
                .transpose()
                .map_err(|_| Error::Storage)?
                .and_then(|r| r.welcome)
                .map(Blob);
            let already: bool = self
                .store
                .read(Duration::from_secs(1), |db| {
                    let id = archive::ready_key(group, view.remote.epoch, commit);
                    db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM client_preferences WHERE id=?1)",
                        [id],
                        |r| r.get(0),
                    )
                })
                .map_err(|_| Error::Storage)?;
            if !already {
                let action = self.prepare_as(
                    Operation::CryptoEpochReady,
                    Target::Room(room),
                    &domain::Ready {
                        group,
                        epoch: local.epoch,
                        commit_digest: commit,
                        sequence: view.remote.sequence,
                        welcome,
                    },
                    grant,
                )?;
                let response = self.execute(&action)?;
                if !matches!(response.outcome, Outcome::Committed { .. }) {
                    return Err(Error::from_outcome(response.outcome));
                }
                view = self.crypto_inspect(room, grant)?;
            }
        }
        Ok(view)
    }
    pub(super) fn check_members_contacts(
        &mut self,
        room: RoomId,
        members: &[domain::Member],
        grant: Option<&delegation::Grant>,
        evidence: Id,
    ) -> Result<()> {
        // A fully verified pinned historical roster needs no fresh account read.
        // If a known account acquired another endpoint, fetch the exact evidence
        // rather than treating its older cached chain as a complete proof.
        if self.trusted_roster(room, members, false).is_ok() {
            return Ok(());
        }
        let mut accounts = std::collections::BTreeSet::new();
        for member in members {
            accounts.insert(member.actor.acting().account);
            accounts.insert(member.actor.represented());
            if let Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } =
                member.actor
            {
                accounts.insert(operator);
            }
        }
        for account in accounts {
            if self
                .historical_contact(room, account, grant, evidence)?
                .state
                != super::trust::TrustState::Trusted
            {
                return Err(super::trust_store::trust_required());
            }
        }
        Ok(())
    }
    fn receive_transition(
        &mut self,
        event: &Event,
        grant: Option<&delegation::Grant>,
    ) -> Result<()> {
        let transition: domain::TransitionEvent =
            event.body.deserialized().map_err(|_| Error::Input)?;
        if digest(&transition.commit.0) != transition.commit_digest {
            return Err(Error::Input);
        }
        self.check_members_contacts(event.room, &transition.members, grant, event.event)?;
        let roster = self.trusted_roster(event.room, &transition.members, false)?;
        let device = self.crypto_device()?;
        let exists = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM crypto_groups WHERE id=?1 AND mode='member')",
                    [transition.group.as_bytes()],
                    |r| r.get::<_, bool>(0),
                )
            })
            .map_err(|_| Error::Storage)?;
        if !exists {
            return Ok(());
        }
        let state = device
            .state(&mut self.store, transition.group)
            .map_err(failure)?;
        if event.sequence <= state.cursor {
            return Ok(());
        }
        if let Some(epoch) = transition.previous_epoch {
            if transition.epoch != epoch + 1 {
                return Err(Error::Input);
            }
            match device.accept_transition_with(
                &mut self.store,
                crypto::TransitionOrder {
                    group: transition.group,
                    epoch,
                    previous_sequence: state.cursor,
                    sequence: event.sequence,
                },
                &transition.commit.0,
                &roster,
                |tx, receipt| epoch_in(tx, transition.group, receipt.epoch, &transition.members),
            ) {
                Ok(_) => {}
                Err(error) => {
                    let report = self.prepare_as(
                        Operation::CryptoReport,
                        Target::Room(event.room),
                        &domain::TransitionFailure {
                            group: transition.group,
                            epoch: transition.epoch,
                            commit_digest: transition.commit_digest,
                        },
                        grant,
                    )?;
                    let _ = self.execute(&report);
                    return Err(failure(error));
                }
            }
        } else {
            if transition.epoch != 0 || state.epoch != 0 {
                return Err(Error::Input);
            }
            self.store
                .write(|tx| {
                    let info: Vec<u8> = tx.query_row(
                        "SELECT info FROM crypto_creation WHERE group_id=?1",
                        [transition.group.as_bytes()],
                        |r| r.get(0),
                    )?;
                    if info != transition.commit.0 {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    tx.execute(
                        "UPDATE crypto_groups SET cursor=?2 WHERE id=?1",
                        params![transition.group.as_bytes(), event.sequence],
                    )?;
                    Ok(Commit::new((), event.action_digest.as_bytes().to_vec()))
                })
                .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
    fn receive_encrypted(&mut self, event: &Event) -> Result<()> {
        let envelope: crypto::EncryptedEvent =
            event.body.deserialized().map_err(|_| Error::Input)?;
        envelope.validate_event(event).map_err(failure)?;
        let group = envelope.context.group;
        let exists = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM crypto_groups WHERE id=?1 AND mode='member')",
                    [group.as_bytes()],
                    |r| r.get::<_, bool>(0),
                )
            })
            .map_err(|_| Error::Storage)?;
        let device = self.crypto_device()?;
        let state = if exists {
            Some(device.state(&mut self.store, group).map_err(failure)?)
        } else {
            None
        };
        if state
            .as_ref()
            .is_some_and(|s| envelope.context.epoch > s.epoch)
        {
            // A missing transition is a gap, never evidence that future ciphertext was read.
            return Err(failure(crypto::Error::Resynchronise));
        }
        if state
            .as_ref()
            .is_none_or(|s| s.epoch != envelope.context.epoch || event.sequence <= s.cursor)
        {
            let saved = archive::content(&mut self.store, std::slice::from_ref(event))
                .map_err(|_| Error::Storage)?;
            if !saved.contains_key(&event.event) {
                self.store
                    .write(|tx| {
                        archive::persist_content(tx, event, &MessageContent::Unavailable)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?;
                        Ok(Commit::new((), event.action_digest.as_bytes().to_vec()))
                    })
                    .map_err(|_| Error::Storage)?;
            }
            return Ok(());
        }
        let state = state.ok_or(Error::Input)?;
        let members = self.epoch_members(group, state.epoch)?;
        if !members.iter().any(|m| m.actor == envelope.context.actor) {
            return Err(Error::Input);
        }
        let roster = self.trusted_roster(event.room, &members, false)?;
        let incoming = crypto::IncomingMessage {
            context: &envelope.context,
            ciphertext: &envelope.ciphertext.0,
            action_digest: event.action_digest,
        };
        let delivery = crypto::HomeDelivery {
            previous_sequence: state.cursor,
            sequence: event.sequence,
            event: event.event,
            event_digest: digest(&cache::encode(event).map_err(|_| Error::Input)?),
        };
        device
            .receive_with(
                &mut self.store,
                &incoming,
                &delivery,
                &roster,
                |tx, outcome| archive::persist(tx, event, outcome),
            )
            .map_err(failure)?;
        Ok(())
    }
}

pub(super) fn epoch_in(
    tx: &rusqlite::Transaction<'_>,
    group: Id,
    epoch: u64,
    members: &[domain::Member],
) -> crypto::Result<()> {
    let bytes = cache::encode(&members)?;
    let old: Option<Vec<u8>> = tx
        .query_row(
            "SELECT members FROM client_crypto_epochs WHERE group_id=?1 AND epoch=?2",
            params![group.as_bytes(), epoch],
            |r| r.get(0),
        )
        .optional()?;
    if old.as_ref().is_some_and(|old| old != &bytes) {
        return Err(crypto::Error::Conflict);
    }
    tx.execute(
        "INSERT OR IGNORE INTO client_crypto_epochs VALUES(?1,?2,?3)",
        params![group.as_bytes(), epoch, bytes],
    )?;
    Ok(())
}
