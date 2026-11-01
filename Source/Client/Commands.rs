// SPDX-License-Identifier: Apache-2.0
//! Explicit command effects, exact approval candidates and cancellable queries.
use super::*;
impl Worker {
    pub(super) fn command(&mut self, command: Command) -> Result<()> {
        use Command::*;
        match command {
            Connect => return self.connect(),
            Disconnect => {
                self.offline();
                return Ok(());
            }
            Refresh => return self.refresh(),
            SelectRoom(room) => return self.select(room),
            OpenEvent { room, event } => return self.open_event(room, event),
            LoadMore => return self.pull(self.selected()?),
            Resynchronise => {
                let room = self.selected()?;
                cache::invalidate(&mut self.client.store, room).map_err(|_| Error::Storage)?;
                cache::reset_gap(&mut self.client.store, room).map_err(|_| Error::Storage)?;
                self.caught_up.remove(&room);
                if let Some(v) = &mut self.snapshot.selected {
                    v.gap = None;
                    v.events.clear();
                }
                return self.pull(room);
            }
            SaveDraft {
                room,
                text,
                mentions,
            } => {
                self.client.save_draft_mentions(room, &text, &mentions)?;
                if let Some(v) = &mut self.snapshot.selected
                    && v.summary.room == room
                {
                    v.draft = text;
                    v.draft_mentions = mentions;
                }
                return Ok(());
            }
            SetPreferences(prefs) => {
                cache::save_preferences(&mut self.client.store, "global", &prefs)
                    .map_err(|_| Error::Storage)?;
                self.snapshot.notifications.clear();
                self.snapshot.preferences = prefs;
                return Ok(());
            }
            SetRoomPreferences { room, preferences } => {
                cache::save_preferences(&mut self.client.store, &room.to_string(), &preferences)
                    .map_err(|_| Error::Storage)?;
                self.snapshot.notifications.retain(|n| n.room != room);
                if let Some(v) = &mut self.snapshot.selected
                    && v.summary.room == room
                {
                    v.preferences = preferences;
                }
                return Ok(());
            }
            Search(mut query) => {
                query.cursor = None;
                return self.search(query, false);
            }
            NextSearchPage => {
                let view = self.snapshot.search.as_ref().ok_or(Error::Input)?;
                if !view.has_more {
                    return Ok(());
                }
                return self.search(view.query.clone(), true);
            }
            CancelSearch => {
                if let Some(v) = &mut self.snapshot.search {
                    v.cancelled = true;
                    v.running = false;
                }
                return Ok(());
            }
            CloseSearch => {
                self.snapshot.search = None;
                return Ok(());
            }
            Send {
                room,
                text,
                mentions,
                parent,
                causation,
                action,
                grant,
            } => {
                return self.send(
                    room,
                    messaging::Send {
                        text,
                        mentions,
                        parent,
                        causation,
                    },
                    action,
                    grant,
                );
            }
            MarkRead { room, sequence } => {
                self.effect(
                    Operation::UnreadSet,
                    Target::Room(room),
                    &messaging::Unread { sequence },
                )?;
            }
            CreateRoom { name } => {
                self.effect(
                    Operation::RoomCreate,
                    Target::Service,
                    &conversations::Create {
                        name,
                        confidentiality: RoomConfidentiality::Community,
                    },
                )?;
            }
            Join(room) => {
                self.effect(Operation::RoomJoin, Target::Room(room), &home::Empty {})?;
            }
            Leave(room) => {
                self.effect(Operation::RoomLeave, Target::Room(room), &home::Empty {})?;
            }
            SetTopic { room, topic } => {
                self.effect(
                    Operation::RoomSetTopic,
                    Target::Room(room),
                    &conversations::Topic { topic },
                )?;
            }
            SetNickname(nickname) => {
                self.effect(
                    Operation::AccountSetNickname,
                    Target::Account(self.snapshot.account),
                    &identity::Nickname { nickname },
                )?;
            }
            SetPresence(body) => {
                self.effect(
                    Operation::PresenceSet,
                    Target::Account(self.snapshot.account),
                    &body,
                )?;
            }
            SetFilter {
                subject,
                ignored,
                muted,
            } => {
                for (op, enabled) in [
                    (Operation::ModerationIgnore, ignored),
                    (Operation::ModerationMute, muted),
                ] {
                    if let Some(enabled) = enabled {
                        self.effect(
                            op,
                            Target::Account(self.snapshot.account),
                            &moderation::Filter { subject, enabled },
                        )?;
                    }
                }
            }
            SetRestriction {
                room,
                kind,
                restriction,
            } => {
                let op = match kind {
                    RestrictionKind::Silence => Operation::ModerationSilence,
                    RestrictionKind::Kick => Operation::ModerationKick,
                    RestrictionKind::Ban => Operation::ModerationBan,
                };
                self.effect(op, Target::Room(room), &restriction)?;
            }
            Inspect => return self.inspect(),
            CreateGrant(body) => {
                self.effect(
                    Operation::DelegationCreate,
                    Target::Account(self.snapshot.account),
                    &body,
                )?;
            }
            InspectGrant(reference) => {
                let inspection: delegation::Inspection = self.read(
                    Operation::DelegationInspect,
                    Target::Delegation(reference),
                    &home::Empty {},
                )?;
                self.snapshot.inspection.proposed = inspection
                    .pending
                    .iter()
                    .map(crate::client::json::pending_action)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| Error::Input)?;
                self.snapshot.inspection.grant = Some(inspection);
                return Ok(());
            }
            ChangeGrant { grant, change } => {
                let op = match change {
                    GrantChange::Pause => Operation::DelegationPause,
                    GrantChange::Resume => Operation::DelegationResume,
                    GrantChange::Revoke => Operation::DelegationRevoke,
                };
                self.effect(op, Target::Delegation(grant), &home::Empty {})?;
                self.snapshot.inspection.grant = None;
                self.snapshot.inspection.proposed.clear();
            }
            DecideApproval {
                grant,
                decision,
                approve,
            } => {
                self.effect(
                    if approve {
                        Operation::ApprovalApprove
                    } else {
                        Operation::ApprovalReject
                    },
                    Target::Delegation(grant),
                    &decision,
                )?;
                return self.command(InspectGrant(grant));
            }
            AbandonPending {
                operation_id,
                action_digest,
            } => {
                self.client.abandon(operation_id, action_digest)?;
                self.deliveries()?;
                self.snapshot.status=Some(Status{request_id:self.request,code:"RetryStoppedOutcomeUnknown".into(),detail:"Automatic resubmission stopped. The original outcome remains unknown; this does not retract a message.".into()});
                return Ok(());
            }
            ResolvePending {
                operation_id,
                action_digest,
            } => {
                let response = self.client.resolve_retained(operation_id, action_digest)?;
                match response.outcome {
                    Outcome::Result { body } => {
                        let result: home::ResolveResult =
                            body.deserialized().map_err(|_| Error::Input)?;
                        if result.operation_id != operation_id
                            || result.action_digest != action_digest
                        {
                            return Err(Error::Input);
                        }
                        if let Some(delivery) = self.snapshot.deliveries.iter_mut().find(|d| {
                            d.operation_id == operation_id && d.action_digest == action_digest
                        }) {
                            delivery.outcome = Some(result.outcome);
                        }
                    }
                    Outcome::Refused { code, detail, .. } | Outcome::Rejected { code, detail } => {
                        return Err(Error::Rejected { code, detail });
                    }
                    _ => return Err(Error::Unknown),
                }
                return Ok(());
            }
            SubmitCandidate(id) => {
                let now = self
                    .client
                    .profile
                    .clock
                    .sample()
                    .map_err(|_| Error::Clock)?
                    .upper_ms;
                let bytes = cache::candidate_bytes(&mut self.client.store, id, now)
                    .map_err(|_| Error::Storage)?;
                let key = VerifyingKey::from_bytes(
                    self.client.profile.registration.endpoint_key.as_bytes(),
                )
                .map_err(|_| Error::Configuration)?;
                let candidate = verify_action(&bytes, &key).map_err(|_| Error::Input)?;
                self.operation = Some(candidate.action().operation);
                self.delivery_room = match candidate.action().target {
                    Target::Room(room) => Some(room),
                    _ => None,
                };
                self.remember(candidate.action())?;
                let response = self.client.execute_signed(&bytes)?;
                self.response(response)?;
                self.clear_matching_draft(candidate.action())?;
                cache::complete_candidate(&mut self.client.store, id)
                    .map_err(|_| Error::Storage)?;
            }
        }
        self.refresh()
    }
    pub(super) fn send(
        &mut self,
        room: RoomId,
        message: messaging::Send,
        is_action: bool,
        grant: Option<Box<delegation::Grant>>,
    ) -> Result<()> {
        let messaging::Send {
            text,
            mentions,
            parent,
            causation,
        } = message;
        self.client.save_draft_mentions(room, &text, &mentions)?;
        if let Some(v) = &mut self.snapshot.selected
            && v.summary.room == room
        {
            v.draft = text.clone();
            v.draft_mentions = mentions.clone();
        }
        self.publish();
        if grant
            .as_ref()
            .is_some_and(|g| g.scope.mode == delegation::Mode::Draft)
        {
            self.snapshot.status = Some(Status {
                request_id: self.request,
                code: "DraftOnly".into(),
                detail: "The draft is saved; this grant cannot send.".into(),
            });
            return Ok(());
        }
        // A fresh session resolves old identities before any new effect can be prepared.
        if self.client.session().is_err() {
            return Err(Error::Offline);
        }
        if self.client.pending()?.iter().any(|p| !p.abandoned) {
            self.client.resolve_pending()?;
            if self.client.pending()?.iter().any(|p| !p.abandoned) {
                return Err(Error::Unknown);
            }
        }
        let operation = if parent.is_some() {
            Operation::MessageReply
        } else if is_action {
            Operation::MessageAction
        } else {
            Operation::MessageSend
        };
        let body = Value::serialized(&messaging::Send {
            text,
            mentions,
            parent,
            causation,
        })
        .map_err(|_| Error::Input)?;
        let mut action = self.client.prepare(operation, Target::Room(room), body)?;
        if let Some(g) = &grant {
            if g.home != self.snapshot.home || g.scope.agent != self.client.session()?.ready.acting
            {
                return Err(Error::Input);
            }
            action.actor = Actor::Delegated {
                acting: g.scope.agent.clone(),
                operator: g.operator,
                represented: g.owner,
                represented_security_generation: g.owner_security_generation,
                grant: g.reference,
            };
        }
        if let Some(g) = &grant
            && g.scope.mode == delegation::Mode::Approve
        {
            let approval = Id::random().map_err(|_| Error::Input)?;
            action.approval = Some(approval);
            let bytes = self.client.sign(&action)?;
            let now = self
                .client
                .profile
                .clock
                .sample()
                .map_err(|_| Error::Clock)?
                .upper_ms;
            let expires = g
                .scope
                .expires_ms
                .min(self.client.session()?.ready.window.expires_ms)
                .min(now.saturating_add(300000));
            cache::candidate(&mut self.client.store, approval, &bytes, expires)
                .map_err(|_| Error::Storage)?;
            let mut request = self.client.prepare(
                Operation::ApprovalPrepare,
                Target::Delegation(g.reference),
                Value::serialized(&delegation::Prepare {
                    candidate: Blob(bytes),
                    expires_ms: expires,
                })
                .map_err(|_| Error::Input)?,
            )?;
            request.actor = action.actor;
            self.operation = Some(Operation::ApprovalPrepare);
            self.remember(&request)?;
            let response = self.client.execute(&request)?;
            self.response(response)?;
            self.snapshot.status = Some(Status {
                request_id: self.request,
                code: "ApprovalPending".into(),
                detail: format!("Exact candidate {approval} is awaiting its owner's decision."),
            });
            return Ok(());
        }
        self.operation = Some(operation);
        self.delivery_room = Some(room);
        self.remember(&action)?;
        let response = self.client.execute(&action)?;
        self.response(response)?;
        self.clear_matching_draft(&action)?;
        self.refresh()
    }
    pub(super) fn search(&mut self, query: messaging::Search, append: bool) -> Result<()> {
        let room = self.selected()?;
        let events = if append {
            self.snapshot
                .search
                .as_ref()
                .map(|v| v.events.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        self.snapshot.search = Some(SearchView {
            room,
            query: query.clone(),
            events,
            has_more: false,
            running: true,
            cancelled: false,
        });
        if self.shared.cancel.load(Ordering::Acquire) {
            if let Some(view) = &mut self.snapshot.search {
                view.cancelled = true;
                view.running = false;
            }
            return Ok(());
        }
        self.publish();
        let action = self.client.prepare(
            Operation::SearchQuery,
            Target::Room(room),
            Value::serialized(&query).map_err(|_| Error::Input)?,
        )?;
        let response = self
            .client
            .search_cancellable(&action, &self.shared.cancel)?;
        let view = self.snapshot.search.as_mut().ok_or(Error::Input)?;
        view.running = false;
        if self.shared.cancel.load(Ordering::Acquire) {
            view.cancelled = true;
            return Ok(());
        }
        let page: messaging::PageResult = match response.outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input)?,
            Outcome::Refused { code, detail, .. } | Outcome::Rejected { code, detail } => {
                return Err(Error::Rejected { code, detail });
            }
            _ => return Err(Error::Unknown),
        };
        view.events.extend(page.events);
        if view.events.len() > 256 {
            view.events.drain(..view.events.len() - 256);
        }
        view.query.cursor = Some(page.cursor);
        view.has_more = page.has_more;
        Ok(())
    }
}
