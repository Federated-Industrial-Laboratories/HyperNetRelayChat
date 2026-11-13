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
            SelectService(agreement) => {
                self.offline();
                self.client.select_service(agreement)?;
                self.snapshot.home = self.client.profile.active_server().home;
                self.snapshot.services = self.client.profile.service_choices();
                self.snapshot.rooms = cache::rooms(&mut self.client.store)
                    .map_err(|_| Error::Storage)?
                    .into_iter()
                    .filter(|room| room.room.home == self.snapshot.home)
                    .collect();
                self.snapshot.selected = None;
                self.snapshot.search = None;
                self.snapshot.inspection = Inspection::default();
                self.snapshot.inspection.stale = true;
                self.snapshot.inspection.filters_stale = true;
                self.snapshot.inspection.filters =
                    cache::filters(&mut self.client.store, self.snapshot.home)
                        .map_err(|_| Error::Storage)?;
                self.snapshot.notifications.clear();
                self.snapshot.deliveries.clear();
                self.snapshot.nickname.clear();
                self.snapshot.motd.clear();
                return self.connect();
            }
            Refresh => return self.refresh(),
            SelectRoom(room) => return self.select(room),
            OpenEvent { room, event } => return self.open_event(room, event),
            LoadMore => return self.pull(self.selected()?),
            Resynchronise => {
                let room = self.selected()?;
                return self.update_view(|worker| {
                    worker.clear_room_presentation(room, None);
                    worker.client.resynchronise_history(room)?;
                    worker.pull(room)
                });
            }
            SaveDraft {
                room,
                text,
                mentions,
            } => {
                self.client.save_draft_mentions(room, &text, &mentions)?;
                self.draft_saved(room);
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
            CreatePrivateGroup { name } => {
                self.effect(
                    Operation::RoomCreate,
                    Target::Service,
                    &conversations::Create {
                        name,
                        confidentiality: RoomConfidentiality::PrivateGroup,
                    },
                )?;
            }
            CreateDirect { recipient } => {
                self.effect(
                    Operation::DirectCreate,
                    Target::Service,
                    &crate::confidential::Direct { recipient },
                )?;
            }
            Invite { room, account } => {
                self.effect(
                    Operation::RoomInvite,
                    Target::Room(room),
                    &crate::confidential::Invite { account },
                )?;
            }
            CryptoEnrol => {
                self.operation = Some(Operation::CryptoEnrolEndpoint);
                let response = self.client.crypto_enrol()?;
                self.response(response)?;
            }
            CryptoInspect { room, grant } => {
                return self.update_view(|worker| {
                    let view = worker.client.crypto_inspect(room, grant.as_deref())?;
                    let selected = worker
                        .snapshot
                        .selected
                        .as_mut()
                        .filter(|v| v.summary.room == room)
                        .ok_or(Error::Input)?;
                    selected.crypto = Some(view);
                    Ok(())
                });
            }
            CryptoPublish { room, grant } => {
                self.operation = Some(Operation::CryptoPublishKeyPackage);
                let response = self.client.crypto_publish(room, grant.as_deref())?;
                self.response(response)?;
            }
            CryptoInitialise { room, recover } => {
                self.operation = Some(if recover {
                    Operation::CryptoRecover
                } else {
                    Operation::CryptoPropose
                });
                let response = self.client.crypto_initialise(room, recover)?;
                self.response(response)?;
            }
            CryptoCommit {
                room,
                additions,
                removals,
            } => {
                self.operation = Some(Operation::CryptoCommit);
                let response = self
                    .client
                    .crypto_commit(room, &additions, &removals, None)?;
                self.response(response)?;
            }
            CryptoSync { room, grant } => {
                return self.update_view(|worker| {
                    let result = worker.client.crypto_sync(room, grant.as_deref());
                    if result.is_err() {
                        worker.reconcile_history_gap(room)?;
                    }
                    let view = result?;
                    let selected = worker
                        .snapshot
                        .selected
                        .as_mut()
                        .filter(|v| v.summary.room == room)
                        .ok_or(Error::Input)?;
                    selected.crypto = Some(view);
                    Ok(())
                });
            }
            TrustContact {
                account,
                anchor_digest,
                legacy,
            } => {
                self.client.trust_contact(account, anchor_digest, legacy)?;
                return Ok(());
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
            InitializeNickname(nickname) => return self.initialize_nickname(&nickname),
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
            ConsentAgent(request) => {
                if request.successor && !self.client.pending()?.is_empty() {
                    return Err(Error::Input);
                }
                let body = self.effect(
                    Operation::AgentConsent,
                    Target::Account(self.snapshot.account),
                    &home::admission::Consent { request },
                )?;
                self.snapshot.inspection.admission_consent =
                    Some(body.deserialized().map_err(|_| Error::Input)?);
                return Ok(());
            }
            AgentAccess(body) => {
                self.effect(
                    Operation::AgentSetAccess,
                    Target::Account(self.snapshot.account),
                    &body,
                )?;
                return self.inspect();
            }
            CreateGrant(body) => {
                self.effect(
                    Operation::DelegationCreate,
                    Target::Account(self.snapshot.account),
                    &body,
                )?;
            }
            InspectGrant(reference) => {
                return self.update_view(|worker| {
                    let preview = worker.client.inspect_grant(reference)?;
                    worker.snapshot.inspection.proposed = preview.candidates;
                    worker.snapshot.inspection.proposed_content = preview.content;
                    worker.snapshot.inspection.grant = Some(preview.inspection);
                    Ok(())
                });
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
                self.operation = Some(if approve {
                    Operation::ApprovalApprove
                } else {
                    Operation::ApprovalReject
                });
                let response = self.client.decide_approval(grant, &decision, approve)?;
                self.response(response)?;
                let view = self.command(InspectGrant(grant));
                self.finish_view(view);
                return Ok(());
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
                    outcome => return Err(Error::from_outcome(outcome)),
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
                let response = self.client.submit_candidate(&bytes)?;
                self.response(response)?;
                self.clear_matching_draft(candidate.action())?;
                cache::complete_candidate(&mut self.client.store, id)
                    .map_err(|_| Error::Storage)?;
            }
        }
        // These mutations can change membership, policy or inspected metadata.
        self.stale();
        let view = self.refresh();
        self.finish_view(view);
        Ok(())
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
        let owns_draft = self.preserve_send_draft(room, &text, &mentions)?;
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
        if self
            .client
            .pending()?
            .iter()
            .any(|p| !p.abandoned && !p.held)
        {
            self.client.resolve_pending()?;
            if self
                .client
                .pending()?
                .iter()
                .any(|p| !p.abandoned && !p.held)
            {
                return Err(Error::Unknown);
            }
        }
        let approval = if grant
            .as_ref()
            .is_some_and(|g| g.scope.mode == delegation::Mode::Approve)
        {
            Some(Id::random().map_err(|_| Error::Input)?)
        } else {
            None
        };
        let message = messaging::Send {
            text,
            mentions,
            parent,
            causation,
        };
        let prepared = self.client.prepare_controller_send_with(
            room,
            &message,
            grant.as_deref(),
            is_action,
            approval,
            |tx, action| {
                if owns_draft {
                    super::super::outbox::bind_draft_transaction(tx, action.action(), &message)?;
                }
                Ok(())
            },
        )?;
        let action = prepared.message.action.clone();
        let operation = action.operation;
        if let Some(g) = &grant
            && g.scope.mode == delegation::Mode::Approve
        {
            let approval = action.approval.ok_or(Error::Input)?;
            let bytes = prepared.message.signed;
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
        let response = self.client.execute_controller_send(prepared)?;
        let direct_commit = grant.is_none()
            && matches!(
                response.response.outcome,
                Outcome::Committed { event: Some(_), .. }
            );
        self.response_observed(response.response, response.exchange_ns)?;
        self.clear_matching_draft(&action)?;
        self.refresh_sent_room(room, direct_commit);
        Ok(())
    }
    pub(super) fn search(&mut self, query: messaging::Search, append: bool) -> Result<()> {
        self.update_view(|worker| worker.search_current(query, append))
    }
    fn search_current(&mut self, query: messaging::Search, append: bool) -> Result<()> {
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
            content: Default::default(),
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
        let result = self
            .client
            .search_messages(room, &query, None, &self.shared.cancel);
        let view = self.snapshot.search.as_mut().ok_or(Error::Input)?;
        view.running = false;
        if self.shared.cancel.load(Ordering::Acquire) {
            view.cancelled = true;
            return Ok(());
        }
        let page = result?;
        view.content.extend(page.content);
        view.events.extend(page.events.into_iter().filter(|event| {
            !cache::filtered(&self.snapshot.inspection.filters, &event.actor, false)
        }));
        if view.events.len() > 256 {
            view.events.drain(..view.events.len() - 256);
        }
        view.content
            .retain(|id, _| view.events.iter().any(|event| event.event == *id));
        view.query.cursor = Some(page.cursor);
        view.has_more = page.has_more;
        Ok(())
    }
}
