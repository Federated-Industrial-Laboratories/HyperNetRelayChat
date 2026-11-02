// SPDX-License-Identifier: Apache-2.0
//! Authenticated encrypted-room commands share the existing client, writer and exact-byte outbox.
use super::{
    Client, CryptoView, Error, Result, archive, cache, outbox, trust::TrustState,
    trust_store::trust_required,
};
use crate::{
    confidential as domain, conversations, crypto, delegation, home, messaging, protocol::*,
};
use rusqlite::OptionalExtension;
use std::{collections::BTreeSet, time::Duration};
#[derive(Clone, Debug)]
pub struct PreparedSend {
    pub action: Action,
    pub signed: Vec<u8>,
    pub encrypted: bool,
}
pub(super) fn failure(error: crypto::Error) -> Error {
    let (code, detail) = match error {
        crypto::Error::Storage(_) | crypto::Error::Database => {
            (ErrorCode::Unavailable, "CryptoStorageUnavailable")
        }
        crypto::Error::Suspended => (ErrorCode::Unavailable, "EncryptedRoomFrozen"),
        crypto::Error::Resynchronise => (
            ErrorCode::ResynchronisationRequired,
            "EncryptedResynchronisationRequired",
        ),
        crypto::Error::Conflict => (ErrorCode::Conflict, "EncryptedOperationPending"),
        crypto::Error::Limit => (ErrorCode::Overloaded, "EncryptedBudgetExceeded"),
        crypto::Error::Binding | crypto::Error::Verification => {
            (ErrorCode::Denied, "EncryptedIdentityVerificationFailed")
        }
        crypto::Error::Invalid => (ErrorCode::InvalidInput, "InvalidEncryptedContent"),
    };
    Error::Rejected {
        code,
        detail: detail.into(),
    }
}
impl Client {
    pub(super) fn validate_message_mode(&mut self, action: &Action) -> Result<()> {
        if !matches!(
            action.operation,
            Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
        ) {
            return Ok(());
        }
        let mut query = self.prepare(
            Operation::RoomInspect,
            action.target.clone(),
            Value::serialized(&home::Empty {}).map_err(|_| Error::Input)?,
        )?;
        query.actor = action.actor.clone();
        let response = self.execute(&query)?;
        let inspection: conversations::Inspection = match response.outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input)?,
            outcome => return Err(Error::from_outcome(outcome)),
        };
        let encrypted = crypto::EncryptionContext::from_action(action).is_ok();
        if encrypted != (inspection.confidentiality != RoomConfidentiality::Community) {
            return Err(Error::Rejected {
                code: ErrorCode::InvalidInput,
                detail: "MessageEncryptionModeMismatch".into(),
            });
        }
        if encrypted {
            let saved: Option<(Vec<u8>, Vec<u8>)> = self
                .store
                .read(Duration::from_secs(1), |db| {
                    db.query_row(
                        "SELECT context,ciphertext FROM crypto_outbox WHERE operation=?1",
                        [cache::encode(&action.operation_id)?],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                })
                .map_err(|_| Error::Storage)?;
            let (context, ciphertext) = saved.ok_or(Error::Input)?;
            let context: crypto::EncryptionContext =
                cache::decode(&context).map_err(|_| Error::Input)?;
            if action_bytes(&context.action(ciphertext).map_err(failure)?)
                .map_err(|_| Error::Input)?
                != action_bytes(action).map_err(|_| Error::Input)?
            {
                return Err(Error::Input);
            }
        }
        Ok(())
    }
    pub(super) fn effects_ready(&mut self) -> Result<()> {
        if self.pending()?.iter().any(|p| !p.abandoned && !p.held) {
            self.resolve_pending()?;
            if self.pending()?.iter().any(|p| !p.abandoned && !p.held) {
                return Err(Error::Unknown);
            }
        }
        Ok(())
    }
    fn membership_effects_ready(&mut self, room: RoomId) -> Result<()> {
        self.effects_ready()?;
        if self.pending()?.iter().any(|pending| {
            pending.abandoned
                && pending.action.action().target == Target::Room(room)
                && matches!(
                    pending.action.action().operation,
                    Operation::CryptoCommit | Operation::CryptoPropose | Operation::CryptoRecover
                )
        }) {
            return Err(Error::Unknown);
        }
        Ok(())
    }

    pub fn prepare_as<T: serde::Serialize>(
        &self,
        operation: Operation,
        target: Target,
        body: &T,
        grant: Option<&delegation::Grant>,
    ) -> Result<Action> {
        let mut action = self.prepare(
            operation,
            target,
            Value::serialized(body).map_err(|_| Error::Input)?,
        )?;
        if let Some(grant) = grant {
            if grant.home != self.profile.active_server().home
                || grant.scope.agent != self.session()?.ready.acting
            {
                return Err(Error::Input);
            }
            action.actor = Actor::Delegated {
                acting: grant.scope.agent.clone(),
                operator: grant.operator,
                represented: grant.owner,
                represented_security_generation: grant.owner_security_generation,
                grant: grant.reference,
            };
        }
        Ok(action)
    }
    pub fn read_as<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &mut self,
        operation: Operation,
        target: Target,
        body: &B,
        grant: Option<&delegation::Grant>,
    ) -> Result<T> {
        let action = self.prepare_as(operation, target, body, grant)?;
        if !home::is_read_operation(operation) {
            return Err(Error::Input);
        }
        match self.execute(&action)?.outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input),
            outcome => {
                let error = Error::from_outcome(outcome);
                if matches!(
                    operation,
                    Operation::RoomInspect | Operation::CryptoInspect | Operation::CryptoHistory
                ) && let Target::Room(room) = action.target
                {
                    cache::inspection_failed(&mut self.store, room, &error)
                        .map_err(|_| Error::Storage)?;
                }
                Err(error)
            }
        }
    }
    pub fn crypto_enrol(&mut self) -> Result<Response> {
        self.effects_ready()?;
        let actor = self.session()?.ready.acting.clone();
        let exists = self
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM crypto_devices WHERE endpoint=?1)",
                    [actor.endpoint.as_bytes()],
                    |r| r.get::<_, bool>(0),
                )
            })
            .map_err(|_| Error::Storage)?;
        let device = if exists {
            crypto::Device::open(&mut self.store, &actor)
        } else {
            crypto::Device::provision(&mut self.store, actor)
        }
        .map_err(failure)?;
        let action = self.prepare_as(
            Operation::CryptoEnrolEndpoint,
            Target::Account(device.actor.account),
            &domain::EnrolKey {
                mls_key: device.mls_key,
            },
            None,
        )?;
        let bytes = self.sign(&action)?;
        let response = self.execute_signed(&bytes)?;
        if matches!(response.outcome, Outcome::Committed { .. }) {
            self.store.write(|tx|{tx.execute("INSERT INTO client_mls_registration VALUES(?1,?2) ON CONFLICT(endpoint) DO NOTHING",rusqlite::params![device.actor.endpoint.as_bytes(),bytes])?;Ok(crate::storage::Commit::new((),digest(&bytes).as_bytes().to_vec()))}).map_err(|_|Error::Storage)?;
        }
        Ok(response)
    }
    pub(super) fn crypto_device(&mut self) -> Result<crypto::Device> {
        let actor = self.session()?.ready.acting.clone();
        crypto::Device::open(&mut self.store, &actor).map_err(failure)
    }
    pub fn crypto_inspect(
        &mut self,
        room: RoomId,
        grant: Option<&delegation::Grant>,
    ) -> Result<CryptoView> {
        let remote: domain::Inspection = self.read_as(
            Operation::CryptoInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        if remote.room != room {
            return Err(Error::Input);
        }
        let mut accounts = BTreeSet::new();
        for member in remote
            .members
            .iter()
            .chain(remote.packages.iter().map(|p| &p.member))
        {
            accounts.insert(member.actor.acting().account);
            accounts.insert(member.actor.represented());
            if let Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } =
                member.actor
            {
                accounts.insert(operator);
            }
        }
        accounts.insert(self.profile.registration.account);
        let mut contacts = Vec::new();
        // Human operator consent is inspected first so an untrusted operator can be presented rather than hidden by agent verification.
        let mut ordered = accounts.into_iter().collect::<Vec<_>>();
        if let AccountClass::Agent { operator } = self.profile.registration.classification {
            ordered.retain(|a| *a != operator);
            ordered.insert(0, operator);
        }
        let historical = self.room_contacts(room)?;
        let mut prospective = ordered.iter().copied().collect::<BTreeSet<_>>();
        prospective.extend(historical.iter().map(|c| c.account));
        if prospective.len() > 256 {
            return Err(Error::Rejected {
                code: ErrorCode::Overloaded,
                detail: "ContactCapacityExceeded".into(),
            });
        }
        for account in ordered {
            contacts.push(self.contact_trust(room, account, grant)?);
        }
        for contact in historical {
            if !contacts.iter().any(|c| c.account == contact.account) {
                contacts.push(contact);
            }
        }
        let local = if let Some(group) = remote.group {
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
            if exists {
                let device = self.crypto_device()?;
                Some(device.state(&mut self.store, group).map_err(failure)?)
            } else {
                None
            }
        } else {
            None
        };
        let view = CryptoView {
            remote,
            local,
            contacts,
            future_only: true,
        };
        archive::save_view(&mut self.store, &view).map_err(|_| Error::Storage)?;
        Ok(view)
    }
    pub fn crypto_publish(
        &mut self,
        room: RoomId,
        grant: Option<&delegation::Grant>,
    ) -> Result<Response> {
        self.effects_ready()?;
        let _: domain::Inspection = self.read_as(
            Operation::CryptoInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        let device = self.crypto_device()?;
        // Each explicit publication creates a fresh one-use package. Exact network retries
        // are resolved from the ordinary outbox before another publication is prepared.
        let package = device
            .publish_key_package(&mut self.store, room)
            .map_err(failure)?;
        let expires = self
            .profile
            .clock
            .sample()
            .map_err(|_| Error::Clock)?
            .lower_ms
            + 86_400_000;
        let action = self.prepare_as(
            Operation::CryptoPublishKeyPackage,
            Target::Room(room),
            &domain::PublishPackage {
                package: Blob(package),
                expires_ms: expires,
            },
            grant,
        )?;
        self.execute(&action)
    }
    pub fn crypto_initialise(&mut self, room: RoomId, recover: bool) -> Result<Response> {
        self.membership_effects_ready(room)?;
        let view = self.crypto_inspect(room, None)?;
        require_trust(&view)?;
        if !recover && view.remote.group.is_some() {
            return Err(Error::Input);
        }
        let device = self.crypto_device()?;
        let own = self.own_member(room)?;
        let roster = self.trusted_roster(room, std::slice::from_ref(&own), true)?;
        let group = Id::random().map_err(|_| Error::Input)?;
        let mut action = self.prepare_as(
            if recover {
                Operation::CryptoRecover
            } else {
                Operation::CryptoPropose
            },
            Target::Room(room),
            &domain::Initialise {
                group,
                group_info: Blob(Vec::new()),
            },
            None,
        )?;
        self.set_room_revision(&mut action, room, None)?;
        let window = self.session()?.ready.window.clone();
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        let key = &self.key;
        let mut signed = None;
        device
            .create_group_with(
                &mut self.store,
                group,
                &roster,
                view.remote.sequence,
                |tx, info| {
                    action.body = Value::serialized(&domain::Initialise {
                        group,
                        group_info: Blob(info.to_vec()),
                    })
                    .map_err(|_| crypto::Error::Invalid)?;
                    signed = Some(persist_membership_action(tx, &action, key, &window, now)?);
                    super::encrypted_history::epoch_in(tx, group, 0, &[own])
                },
            )
            .map_err(failure)?;
        let response = self.execute_signed(&signed.ok_or(Error::Storage)?)?;
        if matches!(response.outcome, Outcome::Committed { .. }) {
            self.crypto_sync(room, None)?;
        }
        Ok(response)
    }
    pub fn crypto_commit(
        &mut self,
        room: RoomId,
        additions: &[Id],
        removals: &[Id],
        grant: Option<&delegation::Grant>,
    ) -> Result<Response> {
        self.membership_effects_ready(room)?;
        if additions.len() > 64
            || removals.len() > 64
            || (!additions.is_empty() && !removals.is_empty())
        {
            return Err(Error::Input);
        }
        self.crypto_sync(room, grant)?;
        let view = self.crypto_inspect(room, grant)?;
        require_trust(&view)?;
        let group = view.remote.group.ok_or(Error::Input)?;
        let current = self.trusted_roster(room, &view.remote.members, false)?;
        let mut next = view.remote.members.clone();
        let mut packages = Vec::new();
        for id in additions {
            let package = view
                .remote
                .packages
                .iter()
                .find(|p| p.digest == *id)
                .ok_or(Error::Input)?;
            next.push(package.member.clone());
            packages.push(package.package.0.clone());
        }
        next.retain(|m| !removals.contains(&m.credential.actor.endpoint));
        if view
            .remote
            .required_removals
            .iter()
            .any(|id| next.iter().any(|m| m.credential.actor.endpoint == *id))
        {
            return Err(Error::Rejected {
                code: ErrorCode::Denied,
                detail: "RequiredEndpointRemoval".into(),
            });
        }
        let next = self.trusted_roster(room, &next, true)?;
        let device = self.crypto_device()?;
        let change = if !additions.is_empty() {
            crypto::Change::Add(&packages)
        } else if !removals.is_empty() {
            crypto::Change::Remove(removals)
        } else {
            crypto::Change::Update
        };
        let mut action = self.prepare_as(
            Operation::CryptoCommit,
            Target::Room(room),
            &domain::CommitEpoch {
                group,
                epoch: view.remote.epoch,
                commit: Blob(Vec::new()),
                additions: additions.to_vec(),
                removals: removals.to_vec(),
            },
            grant,
        )?;
        // Finish all current reads and action/window preparation before the MLS
        // write. A refused inspection must not strand an unbound local candidate.
        self.set_room_revision(&mut action, room, grant)?;
        let window = self.session()?.ready.window.clone();
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        let key = &self.key;
        let mut signed = None;
        device
            .prepare_transition_with(
                &mut self.store,
                crypto::TransitionPreparation {
                    group,
                    epoch: view.remote.epoch,
                    current: &current,
                    next: &next,
                    change,
                },
                |tx, pending| {
                    action.body = Value::serialized(&domain::CommitEpoch {
                        group,
                        epoch: pending.epoch,
                        commit: Blob(pending.commit.clone()),
                        additions: additions.to_vec(),
                        removals: removals.to_vec(),
                    })
                    .map_err(|_| crypto::Error::Invalid)?;
                    signed = Some(persist_membership_action(tx, &action, key, &window, now)?);
                    crypto::bind_transition_in(
                        tx,
                        pending,
                        action.operation_id,
                        action_digest(&action)?,
                    )?;
                    Ok(())
                },
            )
            .map_err(failure)?;
        // Terminal rejection cleanup is joined to outbox recording, including
        // outcomes learned through exact resolution after a disconnect.
        let response = self.execute_signed(&signed.ok_or(Error::Storage)?)?;
        if matches!(response.outcome, Outcome::Committed { .. }) {
            self.crypto_sync(room, grant)?;
        }
        Ok(response)
    }
    fn set_room_revision(
        &mut self,
        action: &mut Action,
        room: RoomId,
        grant: Option<&delegation::Grant>,
    ) -> Result<()> {
        let inspection: conversations::Inspection = self.read_as(
            Operation::RoomInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        action
            .expected
            .insert(Revision::Room, inspection.room_revision);
        Ok(())
    }
    pub fn prepare_send(
        &mut self,
        room: RoomId,
        message: &messaging::Send,
        grant: Option<&delegation::Grant>,
        is_action: bool,
        approval: Option<Id>,
    ) -> Result<PreparedSend> {
        self.prepare_send_with(room, message, grant, is_action, approval, |_, _| Ok(()))
    }
    /// The finalizer joins exact outbox persistence (and the MLS ratchet) without network I/O.
    pub(crate) fn prepare_send_with(
        &mut self,
        room: RoomId,
        message: &messaging::Send,
        grant: Option<&delegation::Grant>,
        is_action: bool,
        approval: Option<Id>,
        finalize: impl FnOnce(&rusqlite::Transaction<'_>, &VerifiedAction) -> rusqlite::Result<()>,
    ) -> Result<PreparedSend> {
        self.save_draft_mentions(room, &message.text, &message.mentions)?;
        self.prepare_preserved_send_with(room, message, grant, is_action, approval, |tx, action| {
            outbox::bind_draft_transaction(tx, action.action(), message)?;
            finalize(tx, action)
        })
    }
    /// The controller already applied command/draft ordering. Preserve that decision
    /// while atomically preparing the exact outbox bytes and any MLS ratchet change.
    pub(super) fn prepare_preserved_send_with(
        &mut self,
        room: RoomId,
        message: &messaging::Send,
        grant: Option<&delegation::Grant>,
        is_action: bool,
        approval: Option<Id>,
        finalize: impl FnOnce(&rusqlite::Transaction<'_>, &VerifiedAction) -> rusqlite::Result<()>,
    ) -> Result<PreparedSend> {
        self.effects_ready()?;
        let inspection: conversations::Inspection = self.read_as(
            Operation::RoomInspect,
            Target::Room(room),
            &home::Empty {},
            grant,
        )?;
        let operation = if message.parent.is_some() {
            Operation::MessageReply
        } else if is_action {
            Operation::MessageAction
        } else {
            Operation::MessageSend
        };
        let mut action = self.prepare_as(operation, Target::Room(room), message, grant)?;
        action.approval = approval;
        if inspection.confidentiality == RoomConfidentiality::Community {
            let signed = self.sign(&action)?;
            let verified =
                verify_action(&signed, &self.key.verifying_key()).map_err(|_| Error::Input)?;
            let window = self.session()?.ready.window.clone();
            let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
            self.store
                .write(|tx| {
                    if approval.is_some() {
                        outbox::prepare_candidate_transaction(tx, &verified, &window, now)?;
                    } else {
                        outbox::prepare_transaction(tx, &verified, &window, now)?;
                    }
                    finalize(tx, &verified)?;
                    Ok(crate::storage::Commit::new(
                        (),
                        verified.digest().as_bytes().to_vec(),
                    ))
                })
                .map_err(|_| Error::Storage)?;
            return Ok(PreparedSend {
                action,
                signed,
                encrypted: false,
            });
        }
        self.crypto_sync(room, grant)?;
        let view = self.crypto_inspect(room, grant)?;
        require_trust(&view)?;
        if view.remote.send_barrier || view.remote.frozen {
            return Err(Error::Rejected {
                code: ErrorCode::Unavailable,
                detail: "EncryptedRoomBarrier".into(),
            });
        }
        let group = view.remote.group.ok_or(Error::Input)?;
        let current = self.trusted_roster(room, &view.remote.members, true)?;
        if !view.remote.members.iter().any(|m| m.actor == action.actor) {
            return Err(Error::Rejected {
                code: ErrorCode::Denied,
                detail: "EncryptedParticipationMismatch".into(),
            });
        }
        for mention in &message.mentions {
            let member = inspection
                .members
                .iter()
                .find(|m| m.account == mention.account)
                .ok_or(Error::Input)?;
            if message
                .text
                .get(mention.start as usize..mention.end as usize)
                != Some(format!("@{}", member.nickname).as_str())
            {
                return Err(Error::Input);
            }
        }
        action
            .expected
            .insert(Revision::Room, inspection.room_revision);
        let context = crypto::EncryptionContext {
            home: action.home,
            room,
            operation_id: action.operation_id,
            actor: action.actor.clone(),
            operation,
            expected: action.expected.clone(),
            approval,
            agreement: action.agreement,
            group,
            epoch: view.remote.epoch,
            parent: message.parent,
            causation: message.causation,
        };
        let window = self.session()?.ready.window.clone();
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        let key = &self.key;
        let device =
            crypto::Device::open(&mut self.store, action.actor.acting()).map_err(failure)?;
        let prepared = device
            .prepare_message(
                &mut self.store,
                &context,
                &current,
                crypto::ApplicationMessage {
                    text: message.text.clone(),
                    mentions: message.mentions.clone(),
                },
                |tx, action| {
                    let signed = sign_action(&action, key)?;
                    let verified = verify_action(&signed, &key.verifying_key())?;
                    if approval.is_some() {
                        outbox::prepare_candidate_transaction(tx, &verified, &window, now)?;
                    } else {
                        outbox::prepare_transaction(tx, &verified, &window, now)?;
                    }
                    finalize(tx, &verified)?;
                    Ok(signed)
                },
            )
            .map_err(failure)?;
        Ok(PreparedSend {
            action: context.action(prepared.ciphertext).map_err(failure)?,
            signed: prepared.signed_action,
            encrypted: true,
        })
    }
    pub fn send_message(
        &mut self,
        room: RoomId,
        message: &messaging::Send,
        grant: Option<&delegation::Grant>,
        is_action: bool,
    ) -> Result<Response> {
        if grant.is_some_and(|g| g.scope.mode != delegation::Mode::Autonomous) {
            return Err(Error::Rejected {
                code: ErrorCode::Denied,
                detail: "ExplicitAgentApprovalRequired".into(),
            });
        }
        let prepared = self.prepare_send(room, message, grant, is_action, None)?;
        self.execute_signed(&prepared.signed)
    }
}
fn persist_membership_action(
    tx: &rusqlite::Transaction<'_>,
    action: &Action,
    key: &SigningKey,
    window: &RetryWindow,
    now: crate::clock::TimeBounds,
) -> crypto::Result<Vec<u8>> {
    let bytes = sign_action(action, key)?;
    let verified = verify_action(&bytes, &key.verifying_key())?;
    outbox::prepare_transaction(tx, &verified, window, now)?;
    Ok(bytes)
}
pub(super) fn require_trust(view: &CryptoView) -> Result<()> {
    let mut required = BTreeSet::new();
    for member in view
        .remote
        .members
        .iter()
        .chain(view.remote.packages.iter().map(|p| &p.member))
    {
        required.insert(member.actor.acting().account);
        required.insert(member.actor.represented());
        if let Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } =
            member.actor
        {
            required.insert(operator);
        }
    }
    if required.iter().any(|account| {
        !view
            .contacts
            .iter()
            .any(|c| c.account == *account && c.state == TrustState::Trusted)
    }) {
        Err(trust_required())
    } else {
        Ok(())
    }
}
