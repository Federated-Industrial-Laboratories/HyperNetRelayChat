// SPDX-License-Identifier: Apache-2.0
//! Durable ciphertext outbox, receive cursors, and one-pass exact approvals.
use super::*;
use crate::protocol::OperationId;
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreparedMessage {
    pub context: EncryptionContext,
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "bytes")]
    pub signed_action: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejection {
    InvalidContent,
    InvalidCryptography,
    ApprovalRejected,
    ResynchronisationRequired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryOutcome {
    Message(String),
    Rejected(Rejection),
}
#[derive(Clone, Debug)]
pub struct IncomingMessage<'a> {
    pub context: &'a EncryptionContext,
    pub ciphertext: &'a [u8],
    pub action_digest: Id,
}
impl IncomingMessage<'_> {
    fn binding(&self) -> Result<Id> {
        Ok(digest(&encode(&(
            self.context,
            digest(self.ciphertext),
            self.action_digest,
        ))?))
    }
    fn validate(&self) -> Result<()> {
        self.context.aad()?;
        if self.ciphertext.is_empty()
            || self.ciphertext.len() > crate::protocol::ORDINARY_FRAME_BYTES
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
/// The caller has verified the home event, ordering and current HRC access.
#[derive(Clone, Debug)]
pub struct HomeDelivery {
    pub previous_sequence: u64,
    pub sequence: u64,
    pub event: Id,
    pub event_digest: Id,
}

impl Device {
    /// The finalizer signs the supplied exact Action; it must perform no I/O or effects.
    pub fn prepare_message(
        &self,
        store: &mut Store,
        context: &EncryptionContext,
        roster: &ApprovedRoster,
        text: &str,
        finalize: impl FnOnce(crate::protocol::Action) -> Result<Vec<u8>>,
    ) -> Result<PreparedMessage> {
        self.check(roster)?;
        if context.actor.acting() != &self.actor || context.room != roster.room() {
            return Err(Error::Binding);
        }
        crate::text::message(text).map_err(|_| Error::Invalid)?;
        let aad = context.aad()?;
        let operation = encode(&context.operation_id)?;
        let input = digest(&encode(&(context, text))?);
        atomic(store, "encrypt", input.as_bytes(), |tx| {
            retention::window_open(tx, context.operation_id.window)?;
            let old: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT input_digest,ciphertext,action FROM crypto_outbox WHERE operation=?1",
                    [&operation],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((saved, ciphertext, signed_action)) = old {
                if saved != input.as_bytes().as_slice() {
                    return Err(Error::Conflict);
                }
                let value = PreparedMessage {
                    context: context.clone(),
                    ciphertext,
                    signed_action,
                };
                return Ok((value.clone(), encode(&value)?));
            }
            let (room, _, frozen) = metadata(tx, context.group)?;
            if frozen {
                return Err(Error::Suspended);
            }
            if room != context.room {
                return Err(Error::Binding);
            }
            budget(tx, "crypto_outbox")?;
            let (sends, gaps): (u64, u32) = tx.query_row(
                "SELECT sends,gaps FROM crypto_groups WHERE id=?1",
                [context.group.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if sends >= MAX_MESSAGES_PER_EPOCH || gaps >= MAX_FORWARD_DISTANCE {
                return Err(Error::Resynchronise);
            }
            let pending: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM crypto_outbox WHERE group_id=?1 AND state='pending')",
                [context.group.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if pending {
                return Err(Error::Conflict);
            }
            let provider = Provider::new(tx);
            let mut mls = self.group(&provider, context.group)?;
            if mls.epoch().as_u64() != context.epoch {
                return Err(Error::Conflict);
            }
            roster.check(mls.members())?;
            let keys = signer(&provider, self.mls_key)?;
            mls.set_aad(aad.clone());
            let ciphertext = tls(&mls
                .create_message(&provider, &keys, text.as_bytes())
                .map_err(|_| Error::Verification)?)?;
            let signed_action = finalize(context.action(ciphertext.clone())?)?;
            if signed_action.is_empty()
                || signed_action.len() > crate::protocol::ORDINARY_FRAME_BYTES
            {
                return Err(Error::Limit);
            }
            tx.execute("INSERT INTO crypto_outbox(operation,group_id,epoch,input_digest,context,ciphertext,action,plaintext,state,window_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9)",rusqlite::params![operation,context.group.as_bytes().as_slice(),context.epoch,input.as_bytes().as_slice(),encode(context)?,ciphertext,signed_action,text,context.operation_id.window.as_bytes().as_slice()])?;
            tx.execute(
                "UPDATE crypto_groups SET sends=sends+1 WHERE id=?1",
                [context.group.as_bytes().as_slice()],
            )?;
            let value = PreparedMessage {
                context: context.clone(),
                ciphertext,
                signed_action,
            };
            Ok((value.clone(), encode(&value)?))
        })
    }
    /// Resolve only from an authenticated durable home outcome, never a transport timeout.
    pub fn resolve_outbox(
        &self,
        store: &mut Store,
        operation: OperationId,
        accepted: bool,
    ) -> Result<()> {
        let input = encode(&(operation, accepted))?;
        atomic(store, "resolve outbox", &input, |tx| {
            let op = encode(&operation)?;
            let (group, state): (Vec<u8>, String) = tx.query_row(
                "SELECT group_id,state FROM crypto_outbox WHERE operation=?1",
                [&op],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let desired = if accepted { "committed" } else { "rejected" };
            if state != desired {
                if state != "pending" {
                    return Err(Error::Conflict);
                }
                tx.execute(
                    "UPDATE crypto_outbox SET state=?2 WHERE operation=?1",
                    rusqlite::params![op, desired],
                )?;
                if !accepted {
                    tx.execute("UPDATE crypto_groups SET gaps=gaps+1 WHERE id=?1", [group])?;
                }
            }
            Ok(((), input.clone()))
        })
    }
    pub fn receive(
        &self,
        store: &mut Store,
        incoming: &IncomingMessage<'_>,
        delivery: &HomeDelivery,
        roster: &ApprovedRoster,
    ) -> Result<DeliveryOutcome> {
        self.receive_with(store, incoming, delivery, roster, |_, _| Ok(()))
    }
    /// Archive/index updates supplied here share the receive ratchet and cursor transaction.
    pub fn receive_with(
        &self,
        store: &mut Store,
        incoming: &IncomingMessage<'_>,
        delivery: &HomeDelivery,
        roster: &ApprovedRoster,
        persist: impl FnOnce(&Transaction<'_>, &DeliveryOutcome) -> Result<()>,
    ) -> Result<DeliveryOutcome> {
        self.check(roster)?;
        incoming.validate()?;
        let input = encode(&(
            incoming.binding()?,
            delivery.previous_sequence,
            delivery.sequence,
            delivery.event,
            delivery.event_digest,
        ))?;
        let mut persist = Some(persist);
        let mut crypto_rejection = None;
        let result = atomic(store, "receive", &input, |tx| {
            if let Some(old) = duplicate(tx, incoming.context.group, delivery)? {
                return Ok((old.clone(), encode(&old)?));
            }
            check_cursor(
                tx,
                incoming.context.group,
                delivery.previous_sequence,
                delivery.sequence,
            )?;
            let decrypted = (|| {
                incoming_state(tx, incoming, roster)?;
                match resolved_candidate(tx, incoming)? {
                    Some(value) => Ok(value),
                    None => self.decrypt(tx, incoming, roster),
                }
            })();
            let outcome = decrypted.map_err(|error| {
                crypto_rejection = match error {
                    Error::Verification | Error::Binding | Error::Invalid => {
                        Some(Rejection::InvalidCryptography)
                    }
                    Error::Resynchronise => Some(Rejection::ResynchronisationRequired),
                    _ => None,
                };
                error
            })?;
            persist.take().ok_or(Error::Database)?(tx, &outcome)?;
            save_delivery(tx, incoming.context.group, delivery, &outcome)?;
            Ok((outcome.clone(), encode(&outcome)?))
        });
        if let Some(reason) = crypto_rejection {
            // The failed OpenMLS transaction and its transient group were dropped.
            // This transaction records only the authenticated home position and rejection.
            let resynchronise = reason == Rejection::ResynchronisationRequired;
            let outcome = DeliveryOutcome::Rejected(reason);
            return atomic(store, "reject ciphertext", &input, |tx| {
                check_cursor(
                    tx,
                    incoming.context.group,
                    delivery.previous_sequence,
                    delivery.sequence,
                )?;
                save_delivery(tx, incoming.context.group, delivery, &outcome)?;
                tx.execute("UPDATE crypto_groups SET gaps=gaps+1,frozen=CASE WHEN gaps+1>=?2 OR ?3 THEN 1 ELSE frozen END WHERE id=?1",rusqlite::params![incoming.context.group.as_bytes().as_slice(),MAX_FORWARD_DISTANCE,resynchronise])?;
                Ok((outcome.clone(), encode(&outcome)?))
            });
        }
        result
    }
    pub fn preview(
        &self,
        store: &mut Store,
        incoming: &IncomingMessage<'_>,
        roster: &ApprovedRoster,
        expected_cursor: u64,
    ) -> Result<DeliveryOutcome> {
        self.check(roster)?;
        incoming.validate()?;
        if incoming.context.approval.is_none() {
            return Err(Error::Binding);
        }
        let binding = incoming.binding()?;
        let operation = encode(&incoming.context.operation_id)?;
        atomic(store, "approval preview", binding.as_bytes(), |tx| {
            retention::window_open(tx, incoming.context.operation_id.window)?;
            incoming_state(tx, incoming, roster)?;
            let old: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT digest,result FROM crypto_approvals WHERE operation=?1",
                    [&operation],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((saved, result)) = old {
                if saved != binding.as_bytes().as_slice() {
                    return Err(Error::Conflict);
                }
                return Ok((decode(&result)?, result));
            }
            let (_, cursor, frozen) = metadata(tx, incoming.context.group)?;
            if frozen {
                return Err(Error::Suspended);
            }
            if cursor != expected_cursor {
                return Err(Error::Resynchronise);
            }
            budget(tx, "crypto_approvals")?;
            let outcome = self.decrypt(tx, incoming, roster)?;
            let state = if matches!(outcome, DeliveryOutcome::Message(_)) {
                "pending"
            } else {
                "rejected"
            };
            tx.execute("INSERT INTO crypto_approvals(operation,group_id,epoch,sender,digest,result,state,window_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",rusqlite::params![operation,incoming.context.group.as_bytes().as_slice(),incoming.context.epoch,incoming.context.actor.acting().endpoint.as_bytes().as_slice(),binding.as_bytes().as_slice(),encode(&outcome)?,state,incoming.context.operation_id.window.as_bytes().as_slice()])?;
            Ok((outcome.clone(), encode(&outcome)?))
        })
    }
    pub fn decide_preview(
        &self,
        store: &mut Store,
        incoming: &IncomingMessage<'_>,
        approve: bool,
    ) -> Result<()> {
        let input = encode(&(incoming.binding()?, approve))?;
        atomic(store, "approval decision", &input, |tx| {
            if approve {
                retention::window_open(tx, incoming.context.operation_id.window)?;
            }
            let operation = encode(&incoming.context.operation_id)?;
            let (saved, result, state): (Vec<u8>, Vec<u8>, String) = tx.query_row(
                "SELECT digest,result,state FROM crypto_approvals WHERE operation=?1",
                [&operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if saved != incoming.binding()?.as_bytes().as_slice() {
                return Err(Error::Conflict);
            }
            let provider = Provider::new(tx);
            let mls = load(&provider, incoming.context.group)?;
            if mls.epoch().as_u64() != incoming.context.epoch {
                return Err(Error::Conflict);
            }
            let desired = if approve { "approved" } else { "rejected" };
            if state != desired && state != "pending" {
                return Err(Error::Conflict);
            }
            if approve
                && !matches!(
                    decode::<DeliveryOutcome>(&result)?,
                    DeliveryOutcome::Message(_)
                )
            {
                return Err(Error::Invalid);
            }
            tx.execute(
                "UPDATE crypto_approvals SET state=?2 WHERE operation=?1",
                rusqlite::params![operation, desired],
            )?;
            Ok(((), input.clone()))
        })
    }
    fn decrypt(
        &self,
        tx: &Transaction<'_>,
        incoming: &IncomingMessage<'_>,
        roster: &ApprovedRoster,
    ) -> Result<DeliveryOutcome> {
        let context = incoming.context;
        if context.room != roster.room() || metadata(tx, context.group)?.0 != context.room {
            return Err(Error::Binding);
        }
        let provider = Provider::new(tx);
        let mut mls = self.group(&provider, context.group)?;
        if mls.epoch().as_u64() != context.epoch {
            return Err(Error::Verification);
        }
        roster.check(mls.members())?;
        let message = message(incoming.ciphertext)?;
        if message.wire_format() != WireFormat::PrivateMessage {
            return Err(Error::Binding);
        }
        let processed = mls
            .process_message(
                &provider,
                message
                    .try_into_protocol_message()
                    .map_err(|_| Error::Invalid)?,
            )
            .map_err(process_error)?;
        if processed.aad() != context.aad()? || !matches!(processed.sender(), Sender::Member(_)) {
            return Err(Error::Binding);
        }
        roster.credential(processed.credential(), context.actor.acting())?;
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(Error::Binding);
        };
        let bytes = application.into_bytes();
        Ok(match String::from_utf8(bytes) {
            Ok(text) if crate::text::message(&text).is_ok() => DeliveryOutcome::Message(text),
            _ => DeliveryOutcome::Rejected(Rejection::InvalidContent),
        })
    }
}
fn incoming_state(
    tx: &Transaction<'_>,
    incoming: &IncomingMessage<'_>,
    roster: &ApprovedRoster,
) -> Result<()> {
    if incoming.context.room != roster.room()
        || metadata(tx, incoming.context.group)?.0 != roster.room()
    {
        return Err(Error::Binding);
    }
    if roster
        .endpoint(incoming.context.actor.acting().endpoint)?
        .actor
        != *incoming.context.actor.acting()
    {
        return Err(Error::Binding);
    }
    let provider = Provider::new(tx);
    let group = load(&provider, incoming.context.group)?;
    if group.epoch().as_u64() != incoming.context.epoch {
        return Err(Error::Verification);
    }
    roster.check(group.members())
}
fn process_error(error: ProcessMessageError<rusqlite::Error>) -> Error {
    match error {
        ProcessMessageError::StorageError(_) => Error::Database,
        ProcessMessageError::GroupStateError(_) => Error::Suspended,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInTheFuture),
        )) => Error::Resynchronise,
        _ => Error::Verification,
    }
}
fn budget(tx: &Transaction<'_>, table: &str) -> Result<()> {
    let query = match table {
        "crypto_outbox" => "SELECT count(*) FROM crypto_outbox",
        "crypto_approvals" => "SELECT count(*) FROM crypto_approvals",
        _ => "SELECT count(*) FROM crypto_deliveries",
    };
    let count: i64 = tx.query_row(query, [], |r| r.get(0))?;
    if count >= RECORD_LIMIT {
        return Err(Error::Limit);
    }
    Ok(())
}
fn duplicate(
    tx: &Transaction<'_>,
    group: Id,
    delivery: &HomeDelivery,
) -> Result<Option<DeliveryOutcome>> {
    let old: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT event,digest,result FROM crypto_deliveries WHERE group_id=?1 AND sequence=?2",
            rusqlite::params![group.as_bytes().as_slice(), delivery.sequence],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((event, digest, result)) = old {
        if event != delivery.event.as_bytes().as_slice()
            || digest != delivery.event_digest.as_bytes().as_slice()
        {
            return Err(Error::Conflict);
        }
        return Ok(Some(decode(&result)?));
    }
    Ok(None)
}
fn save_delivery(
    tx: &Transaction<'_>,
    group: Id,
    delivery: &HomeDelivery,
    outcome: &DeliveryOutcome,
) -> Result<()> {
    budget(tx, "crypto_deliveries")?;
    tx.execute("INSERT INTO crypto_deliveries(group_id,sequence,event,digest,result) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![group.as_bytes().as_slice(),delivery.sequence,delivery.event.as_bytes().as_slice(),delivery.event_digest.as_bytes().as_slice(),encode(outcome)?])?;
    tx.execute(
        "UPDATE crypto_groups SET cursor=?2 WHERE id=?1",
        rusqlite::params![group.as_bytes().as_slice(), delivery.sequence],
    )?;
    Ok(())
}
fn resolved_candidate(
    tx: &Transaction<'_>,
    incoming: &IncomingMessage<'_>,
) -> Result<Option<DeliveryOutcome>> {
    let operation = encode(&incoming.context.operation_id)?;
    let own:Option<(Vec<u8>,Vec<u8>,String)>=tx.query_row("SELECT ciphertext,context,plaintext FROM crypto_outbox WHERE operation=?1 AND group_id=?2",rusqlite::params![operation,incoming.context.group.as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((ciphertext, context, plaintext)) = own {
        let context: EncryptionContext = decode(&context)?;
        let expected = crate::protocol::action_digest(&context.action(ciphertext.clone())?)
            .map_err(|_| Error::Invalid)?;
        if context != *incoming.context
            || ciphertext != incoming.ciphertext
            || expected != incoming.action_digest
        {
            return Err(Error::Conflict);
        }
        tx.execute(
            "UPDATE crypto_outbox SET state='committed' WHERE operation=?1",
            [operation],
        )?;
        return Ok(Some(DeliveryOutcome::Message(plaintext)));
    }
    let preview: Option<(Vec<u8>, Vec<u8>, String)> = tx
        .query_row(
            "SELECT digest,result,state FROM crypto_approvals WHERE operation=?1",
            [&operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((saved, result, state)) = preview {
        if saved != incoming.binding()?.as_bytes().as_slice() {
            return Err(Error::Conflict);
        }
        tx.execute(
            "UPDATE crypto_approvals SET state='delivered' WHERE operation=?1",
            [operation],
        )?;
        return if state == "approved" {
            Ok(Some(decode(&result)?))
        } else {
            Ok(Some(DeliveryOutcome::Rejected(Rejection::ApprovalRejected)))
        };
    }
    Ok(None)
}
