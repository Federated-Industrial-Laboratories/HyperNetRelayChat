// SPDX-License-Identifier: Apache-2.0
//! Exact approval inspection decrypts once; only a current approved candidate leaves held outbox state.
use super::archive::serialize_content as archive_content;
use super::{Client, Error, MessageContent, Result, cache, encrypted::failure, outbox};
use crate::{crypto, delegation, home, protocol::*};
use std::collections::BTreeMap;
#[derive(Clone, Debug, serde::Serialize)]
pub struct GrantPreview {
    pub inspection: delegation::Inspection,
    pub candidates: Vec<Action>,
    #[serde(serialize_with = "archive_content")]
    pub content: BTreeMap<Id, MessageContent>,
}
impl Client {
    pub fn inspect_grant(&mut self, reference: GrantRef) -> Result<GrantPreview> {
        let inspection: delegation::Inspection = self.read_as(
            Operation::DelegationInspect,
            Target::Delegation(reference),
            &home::Empty {},
            None,
        )?;
        let mut content = BTreeMap::new();
        let mut candidates = Vec::new();
        for pending in &inspection.pending {
            let candidate = super::json::pending_action(pending).map_err(|_| Error::Input)?;
            if let Ok((context, encrypted)) = crypto::EncryptionContext::from_action(&candidate) {
                let result = (|| {
                    if inspection.grant.owner != self.profile.registration.account {
                        return Err(Error::Input);
                    }
                    let view = self.crypto_sync(context.room, None)?;
                    let roster = self.trusted_roster(context.room, &view.remote.members, true)?;
                    if !view.remote.members.iter().any(|m| m.actor == context.actor) {
                        return Err(Error::Input);
                    }
                    let chain = self.trusted_chain(context.actor.acting().account)?;
                    let endpoint = chain
                        .latest()
                        .endpoints
                        .iter()
                        .find(|e| e.actor == *context.actor.acting())
                        .ok_or(Error::Input)?;
                    let key = VerifyingKey::from_bytes(endpoint.key.as_bytes())
                        .map_err(|_| Error::Input)?;
                    let verified =
                        verify_action(&pending.candidate.0, &key).map_err(|_| Error::Input)?;
                    if verified.digest() != pending.action_digest {
                        return Err(Error::Input);
                    }
                    let incoming = crypto::IncomingMessage {
                        context: &context,
                        ciphertext: &encrypted.ciphertext,
                        action_digest: verified.digest(),
                    };
                    let device = self.crypto_device()?;
                    let cursor = view.local.ok_or(Error::Input)?.cursor;
                    let value = device
                        .preview(&mut self.store, &incoming, &roster, cursor)
                        .map_err(failure)?;
                    Ok::<_, Error>(match value {
                        crypto::DeliveryOutcome::Message(message) => {
                            MessageContent::Decrypted(message)
                        }
                        crypto::DeliveryOutcome::Rejected(reason) => {
                            MessageContent::Rejected(reason)
                        }
                    })
                })()
                .unwrap_or(MessageContent::Unavailable);
                content.insert(pending.action_digest, result);
            }
            candidates.push(candidate);
        }
        Ok(GrantPreview {
            inspection,
            candidates,
            content,
        })
    }
    pub fn decide_approval(
        &mut self,
        reference: GrantRef,
        decision: &delegation::Decision,
        approve: bool,
    ) -> Result<Response> {
        let preview = self.inspect_grant(reference)?;
        if preview.inspection.grant.owner != self.profile.registration.account {
            return Err(Error::Input);
        }
        let pending = preview
            .inspection
            .pending
            .iter()
            .find(|p| p.approval == decision.approval && p.action_digest == decision.action_digest)
            .ok_or(Error::Input)?;
        let candidate = super::json::pending_action(pending).map_err(|_| Error::Input)?;
        if let Ok((context, encrypted)) = crypto::EncryptionContext::from_action(&candidate) {
            let available = matches!(
                preview.content.get(&decision.action_digest),
                Some(MessageContent::Decrypted(_))
            );
            if approve && !available {
                return Err(Error::Rejected {
                    code: ErrorCode::Denied,
                    detail: "EncryptedApprovalContentUnavailable".into(),
                });
            }
            if available {
                let incoming = crypto::IncomingMessage {
                    context: &context,
                    ciphertext: &encrypted.ciphertext,
                    action_digest: decision.action_digest,
                };
                let device = self.crypto_device()?;
                device
                    .decide_preview(&mut self.store, &incoming, approve)
                    .map_err(failure)?;
            }
        }
        self.call(
            if approve {
                Operation::ApprovalApprove
            } else {
                Operation::ApprovalReject
            },
            Target::Delegation(reference),
            decision,
        )
    }
    pub fn submit_candidate(&mut self, bytes: &[u8]) -> Result<Response> {
        let candidate =
            verify_action(bytes, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        let action = candidate.action();
        let approval = action.approval.ok_or(Error::Input)?;
        let Actor::Delegated { grant, .. } = action.actor else {
            return Err(Error::Input);
        };
        let inspection: delegation::Inspection = self.read_as(
            Operation::DelegationInspect,
            Target::Delegation(grant),
            &home::Empty {},
            None,
        )?;
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        let pending = inspection
            .pending
            .iter()
            .find(|p| {
                p.approval == approval
                    && p.action_digest == candidate.digest()
                    && p.candidate.0 == bytes
                    && p.state == 1
                    && now.upper_ms < p.expires_ms
            })
            .ok_or(Error::Rejected {
                code: ErrorCode::Denied,
                detail: "ExactApprovalUnavailable".into(),
            })?;
        if inspection.grant.state != delegation::State::Active
            || !now.permits(
                inspection.grant.scope.not_before_ms,
                inspection.grant.scope.expires_ms,
            )
        {
            return Err(Error::Rejected {
                code: ErrorCode::Expired,
                detail: "GrantUnavailable".into(),
            });
        }
        let _ = pending;
        if self
            .pending()?
            .iter()
            .any(|p| p.action.digest() == candidate.digest() && p.held)
        {
            outbox::release_candidate(&mut self.store, &candidate).map_err(|_| Error::Storage)?;
            self.retry_pending(action.operation_id, candidate.digest())
        } else {
            self.execute_signed(bytes)
        }
    }
    pub(super) fn own_plaintext(&mut self, action: &Action) -> Result<crate::messaging::Send> {
        if let Ok((context, _)) = crypto::EncryptionContext::from_action(action) {
            let bytes = self
                .store
                .read(std::time::Duration::from_secs(1), |db| {
                    db.query_row(
                        "SELECT plaintext FROM crypto_outbox WHERE operation=?1",
                        [cache::encode(&action.operation_id)?],
                        |r| r.get::<_, Vec<u8>>(0),
                    )
                })
                .map_err(|_| Error::Storage)?;
            let message = crypto::ApplicationMessage::from_bytes(&bytes).map_err(failure)?;
            Ok(crate::messaging::Send {
                text: message.text,
                mentions: message.mentions,
                parent: context.parent,
                causation: context.causation,
            })
        } else {
            action.body.deserialized().map_err(|_| Error::Input)
        }
    }
}
