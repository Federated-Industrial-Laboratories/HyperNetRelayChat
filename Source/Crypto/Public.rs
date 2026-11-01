// SPDX-License-Identifier: Apache-2.0
//! Home-service public MLS validation. This cannot verify the private confirmation tag.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicEpoch {
    pub group: Id,
    pub epoch: u64,
    pub commit_digest: Id,
}

/// Call inside the same Store transaction as room creation and endpoint authority.
/// The caller supplies the current approved roster from authenticated registrations.
pub fn create_public_in(
    tx: &Transaction<'_>,
    group: Id,
    info: &[u8],
    roster: &ApprovedRoster,
) -> Result<()> {
    let MlsMessageBodyIn::GroupInfo(info) = message(info)?.extract() else {
        return Err(Error::Invalid);
    };
    if info.group_id() != &group_id(group)
        || info.epoch().as_u64() != 0
        || info.ciphersuite() != SUITE
    {
        return Err(Error::Binding);
    }
    let tree = info
        .extensions()
        .ratchet_tree()
        .ok_or(Error::Binding)?
        .ratchet_tree()
        .clone();
    let provider = Provider::new(tx);
    let (public, _) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        tree,
        info,
        ProposalStore::new(),
    )
    .map_err(|_| Error::Verification)?;
    roster.check(public.members())?;
    tx.execute(
        "INSERT INTO crypto_groups(id,room,mode,cursor) VALUES(?1,?2,'public',0)",
        rusqlite::params![group.as_bytes().as_slice(), encode(&roster.room())?],
    )?;
    Ok(())
}

/// Validate and persist exactly one public transition under the home's serial
/// transaction. The caller must maintain its send barrier until an eligible
/// endpoint supplies a durable receipt for this exact epoch and commit digest.
pub fn accept_public_in(
    tx: &Transaction<'_>,
    group: Id,
    expected_epoch: u64,
    commit: &[u8],
    actor: &crate::protocol::EndpointActor,
    current: &ApprovedRoster,
    next: &ApprovedRoster,
) -> Result<PublicEpoch> {
    if current.room() != next.room() {
        return Err(Error::Binding);
    }
    let room: Vec<u8> = tx.query_row(
        "SELECT room FROM crypto_groups WHERE id=?1 AND mode='public' AND frozen=0",
        [group.as_bytes().as_slice()],
        |r| r.get(0),
    )?;
    if decode::<RoomId>(&room)? != current.room() {
        return Err(Error::Binding);
    }
    let provider = Provider::new(tx);
    let mut public =
        PublicGroup::load(provider.storage(), &group_id(group))?.ok_or(Error::Resynchronise)?;
    if public.group_context().epoch().as_u64() != expected_epoch {
        return Err(Error::Conflict);
    }
    current.check(public.members())?;
    let processed = public
        .process_message(provider.crypto(), groups::public_commit(commit)?)
        .map_err(|_| Error::Verification)?;
    if !matches!(processed.sender(), Sender::Member(_)) {
        return Err(Error::Binding);
    }
    current.credential(processed.credential(), actor)?;
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(Error::Binding);
    };
    groups::reject_extensions(&staged)?;
    public
        .merge_commit(provider.storage(), *staged)
        .map_err(|_| Error::Verification)?;
    next.check(public.members())?;
    if public.group_context().epoch().as_u64() != expected_epoch + 1 {
        return Err(Error::Verification);
    }
    Ok(PublicEpoch {
        group,
        epoch: expected_epoch + 1,
        commit_digest: digest(commit),
    })
}
