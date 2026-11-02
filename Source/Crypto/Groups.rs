// SPDX-License-Identifier: Apache-2.0
//! Persistent group admission and home-ordered membership transitions.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupState {
    pub group: Id,
    pub epoch: u64,
    pub cursor: u64,
    pub active: bool,
    pub frozen: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransition {
    pub group: Id,
    pub epoch: u64,
    #[serde(with = "bytes")]
    pub commit: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochReceipt {
    pub group: Id,
    pub epoch: u64,
    pub commit_digest: Id,
    pub sequence: u64,
    pub active: bool,
    #[serde(with = "optional_bytes")]
    pub welcome: Option<Vec<u8>>,
}
/// The authenticated home position of one transition from the expected epoch.
#[derive(Clone, Copy, Debug)]
pub struct TransitionOrder {
    pub group: Id,
    pub epoch: u64,
    pub previous_sequence: u64,
    pub sequence: u64,
}
pub enum Change<'a> {
    Add(&'a [Vec<u8>]),
    Remove(&'a [Id]),
    Update,
}
/// One membership proposal and its authenticated source epoch.
pub struct TransitionPreparation<'a> {
    pub group: Id,
    pub epoch: u64,
    pub current: &'a ApprovedRoster,
    pub next: &'a ApprovedRoster,
    pub change: Change<'a>,
}

impl Device {
    pub fn publish_key_package(&self, store: &mut Store, room: RoomId) -> Result<Vec<u8>> {
        let input = self.credential(room).bytes()?;
        atomic(store, "key package", &input, |tx| {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM crypto_packages", [], |r| r.get(0))?;
            if count >= 64 {
                return Err(Error::Limit);
            }
            let provider = Provider::new(tx);
            let keys = signer(&provider, self.mls_key)?;
            let bundle = KeyPackage::builder()
                .build(SUITE, &provider, &keys, self.credential_with_key(room)?)
                .map_err(|_| Error::Verification)?;
            let bytes = tls(bundle.key_package())?;
            let reference = serde_json::to_vec(
                &bundle
                    .key_package()
                    .hash_ref(provider.crypto())
                    .map_err(|_| Error::Verification)?,
            )
            .map_err(|_| Error::Invalid)?;
            tx.execute("INSERT INTO crypto_packages(digest,endpoint,room,bytes,package_ref) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![digest(&bytes).as_bytes().as_slice(),self.actor.endpoint.as_bytes().as_slice(),encode(&room)?,bytes,reference])?;
            Ok((bytes.clone(), bytes))
        })
    }
    /// Create a fresh cryptographic incarnation. The initial roster contains this endpoint only.
    pub fn create_group(
        &self,
        store: &mut Store,
        group: Id,
        roster: &ApprovedRoster,
        cursor: u64,
    ) -> Result<Vec<u8>> {
        self.create_group_with(store, group, roster, cursor, |_, _| Ok(()))
    }
    pub fn create_group_with(
        &self,
        store: &mut Store,
        group: Id,
        roster: &ApprovedRoster,
        cursor: u64,
        persist: impl FnOnce(&Transaction<'_>, &[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        self.check(roster)?;
        if roster.members().len() != 1 || cursor > i64::MAX as u64 {
            return Err(Error::Binding);
        }
        let request = encode(&(group, roster, cursor))?;
        atomic(store, "create group", &request, |tx| {
            let saved: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT request,info FROM crypto_creation WHERE group_id=?1",
                    [group.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((previous, info)) = saved {
                if previous != request {
                    return Err(Error::Conflict);
                }
                return Ok((info.clone(), info));
            }
            tx.execute(
                "INSERT INTO crypto_groups(id,room,mode,cursor) VALUES(?1,?2,'member',?3)",
                rusqlite::params![group.as_bytes().as_slice(), encode(&roster.room())?, cursor],
            )?;
            let provider = Provider::new(tx);
            let keys = signer(&provider, self.mls_key)?;
            let mls = MlsGroup::new_with_group_id(
                &provider,
                &keys,
                &create_config(),
                group_id(group),
                self.credential_with_key(roster.room())?,
            )
            .map_err(|_| Error::Verification)?;
            roster.check(mls.members())?;
            let info = tls(&mls
                .export_group_info(provider.crypto(), &keys, true)
                .map_err(|_| Error::Verification)?)?;
            tx.execute(
                "INSERT INTO crypto_creation(group_id,request,info) VALUES(?1,?2,?3)",
                rusqlite::params![group.as_bytes().as_slice(), request, info],
            )?;
            persist(tx, &info)?;
            Ok((info.clone(), info))
        })
    }
    pub fn state(&self, store: &mut Store, group: Id) -> Result<GroupState> {
        let mut result = None;
        store.read(std::time::Duration::from_secs(1), |conn| {
            result = Some((|| {
                let (_, cursor, frozen) = metadata(conn, group)?;
                let provider = Provider::new(conn);
                let mls = load(&provider, group)?;
                Ok(GroupState {
                    group,
                    epoch: mls.epoch().as_u64(),
                    cursor,
                    active: mls.is_active(),
                    frozen,
                })
            })());
            Ok(())
        })?;
        result.ok_or(Error::Database)?
    }
    pub fn prepare_transition(
        &self,
        store: &mut Store,
        group: Id,
        epoch: u64,
        current: &ApprovedRoster,
        next: &ApprovedRoster,
        change: Change<'_>,
    ) -> Result<PendingTransition> {
        self.prepare_transition_with(
            store,
            TransitionPreparation {
                group,
                epoch,
                current,
                next,
                change,
            },
            |_, _| Ok(()),
        )
    }
    /// Persist the exact application operation in the same transaction as the MLS
    /// candidate. Existing candidates retain their bytes when attaching legacy state.
    pub fn prepare_transition_with(
        &self,
        store: &mut Store,
        preparation: TransitionPreparation<'_>,
        persist: impl FnOnce(&Transaction<'_>, &PendingTransition) -> Result<()>,
    ) -> Result<PendingTransition> {
        let TransitionPreparation {
            group,
            epoch,
            current,
            next,
            change,
        } = preparation;
        self.check(current)?;
        if current.room() != next.room() {
            return Err(Error::Binding);
        }
        let request = encode(&(group, epoch, next))?;
        atomic(store, "prepare transition", &request, |tx| {
            let (room, _, frozen) = metadata(tx, group)?;
            if frozen {
                return Err(Error::Suspended);
            }
            if room != current.room() {
                return Err(Error::Binding);
            }
            let pending: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT request,commit_bytes FROM crypto_pending WHERE group_id=?1",
                    [group.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((saved, commit)) = pending {
                if saved != request {
                    return Err(Error::Conflict);
                }
                let value = PendingTransition {
                    group,
                    epoch,
                    commit,
                };
                persist(tx, &value)?;
                return Ok((value.clone(), encode(&value)?));
            }
            let outstanding: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM crypto_outbox WHERE group_id=?1 AND state='pending')",
                [group.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if outstanding {
                return Err(Error::Conflict);
            }
            let provider = Provider::new(tx);
            let keys = signer(&provider, self.mls_key)?;
            let mut mls = self.group(&provider, group)?;
            if mls.epoch().as_u64() != epoch {
                return Err(Error::Conflict);
            }
            current.check(mls.members())?;
            let (commit, welcome) = match change {
                Change::Add(packages) => {
                    if packages.is_empty()
                        || packages.len() > MAX_ENDPOINTS
                        || packages.iter().map(Vec::len).sum::<usize>()
                            > crate::protocol::CRYPTO_FRAME_BYTES
                    {
                        return Err(Error::Limit);
                    }
                    let mut additions = Vec::new();
                    let mut projected = current.members().to_vec();
                    for bytes in packages {
                        if bytes.len() > crate::protocol::CRYPTO_FRAME_BYTES {
                            return Err(Error::Limit);
                        }
                        let package = KeyPackageIn::tls_deserialize_exact(bytes)
                            .map_err(|_| Error::Invalid)?
                            .validate(provider.crypto(), ProtocolVersion::Mls10)
                            .map_err(|_| Error::Verification)?;
                        if package.ciphersuite() != SUITE || package.last_resort() {
                            return Err(Error::Binding);
                        }
                        let credential = next
                            .members()
                            .iter()
                            .find(|m| {
                                m.mls_key.as_bytes().as_slice()
                                    == package.leaf_node().signature_key().as_slice()
                            })
                            .ok_or(Error::Binding)?;
                        if package.leaf_node().credential() != &self::credential_value(credential)?
                        {
                            return Err(Error::Binding);
                        }
                        projected.push(credential.clone());
                        additions.push(package);
                    }
                    check_projected(next, &projected)?;
                    let (commit, welcome, _) = mls
                        .add_members(&provider, &keys, &additions)
                        .map_err(|_| Error::Verification)?;
                    (tls(&commit)?, Some(tls(&welcome)?))
                }
                Change::Remove(endpoints) => {
                    if endpoints.is_empty() || endpoints.contains(&self.actor.endpoint) {
                        return Err(Error::Binding);
                    }
                    let mut leaves = Vec::new();
                    for endpoint in endpoints {
                        let member = current.endpoint(*endpoint)?;
                        leaves.push(
                            mls.members()
                                .find(|m| m.signature_key == member.mls_key.as_bytes().as_slice())
                                .ok_or(Error::Binding)?
                                .index,
                        );
                    }
                    let projected: Vec<_> = current
                        .members()
                        .iter()
                        .filter(|m| !endpoints.contains(&m.actor.endpoint))
                        .cloned()
                        .collect();
                    check_projected(next, &projected)?;
                    let (commit, _, _) = mls
                        .remove_members(&provider, &keys, &leaves)
                        .map_err(|_| Error::Verification)?;
                    (tls(&commit)?, None)
                }
                Change::Update => {
                    check_projected(next, current.members())?;
                    let bundle = mls
                        .self_update(&provider, &keys, LeafNodeParameters::default())
                        .map_err(|_| Error::Verification)?;
                    (tls(bundle.commit())?, None)
                }
            };
            tx.execute("INSERT INTO crypto_pending(group_id,epoch,request,commit_bytes,welcome,roster) VALUES(?1,?2,?3,?4,?5,?6)",rusqlite::params![group.as_bytes().as_slice(),epoch,request,commit,welcome,encode(next)?])?;
            let value = PendingTransition {
                group,
                epoch,
                commit,
            };
            persist(tx, &value)?;
            Ok((value.clone(), encode(&value)?))
        })
    }
    /// Apply an authenticated home winner; a competing local candidate is discarded.
    /// Welcome bytes remain private in the outbox until this exact winner is durable.
    pub fn accept_transition(
        &self,
        store: &mut Store,
        order: TransitionOrder,
        commit: &[u8],
        next: &ApprovedRoster,
    ) -> Result<EpochReceipt> {
        self.accept_transition_with(store, order, commit, next, |_, _| Ok(()))
    }
    pub fn accept_transition_with(
        &self,
        store: &mut Store,
        order: TransitionOrder,
        commit: &[u8],
        next: &ApprovedRoster,
        persist: impl FnOnce(&Transaction<'_>, &EpochReceipt) -> Result<()>,
    ) -> Result<EpochReceipt> {
        let TransitionOrder {
            group,
            epoch,
            previous_sequence: prior_cursor,
            sequence,
        } = order;
        let input = encode(&(group, epoch, prior_cursor, sequence, digest(commit), next))?;
        let result = atomic(store, "accept transition", &input, |tx| {
            let saved:Option<(Vec<u8>,Vec<u8>)>=tx.query_row("SELECT input_digest,result FROM crypto_transitions WHERE group_id=?1 AND sequence=?2",rusqlite::params![group.as_bytes().as_slice(),sequence],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            if let Some((previous, result)) = saved {
                if previous != digest(&input).as_bytes().as_slice() {
                    return Err(Error::Conflict);
                }
                return Ok((decode(&result)?, result));
            }
            check_cursor(tx, group, prior_cursor, sequence)?;
            if metadata(tx, group)?.0 != next.room() {
                return Err(Error::Binding);
            }
            let provider = Provider::new(tx);
            let mut mls = self.group(&provider, group)?;
            if mls.epoch().as_u64() != epoch {
                return Err(Error::Conflict);
            }
            let pending: Option<(Vec<u8>, Option<Vec<u8>>)> = tx
                .query_row(
                    "SELECT commit_bytes,welcome FROM crypto_pending WHERE group_id=?1",
                    [group.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let mut welcome = None;
            if pending.as_ref().is_some_and(|(bytes, _)| bytes == commit) {
                mls.merge_pending_commit(&provider)
                    .map_err(|_| Error::Verification)?;
                welcome = pending.and_then(|(_, welcome)| welcome);
            } else {
                if mls.pending_commit().is_some() {
                    mls.clear_pending_commit(provider.storage())?;
                }
                let protocol = public_commit(commit)?;
                let processed = mls
                    .process_message(&provider, protocol)
                    .map_err(|_| Error::Verification)?;
                if !matches!(processed.sender(), Sender::Member(_)) {
                    return Err(Error::Binding);
                }
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
                else {
                    return Err(Error::Binding);
                };
                reject_extensions(&staged)?;
                mls.merge_staged_commit(&provider, *staged)
                    .map_err(|_| Error::Verification)?;
            }
            next.check(mls.members())?;
            if mls.epoch().as_u64() != epoch + 1 {
                return Err(Error::Verification);
            }
            tx.execute(
                "DELETE FROM crypto_pending WHERE group_id=?1",
                [group.as_bytes().as_slice()],
            )?;
            tx.execute("UPDATE crypto_approvals SET state='rejected' WHERE group_id=?1 AND state IN ('pending','approved')",[group.as_bytes().as_slice()])?;
            tx.execute(
                "UPDATE crypto_groups SET cursor=?2,sends=0,gaps=0 WHERE id=?1",
                rusqlite::params![group.as_bytes().as_slice(), sequence],
            )?;
            let value = EpochReceipt {
                group,
                epoch: epoch + 1,
                commit_digest: digest(commit),
                sequence,
                active: mls.is_active(),
                welcome,
            };
            tx.execute("INSERT INTO crypto_transitions(group_id,sequence,input_digest,result) VALUES(?1,?2,?3,?4)",rusqlite::params![group.as_bytes().as_slice(),sequence,digest(&input).as_bytes().as_slice(),encode(&value)?])?;
            persist(tx, &value)?;
            Ok((value.clone(), encode(&value)?))
        });
        if matches!(result, Err(Error::Verification | Error::Binding)) {
            atomic(store, "freeze transition", &input, |tx| {
                tx.execute(
                    "UPDATE crypto_groups SET frozen=1 WHERE id=?1",
                    [group.as_bytes().as_slice()],
                )?;
                Ok(((), b"suspended".to_vec()))
            })?;
        }
        result
    }
    /// Clear a candidate only after the home durably rejected that exact commit.
    pub fn reject_transition(&self, store: &mut Store, group: Id, commit_digest: Id) -> Result<()> {
        let input = encode(&(group, commit_digest))?;
        atomic(store, "reject transition", &input, |tx| {
            let epoch: u64 = tx.query_row(
                "SELECT epoch FROM crypto_pending WHERE group_id=?1",
                [group.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            self.group(&Provider::new(tx), group)?;
            if !reject_transition_in(
                tx,
                metadata(tx, group)?.0,
                group,
                epoch,
                commit_digest,
                None,
            )? {
                return Err(Error::Conflict);
            }
            Ok(((), input.clone()))
        })
    }
    pub fn join(
        &self,
        store: &mut Store,
        group: Id,
        epoch: u64,
        cursor: u64,
        welcome: &[u8],
        roster: &ApprovedRoster,
    ) -> Result<GroupState> {
        self.join_with(
            store,
            WelcomeJoin {
                group,
                epoch,
                cursor,
                welcome,
                roster,
            },
            |_, _| Ok(()),
        )
    }
    pub fn join_with(
        &self,
        store: &mut Store,
        join: WelcomeJoin<'_>,
        persist: impl FnOnce(&Transaction<'_>, &GroupState) -> Result<()>,
    ) -> Result<GroupState> {
        let WelcomeJoin {
            group,
            epoch,
            cursor,
            welcome,
            roster,
        } = join;
        self.check(roster)?;
        let input = encode(&(group, epoch, cursor, digest(welcome), roster))?;
        atomic(store, "welcome", &input, |tx| {
            let saved: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT input_digest,result FROM crypto_joins WHERE group_id=?1",
                    [group.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((previous, result)) = saved {
                if previous != digest(&input).as_bytes().as_slice() {
                    return Err(Error::Conflict);
                }
                return Ok((decode(&result)?, result));
            }
            let provider = Provider::new(tx);
            let MlsMessageBodyIn::Welcome(welcome) = message(welcome)?.extract() else {
                return Err(Error::Invalid);
            };
            let staged = StagedWelcome::new_from_welcome(&provider, &join_config(), welcome, None)
                .map_err(|_| Error::Verification)?;
            roster.check(staged.members())?;
            let mls = staged
                .into_group(&provider)
                .map_err(|_| Error::Verification)?;
            if mls.group_id() != &group_id(group) || mls.epoch().as_u64() != epoch {
                return Err(Error::Binding);
            }
            let mine = mls
                .members()
                .find(|m| m.index == mls.own_leaf_index())
                .ok_or(Error::Binding)?;
            if mine.signature_key != self.mls_key.as_bytes().as_slice() {
                return Err(Error::Binding);
            }
            tx.execute(
                "INSERT INTO crypto_groups(id,room,mode,cursor) VALUES(?1,?2,'member',?3)",
                rusqlite::params![group.as_bytes().as_slice(), encode(&roster.room())?, cursor],
            )?;
            // Consumed packages are no longer publishable; their secret deletion is done by OpenMLS.
            tx.execute("DELETE FROM crypto_packages WHERE NOT EXISTS(SELECT 1 FROM openmls_key_packages k WHERE k.key_package_ref=crypto_packages.package_ref)",[])?;
            let value = GroupState {
                group,
                epoch,
                cursor,
                active: true,
                frozen: false,
            };
            tx.execute(
                "INSERT INTO crypto_joins(group_id,input_digest,result) VALUES(?1,?2,?3)",
                rusqlite::params![
                    group.as_bytes().as_slice(),
                    digest(&input).as_bytes().as_slice(),
                    encode(&value)?
                ],
            )?;
            persist(tx, &value)?;
            Ok((value.clone(), encode(&value)?))
        })
    }
}

/// Join a verified terminal rejection to the exact HRC outbox outcome. A repeated
/// or older rejection cannot erase another locally prepared membership change.
pub(crate) fn reject_transition_in(
    tx: &Transaction<'_>,
    room: RoomId,
    group: Id,
    epoch: u64,
    commit_digest: Id,
    operation: Option<(crate::protocol::OperationId, Id)>,
) -> Result<bool> {
    let pending: Option<(u64, Vec<u8>, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT epoch,commit_bytes,operation FROM crypto_pending WHERE group_id=?1",
            [group.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((saved_epoch, commit, binding)) = pending else {
        return Ok(false);
    };
    if saved_epoch != epoch || digest(&commit) != commit_digest {
        return Ok(false);
    }
    if metadata(tx, group)?.0 != room {
        return Ok(false);
    }
    if let Some(operation) = operation
        && binding.as_ref() != Some(&encode(&operation)?)
    {
        return Ok(false);
    }
    let provider = Provider::new(tx);
    let mut mls = load(&provider, group)?;
    mls.clear_pending_commit(provider.storage())?;
    tx.execute(
        "DELETE FROM crypto_pending WHERE group_id=?1",
        [group.as_bytes().as_slice()],
    )?;
    Ok(true)
}

/// Attach an exact signed operation once, including a legacy unbound candidate.
pub(crate) fn bind_transition_in(
    tx: &Transaction<'_>,
    pending: &PendingTransition,
    operation: crate::protocol::OperationId,
    action_digest: Id,
) -> Result<()> {
    let (epoch, bytes, previous): (u64, Vec<u8>, Option<Vec<u8>>) = tx.query_row(
        "SELECT epoch,commit_bytes,operation FROM crypto_pending WHERE group_id=?1",
        [pending.group.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let binding = encode(&(operation, action_digest))?;
    if epoch != pending.epoch
        || bytes != pending.commit
        || previous.as_ref().is_some_and(|old| old != &binding)
    {
        return Err(Error::Conflict);
    }
    tx.execute(
        "UPDATE crypto_pending SET operation=?1 WHERE group_id=?2",
        rusqlite::params![binding, pending.group.as_bytes().as_slice()],
    )?;
    Ok(())
}
pub struct WelcomeJoin<'a> {
    pub group: Id,
    pub epoch: u64,
    pub cursor: u64,
    pub welcome: &'a [u8],
    pub roster: &'a ApprovedRoster,
}
fn credential_value(value: &EndpointCredential) -> Result<Credential> {
    Ok(BasicCredential::new(value.bytes()?).into())
}
fn check_projected(next: &ApprovedRoster, projected: &[EndpointCredential]) -> Result<()> {
    if next.members().len() != projected.len()
        || projected
            .iter()
            .any(|member| !next.members().contains(member))
    {
        return Err(Error::Binding);
    }
    Ok(())
}
pub(super) fn public_commit(bytes: &[u8]) -> Result<ProtocolMessage> {
    let message = message(bytes)?;
    if message.wire_format() != WireFormat::PublicMessage {
        return Err(Error::Binding);
    }
    message
        .try_into_protocol_message()
        .map_err(|_| Error::Invalid)
}
pub(super) fn reject_extensions(staged: &StagedCommit) -> Result<()> {
    if staged.psk_proposals().next().is_some()
        || staged.queued_proposals().any(|p| {
            !matches!(
                p.proposal(),
                Proposal::Add(_) | Proposal::Remove(_) | Proposal::Update(_)
            )
        })
    {
        return Err(Error::Binding);
    }
    Ok(())
}
