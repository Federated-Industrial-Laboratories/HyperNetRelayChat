// SPDX-License-Identifier: Apache-2.0
use super::*;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

pub(crate) fn load(db: &Connection, id: Id) -> Domain<AgreementState> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT data FROM federation_agreements WHERE id=?1",
            [id.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    bytes
        .map(|b| decode(&b))
        .transpose()?
        .ok_or(Fault::Reject(ErrorCode::Denied, "AgreementUnavailable"))
}
pub(crate) fn current(
    db: &Connection,
    reference: AgreementRef,
    now: TimeBounds,
) -> Domain<AgreementState> {
    let state = load(db, reference.id)?;
    if state.reference != reference {
        return conflict("AgreementRevision");
    }
    if state.withdrawn {
        return deny("AgreementWithdrawn");
    }
    if !now.permits(state.agreement.not_before_ms, state.agreement.expires_ms) {
        return Err(Fault::Reject(ErrorCode::Expired, "AgreementExpired"));
    }
    Ok(state)
}
pub(crate) fn admission(
    db: &Connection,
    reference: AdmissionRef,
    now: TimeBounds,
) -> Domain<RemoteAdmission> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT data FROM federation_admissions WHERE id=?1",
            [reference.id.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    let a: RemoteAdmission = bytes
        .map(|b| decode(&b))
        .transpose()?
        .ok_or(Fault::Reject(ErrorCode::Denied, "RemoteAdmission"))?;
    if a.reference != reference {
        return conflict("AdmissionRevision");
    }
    if a.withdrawn {
        return deny("AdmissionWithdrawn");
    }
    if !now.permits(a.not_before_ms, a.expires_ms) {
        return Err(Fault::Reject(ErrorCode::Expired, "AdmissionExpired"));
    }
    current(db, a.agreement, now)?;
    Ok(a)
}
pub(crate) fn actor_admitted(
    db: &Connection,
    actor: &EndpointActor,
    room: RoomId,
    now: TimeBounds,
) -> Domain<()> {
    if actor.account.origin == room.home.network {
        return Ok(());
    }
    let rows=db.prepare("SELECT data FROM federation_admissions WHERE account=?1 AND endpoint=?2 AND withdrawn=0 LIMIT 33")?.query_map(params![actor.account.to_string(),actor.endpoint.as_hex()],|r|decode::<RemoteAdmission>(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > 32 {
        return deny("AdmissionCapacity");
    }
    for a in rows {
        if a.acting == *actor && a.rooms.contains(&room) && admission(db, a.reference, now).is_ok()
        {
            return Ok(());
        }
    }
    deny("RemoteRoomAdmission")
}
pub(crate) fn recipient_admitted(
    db: &Connection,
    account: AccountId,
    home: ServiceId,
    now: TimeBounds,
) -> Domain<bool> {
    if account.origin == home.network {
        return Ok(true);
    }
    let rows = db
        .prepare(
            "SELECT data FROM federation_admissions WHERE account=?1 AND withdrawn=0 LIMIT 257",
        )?
        .query_map([account.to_string()], |r| {
            decode::<RemoteAdmission>(&r.get::<_, Vec<u8>>(0)?)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for a in rows {
        if a.home == home && admission(db, a.reference, now).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn expire_in(db: &Transaction<'_>, now: TimeBounds) -> rusqlite::Result<()> {
    let local: ServiceId =
        db.query_row("SELECT home FROM hrc_meta WHERE singleton=1", [], |r| {
            decode(&r.get::<_, Vec<u8>>(0)?)
        })?;
    let agreements = db
        .prepare(
            "SELECT id,data FROM federation_agreements WHERE withdrawn=0 AND expires<=?1 LIMIT 33",
        )?
        .query_map([now.upper_ms], |r| {
            Ok((
                r.get::<_, String>(0)?,
                decode::<AgreementState>(&r.get::<_, Vec<u8>>(1)?)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, mut state) in agreements {
        state.withdrawn = true;
        state.barrier_position = if local == state.agreement.home {
            Some(crate::home::next_position(db)?)
        } else {
            None
        };
        db.execute(
            "UPDATE federation_agreements SET withdrawn=1,data=?1 WHERE id=?2",
            params![encode(&state)?, id],
        )?;
        withdraw_admissions(db, &id, None)?;
    }
    let rows=db.prepare("SELECT agreement,id FROM federation_admissions WHERE withdrawn=0 AND expires<=?1 LIMIT 257")?.query_map([now.upper_ms],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for (agreement, id) in rows {
        withdraw_admissions(db, &agreement, Some(&id))?;
    }
    Ok(())
}
fn withdraw_admissions(
    db: &Transaction<'_>,
    agreement: &str,
    selected: Option<&str>,
) -> rusqlite::Result<()> {
    let rows=db.prepare("SELECT id,data FROM federation_admissions WHERE agreement=?1 AND withdrawn=0 AND (?2 IS NULL OR id=?2) LIMIT 257")?.query_map(params![agreement,selected],|r|Ok((r.get::<_,String>(0)?,decode::<RemoteAdmission>(&r.get::<_,Vec<u8>>(1)?)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > 256 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut accounts = std::collections::BTreeSet::new();
    for (id, mut a) in rows {
        a.withdrawn = true;
        db.execute(
            "UPDATE federation_admissions SET withdrawn=1,data=?1 WHERE id=?2",
            params![encode(&a)?, id],
        )?;
        accounts.insert(a.acting.account);
    }
    invalidate(db, &accounts.into_iter().collect::<Vec<_>>())
}

fn bind_room_origins(db: &Transaction<'_>, agreement: &FederationAgreement) -> Domain<()> {
    let mut count: u64 = db.query_row("SELECT count(*) FROM federation_room_origins", [], |r| {
        r.get(0)
    })?;
    for shared in &agreement.rooms {
        let existing: Option<Vec<u8>> = db
            .query_row(
                "SELECT origin FROM federation_room_origins WHERE room=?1",
                [shared.room.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            if decode::<ServiceId>(&bytes)? != agreement.origin {
                return deny("ThirdNetworkRoom");
            }
        } else {
            // Keep the binding after withdrawal: retained room history must not
            // become a route to a third origin through a later agreement.
            if count >= 1024 {
                return Err(Fault::Reject(
                    ErrorCode::Overloaded,
                    "SharedRoomBindingCapacity",
                ));
            }
            db.execute(
                "INSERT INTO federation_room_origins VALUES(?1,?2)",
                params![shared.room.to_string(), encode(&agreement.origin)?],
            )?;
            count += 1;
        }
    }
    Ok(())
}
impl Home {
    pub fn federation_find_admission(
        &mut self,
        gateway: &GatewayContext,
        account: AccountId,
        endpoint: Id,
        binding_digest: Id,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<RemoteAdmission> {
        let t = now(clock)?;
        if !permit() {
            return Err(Error::Refused {
                code: ErrorCode::Unavailable,
                detail: "GatewayAuthorityUnavailable",
            });
        }
        self.store.read(Duration::from_secs(2),|db|{
            let query=||->Domain<RemoteAdmission>{let state=current(db,gateway.agreement,t)?;exchange::gateway_binding(&state,gateway,self.home)?;
                if account.origin!=state.agreement.origin.network{return deny("AdmissionOrigin")}
                let bytes:Option<Vec<u8>>=db.query_row("SELECT data FROM federation_admissions WHERE agreement=?1 AND account=?2 AND endpoint=?3",params![state.reference.id.as_hex(),account.to_string(),endpoint.as_hex()],|r|r.get(0)).optional()?;
                let saved:RemoteAdmission=bytes.map(|b|decode(&b)).transpose()?.ok_or(Fault::Reject(ErrorCode::Denied,"RemoteAdmission"))?;
                let result=admission(db,saved.reference,t)?;if result.agreement!=state.reference||result.acting.binding_digest!=binding_digest{return deny("AdmissionBinding")}Ok(result)
            };Ok(query())
        })?.map_err(convert)
    }
    pub fn federation_inspect(&mut self, reference: AgreementRef) -> Result<AgreementState> {
        let value = self
            .store
            .read(Duration::from_secs(2), |db| Ok(load(db, reference.id)))?
            .map_err(convert)?;
        if value.reference != reference {
            return Err(refused("AgreementRevision"));
        }
        Ok(value)
    }
    /// Only a local administrative command may supply these independent trust pins.
    pub fn federation_accept(
        &mut self,
        home_signature: &[u8],
        origin_signature: &[u8],
        pins: &AgreementPins,
        clock: TimeBounds,
    ) -> Result<AgreementState> {
        let h = verify_agreement(home_signature, &key(pins.home_key)?)?;
        let o = verify_agreement(origin_signature, &key(pins.origin_key)?)?;
        let a = h.value();
        if h.bytes() != o.bytes()
            || a.home != pins.home
            || a.origin != pins.origin
            || a.home_service_key != pins.home_key
            || a.origin_service_key != pins.origin_key
            || a.origin_attestor_key != pins.origin_attestor
            || self.home != a.home && self.home != a.origin
            || Id::from_bytes(self.signer.verifying_key().to_bytes())
                != if self.home == a.home {
                    a.home_service_key
                } else {
                    a.origin_service_key
                }
        {
            return Err(refused("AgreementPins"));
        }
        let state = AgreementState {
            reference: AgreementRef {
                id: a.id,
                revision: a.revision,
                digest: h.digest(),
            },
            agreement: a.clone(),
            home_signature: Blob(home_signature.to_vec()),
            origin_signature: Blob(origin_signature.to_vec()),
            withdrawn: false,
            barrier_position: None,
        };
        write(self, "HRC.Federation.Accept", clock, |db, now| {
            if !now.permits(a.not_before_ms, a.expires_ms) {
                return Err(Fault::Reject(ErrorCode::Expired, "AgreementExpired"));
            }
            match load(db, a.id) {
                Ok(old) => {
                    if old.reference == state.reference {
                        return Ok(old);
                    }
                    if a.revision != old.reference.revision + 1
                        || old.agreement.home != a.home
                        || old.agreement.origin != a.origin
                        || old.agreement.home_service_key != a.home_service_key
                        || old.agreement.origin_service_key != a.origin_service_key
                    {
                        return conflict("AgreementRevision");
                    }
                    withdraw_admissions(db, &a.id.as_hex(), None)?;
                    db.execute(
                        "DELETE FROM federation_freshness WHERE agreement=?1",
                        [a.id.as_hex()],
                    )?;
                    db.execute("UPDATE federation_watches SET dirty=1,acknowledged=NULL WHERE agreement=?1",[a.id.as_hex()])?;
                }
                Err(Fault::Reject(..)) => {
                    let count: u64 =
                        db.query_row("SELECT count(*) FROM federation_agreements", [], |r| {
                            r.get(0)
                        })?;
                    if count >= 32 {
                        return Err(Fault::Reject(ErrorCode::Overloaded, "AgreementCapacity"));
                    }
                    if a.revision != 1 {
                        return conflict("AgreementRevision");
                    }
                }
                Err(e) => return Err(e),
            }
            bind_room_origins(db, a)?;
            db.execute("INSERT INTO federation_agreements VALUES(?1,?2,?3,?4,?5,0) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,data=excluded.data,expires=excluded.expires,withdrawn=0",params![a.id.as_hex(),a.revision,h.digest().as_bytes(),encode(&state)?,a.expires_ms])?;
            Ok(state.clone())
        })
    }
    pub fn federation_agreement(
        &mut self,
        reference: AgreementRef,
        clock: TimeBounds,
    ) -> Result<AgreementState> {
        let t = now(clock)?;
        self.store
            .read(Duration::from_secs(2), |db| Ok(current(db, reference, t)))
            .map_err(Error::from)?
            .map_err(convert)
    }
    pub fn federation_withdraw(
        &mut self,
        reference: AgreementRef,
        clock: TimeBounds,
    ) -> Result<AgreementState> {
        let local = self.home;
        write(self, "HRC.Federation.Withdraw", clock, |db, _| {
            let mut state = load(db, reference.id)?;
            if state.reference != reference {
                return conflict("AgreementRevision");
            }
            if !state.withdrawn {
                state.withdrawn = true;
                state.barrier_position = if local == state.agreement.home {
                    Some(crate::home::next_position(db)?)
                } else {
                    None
                };
                withdraw_admissions(db, &reference.id.as_hex(), None)?;
                db.execute(
                    "UPDATE federation_agreements SET withdrawn=1,data=?1 WHERE id=?2",
                    params![encode(&state)?, reference.id.as_hex()],
                )?;
            }
            Ok(state)
        })
    }
    pub fn federation_withdraw_from_gateway(
        &mut self,
        gateway: &GatewayContext,
        request: &Verified<FederationControl>,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<AgreementState> {
        if !permit() {
            return Err(Error::Refused {
                code: ErrorCode::Unavailable,
                detail: "GatewayAuthorityUnavailable",
            });
        }
        let FederationControl::Request {
            home,
            origin,
            agreement,
            request: request_id,
            operation,
            body,
            created_ms,
            expires_ms,
            ..
        } = request.value()
        else {
            return Err(refused("WithdrawalRequest"));
        };
        let withdrawal: FederationWithdrawal =
            body.deserialized().map_err(|_| refused("WithdrawalBody"))?;
        if *operation != Operation::FederationWithdraw
            || withdrawal.agreement != *agreement
            || withdrawal.request != *request_id
            || self.home != *home
        {
            return Err(refused("WithdrawalBinding"));
        }
        let local = self.home;
        write(
            self,
            &("HRC.Federation.WithdrawControl", request.digest()),
            clock,
            |db, t| {
                let mut state = load(db, agreement.id)?;
                if state.reference != *agreement
                    || state.agreement.home != *home
                    || state.agreement.origin != *origin
                    || request.signer_key() != state.agreement.origin_service_key
                {
                    return deny("WithdrawalSigner");
                }
                exchange::gateway_binding(&state, gateway, local)?;
                if !t.permits(*created_ms, *expires_ms) {
                    return Err(Fault::Reject(
                        ErrorCode::Expired,
                        "WithdrawalRequestExpired",
                    ));
                }
                let saved: Option<(Vec<u8>, Vec<u8>)> = db
                    .query_row(
                        "SELECT digest,result FROM federation_controls WHERE request=?1",
                        [request_id.as_hex()],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((digest, bytes)) = saved {
                    if digest.as_slice() != request.digest().as_bytes() {
                        return conflict("ControlRequestContent");
                    }
                    if !permit()
                        || !clock
                            .refresh()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?
                            .permits(*created_ms, *expires_ms)
                    {
                        return Err(Fault::Reject(
                            ErrorCode::Unavailable,
                            "WithdrawalAuthorityUnavailable",
                        ));
                    }
                    return Ok(decode(&bytes)?);
                }
                db.execute(
                    "DELETE FROM federation_controls WHERE created<=?1",
                    [t.upper_ms.saturating_sub(7 * DAY)],
                )?;
                let count: u64 =
                    db.query_row("SELECT count(*) FROM federation_controls", [], |r| r.get(0))?;
                if count >= 65536 {
                    return Err(Fault::Reject(
                        ErrorCode::Overloaded,
                        "ControlReceiptCapacity",
                    ));
                }
                if !state.withdrawn {
                    state.withdrawn = true;
                    state.barrier_position = Some(crate::home::next_position(db)?);
                    withdraw_admissions(db, &agreement.id.as_hex(), None)?;
                    db.execute(
                        "UPDATE federation_agreements SET withdrawn=1,data=?1 WHERE id=?2",
                        params![encode(&state)?, agreement.id.as_hex()],
                    )?;
                }
                db.execute(
                    "INSERT INTO federation_controls VALUES(?1,?2,?3,?4)",
                    params![
                        request_id.as_hex(),
                        request.digest().as_bytes(),
                        encode(&state)?,
                        t.lower_ms
                    ],
                )?;
                let final_time = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
                if !permit() || !final_time.permits(*created_ms, *expires_ms) {
                    return Err(Fault::Reject(
                        ErrorCode::Unavailable,
                        "WithdrawalAuthorityUnavailable",
                    ));
                }
                Ok(state)
            },
        )
    }
    /// Record a home-signed barrier only after this origin has stopped locally.
    pub fn federation_record_withdrawal_ack(
        &mut self,
        request: &Verified<FederationControl>,
        result: &Verified<FederationControl>,
        clock: TimeBounds,
    ) -> Result<AgreementState> {
        let FederationControl::Request {
            home,
            origin,
            agreement,
            request: request_id,
            operation,
            body,
            created_ms,
            expires_ms,
            ..
        } = request.value()
        else {
            return Err(refused("WithdrawalRequest"));
        };
        let withdrawal: FederationWithdrawal =
            body.deserialized().map_err(|_| refused("WithdrawalBody"))?;
        let FederationControl::Result {
            home: rh,
            origin: ro,
            agreement: ra,
            request: rr,
            operation: op,
            request_digest,
            outcome,
            created_ms: rc,
            expires_ms: re,
            ..
        } = result.value()
        else {
            return Err(refused("WithdrawalResult"));
        };
        if self.home != *origin
            || *operation != Operation::FederationWithdraw
            || withdrawal.agreement != *agreement
            || withdrawal.request != *request_id
            || rh != home
            || ro != origin
            || ra != agreement
            || rr != request_id
            || op != operation
            || *request_digest != request.digest()
            || rc != created_ms
            || re != expires_ms
            || request.signed_bytes().len() > 8192
            || result.signed_bytes().len() > 56 * 1024
        {
            return Err(refused("WithdrawalAcknowledgementBinding"));
        }
        let Outcome::Result { body } = outcome else {
            return Err(refused("WithdrawalNotAcknowledged"));
        };
        let acknowledged: AgreementState = body
            .deserialized()
            .map_err(|_| refused("WithdrawalResult"))?;
        write(
            self,
            &("HRC.Federation.WithdrawAck", result.digest()),
            clock,
            |db, t| {
                let mut state = load(db, agreement.id)?;
                if state.reference != *agreement
                    || state.agreement.home != *home
                    || state.agreement.origin != *origin
                    || request.signer_key() != state.agreement.origin_service_key
                    || result.signer_key() != state.agreement.home_service_key
                    || !state.withdrawn
                    || !acknowledged.withdrawn
                    || acknowledged.reference != state.reference
                    || acknowledged.barrier_position.is_none()
                    || encode(&acknowledged.agreement)? != encode(&state.agreement)?
                    || acknowledged.home_signature != state.home_signature
                    || acknowledged.origin_signature != state.origin_signature
                {
                    return deny("WithdrawalAcknowledgementAuthority");
                }
                if !t.permits(*created_ms, *expires_ms) {
                    return Err(Fault::Reject(
                        ErrorCode::Expired,
                        "WithdrawalRequestExpired",
                    ));
                }
                if state.barrier_position.is_some()
                    && state.barrier_position != acknowledged.barrier_position
                {
                    return conflict("WithdrawalBarrier");
                }
                state.barrier_position = acknowledged.barrier_position;
                db.execute(
                    "UPDATE federation_agreements SET data=?1 WHERE id=?2",
                    params![encode(&state)?, agreement.id.as_hex()],
                )?;
                db.execute("INSERT INTO federation_withdrawal_acks VALUES(?1,?2,?3,?4) ON CONFLICT(agreement) DO UPDATE SET revision=excluded.revision,request=excluded.request,result=excluded.result",
                params![agreement.id.as_hex(),agreement.revision,request.signed_bytes(),result.signed_bytes()])?;
                if !clock
                    .refresh()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .permits(*created_ms, *expires_ms)
                {
                    return Err(Fault::Reject(
                        ErrorCode::Expired,
                        "WithdrawalRequestExpired",
                    ));
                }
                Ok(state)
            },
        )
    }
    pub fn federation_admit(
        &mut self,
        request: &AdmitEndpoint,
        clock: TimeBounds,
    ) -> Result<RemoteAdmission> {
        let home = self.home;
        write(self, "HRC.Federation.Admission", clock, |db, now| {
            let state = current(db, request.agreement, now)?;
            let a = &state.agreement;
            if a.home != home
                || request.account.origin != a.origin.network
                || request.rooms.len() > 32
                || request
                    .rooms
                    .iter()
                    .any(|r| !a.rooms.iter().any(|allowed| allowed.room == *r))
                || request
                    .rooms
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != request.rooms.len()
                || request.expires_ms <= now.upper_ms
                || request.expires_ms > a.expires_ms
                || request.expires_ms - now.lower_ms > 7 * DAY
            {
                return invalid("RemoteAdmissionScope");
            }
            let cp = identities::checkpoint(db, request.checkpoint)?;
            if cp.account != request.account {
                return deny("CheckpointAccount");
            }
            let ep = crate::identity::endpoint(db, request.account, request.endpoint)?
                .ok_or(Fault::Reject(ErrorCode::Denied, "RemoteEndpoint"))?;
            if ep.acting.binding_digest != request.binding_digest
                || !cp.state.endpoints.iter().any(|e| e.actor == ep.acting)
            {
                return deny("RemoteEndpointBinding");
            }
            let old:Option<Vec<u8>>=db.query_row("SELECT data FROM federation_admissions WHERE agreement=?1 AND account=?2 AND endpoint=?3",params![a.id.as_hex(),request.account.to_string(),request.endpoint.as_hex()],|r|r.get(0)).optional()?;
            let (id, revision) = if let Some(bytes) = old {
                let previous: RemoteAdmission = decode(&bytes)?;
                if request.expected_revision.checked_add(1) == Some(previous.reference.revision)
                    && previous.agreement == request.agreement
                    && previous.acting == ep.acting
                    && previous.checkpoint == request.checkpoint
                    && previous.rooms == request.rooms
                    && previous.expires_ms == request.expires_ms
                {
                    if previous.withdrawn {
                        return deny("AdmissionWithdrawn");
                    }
                    return Ok(previous);
                }
                if previous.reference.revision != request.expected_revision {
                    return conflict("AdmissionRevision");
                }
                invalidate(db, &[request.account])?;
                (
                    previous.reference.id,
                    previous
                        .reference
                        .revision
                        .checked_add(1)
                        .ok_or(Fault::Reject(ErrorCode::Conflict, "AdmissionRevision"))?,
                )
            } else {
                if request.expected_revision != 0 {
                    return conflict("AdmissionRevision");
                }
                let count: u64 =
                    db.query_row("SELECT count(*) FROM federation_admissions", [], |r| {
                        r.get(0)
                    })?;
                if count >= 256 {
                    return Err(Fault::Reject(ErrorCode::Overloaded, "AdmissionCapacity"));
                }
                (random()?, 1)
            };
            let admitted = RemoteAdmission {
                reference: AdmissionRef { id, revision },
                home,
                origin: a.origin,
                agreement: request.agreement,
                acting: ep.acting,
                checkpoint: request.checkpoint,
                rooms: request.rooms.clone(),
                not_before_ms: now.lower_ms,
                expires_ms: request.expires_ms,
                withdrawn: false,
            };
            db.execute("INSERT INTO federation_admissions VALUES(?1,?2,?3,?4,?5,?6,0,?7) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,expires=excluded.expires,withdrawn=0,data=excluded.data",params![id.as_hex(),a.id.as_hex(),request.account.to_string(),request.endpoint.as_hex(),revision,request.expires_ms,encode(&admitted)?])?;
            Ok(admitted)
        })
    }
    pub fn federation_withdraw_endpoint(
        &mut self,
        reference: AdmissionRef,
        clock: TimeBounds,
    ) -> Result<()> {
        write(
            self,
            &("HRC.Federation.WithdrawEndpoint", reference),
            clock,
            |db, _| {
                let bytes: Vec<u8> = db.query_row(
                    "SELECT data FROM federation_admissions WHERE id=?1",
                    [reference.id.as_hex()],
                    |r| r.get(0),
                )?;
                let a: RemoteAdmission = decode(&bytes)?;
                if a.reference != reference {
                    return conflict("AdmissionRevision");
                }
                withdraw_admissions(db, &a.agreement.id.as_hex(), Some(&reference.id.as_hex()))?;
                Ok(())
            },
        )
    }
}
