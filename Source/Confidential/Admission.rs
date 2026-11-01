// SPDX-License-Identifier: Apache-2.0
//! Enrol a distinct MLS key and bounded, explicitly requested room admission packages.
use super::{EnrolKey, PublishPackage, authority, representation};
use crate::{
    clock::TimeBounds,
    home::{self, types::*},
    protocol::*,
};
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn enrol(db: &Transaction<'_>, verified: &VerifiedAction) -> Domain<Outcome> {
    let action = verified.action();
    if matches!(action.actor, Actor::Delegated { .. })
        || action.target != Target::Account(action.actor.acting().account)
    {
        return deny("MlsEndpointOwner");
    }
    let request: EnrolKey = unpack(&action.body)?;
    let key = VerifyingKey::from_bytes(request.mls_key.as_bytes())
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "MlsKey"))?;
    let endpoint = crate::identity::endpoint(
        db,
        action.actor.acting().account,
        action.actor.acting().endpoint,
    )?
    .ok_or(Fault::Reject(ErrorCode::Denied, "EndpointDisabled"))?;
    let recovery: Vec<u8> = db.query_row(
        "SELECT recovery FROM hrc_accounts WHERE id=?1",
        [action.actor.acting().account.to_string()],
        |r| r.get(0),
    )?;
    if key.is_weak() || key == endpoint.key || request.mls_key.as_bytes() == recovery.as_slice() {
        return invalid("IndependentMlsKey");
    }
    let old: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT actor,key FROM hrc_mls_keys WHERE account=?1 AND endpoint=?2",
            params![
                action.actor.acting().account.to_string(),
                action.actor.acting().endpoint.as_hex()
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((actor, key)) = old {
        if decode::<EndpointActor>(&actor)? != *action.actor.acting()
            || key != request.mls_key.as_bytes()
        {
            return conflict("ImmutableMlsEndpointKey");
        }
        return home::committed(db, None, Value::Null);
    }
    let duplicate: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_mls_keys WHERE key=?1)",
        [request.mls_key.as_bytes().as_slice()],
        |r| r.get(0),
    )?;
    if duplicate {
        return conflict("MlsKeyAlreadyEnrolled");
    }
    let count: u64 = db.query_row("SELECT count(*) FROM hrc_mls_keys", [], |r| r.get(0))?;
    if count >= 4096 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "MlsEndpointLimit"));
    }
    db.execute(
        "INSERT INTO hrc_mls_keys VALUES(?1,?2,?3,?4,?5)",
        params![
            action.actor.acting().account.to_string(),
            action.actor.acting().endpoint.as_hex(),
            encode(action.actor.acting())?,
            request.mls_key.as_bytes().as_slice(),
            verified.signed_bytes()
        ],
    )?;
    home::committed(db, None, Value::Null)
}

pub(super) fn package(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let room = crate::conversations::target(action)?;
    let request: PublishPackage = unpack(&action.body)?;
    if !authority::eligible(db, room, &action.actor, now)? {
        return deny("EncryptedReadPermission");
    }
    let mode: u8 = db.query_row(
        "SELECT mode FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if mode == 0 {
        return invalid("EncryptedRoomRequired");
    }
    if request.expires_ms <= now.upper_ms || request.expires_ms > now.lower_ms.saturating_add(DAY) {
        return invalid("KeyPackageValidity");
    }
    let member = authority::member(db, room, &action.actor)?;
    let credential = &member.credential;
    crate::crypto::validate_key_package_in(db, &request.package.0, credential)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "KeyPackageBinding"))?;
    let digest = digest(&request.package.0);
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_mls_packages WHERE digest=?1)",
        [digest.as_hex()],
        |r| r.get(0),
    )?;
    if exists {
        return conflict("KeyPackageAlreadyPublished");
    }
    // Replacing an unconsumed request never makes a previously consumed package reusable.
    db.execute(
        "UPDATE hrc_mls_packages SET used=1 WHERE room=?1 AND used=0 AND (endpoint=?2 OR expires<=?3)",
        params![room.to_string(), action.actor.acting().endpoint.as_hex(), now.upper_ms],
    )?;
    let count: u64 = db.query_row(
        "SELECT count(*) FROM hrc_mls_packages WHERE room=?1 AND used=0",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if count >= 64 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "RoomPackageLimit"));
    }
    let total: u64 = db.query_row("SELECT count(*) FROM hrc_mls_packages", [], |r| r.get(0))?;
    if total >= 16384 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "KeyPackageLimit"));
    }
    let actor = encode(&action.actor)?;
    let credential = encode(credential)?;
    let delegation = member.delegation.as_ref().map(encode).transpose()?;
    // The fixed allowance covers canonical field names, scalar values and blob framing.
    let occupied: usize = db.query_row(
        "SELECT coalesce(sum(length(actor)+length(credential)+length(registration)+coalesce(length(delegation),0)+length(package)+256),0) FROM hrc_mls_packages WHERE room=?1 AND used=0",
        [room.to_string()], |r| r.get(0),
    )?;
    let required = actor.len()
        + credential.len()
        + member.registration.0.len()
        + delegation.as_ref().map_or(0, Vec::len)
        + request.package.0.len()
        + 256;
    representation::bounded(&member, ORDINARY_FRAME_BYTES)?;
    if occupied.saturating_add(required) > representation::PACKAGE_BYTES {
        return Err(Fault::Reject(ErrorCode::Overloaded, "RoomPackageBytes"));
    }
    db.execute(
        "INSERT INTO hrc_mls_packages VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
        params![
            digest.as_hex(),
            room.to_string(),
            action.actor.acting().endpoint.as_hex(),
            actor,
            credential,
            member.registration.0,
            delegation,
            request.package.0,
            request.expires_ms
        ],
    )?;
    home::committed(db, None, value(&digest)?)
}
