// SPDX-License-Identifier: Apache-2.0
//! Standard COSE_Sign1 with pinned role headers and strict Ed25519 verification.
use super::{
    CRYPTO_FRAME_BYTES, Error, ORDINARY_FRAME_BYTES, PROTOCOL, Result, VERSION, cbor,
    federation::*, lifecycle::*, types::*,
};
use ciborium::Value;
use coset::{CborSerializable, CoseSign1, CoseSign1Builder, Header, HeaderBuilder, iana};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const AAD: &[u8] = b"HRC/1";
#[derive(Clone, Copy)]
enum Role {
    Action = 1,
    Registration = 2,
    EndpointBinding = 3,
    Challenge = 4,
    Proof = 5,
    Ready = 6,
    Response = 7,
    Event = 8,
    Approval = 9,
    FederationChallenge = 10,
    OriginAssertion = 11,
    Agreement = 12,
    HistoryCursor = 13,
    DeviceRequest = 14,
    DeviceChallenge = 15,
    DeviceProof = 16,
    DeviceReceipt = 17,
    ReplacementKey = 18,
    GatewayMessage = 19,
    RemoteSessionRequest = 20,
    RemoteSessionReady = 21,
    OriginIdentityCheckpoint = 22,
    FederationControl = 23,
    OriginIdentityPage = 24,
    IdentityFreshness = 25,
}
impl Role {
    fn content_type(self) -> &'static str {
        match self {
            Self::Action => "application/hrc-action+cbor;v=1",
            Self::Registration => "application/hrc-registration+cbor;v=1",
            Self::EndpointBinding => "application/hrc-endpoint-binding+cbor;v=1",
            Self::Challenge => "application/hrc-session-challenge+cbor;v=1",
            Self::Proof => "application/hrc-session-proof+cbor;v=1",
            Self::Ready => "application/hrc-session-ready+cbor;v=1",
            Self::Response => "application/hrc-response+cbor;v=1",
            Self::Event => "application/hrc-event+cbor;v=1",
            Self::Approval => "application/hrc-approval+cbor;v=1",
            Self::FederationChallenge => "application/hrc-federation-challenge+cbor;v=1",
            Self::OriginAssertion => "application/hrc-origin-assertion+cbor;v=1",
            Self::Agreement => "application/hrc-agreement+cbor;v=1",
            Self::HistoryCursor => "application/hrc-history-cursor+cbor;v=1",
            Self::DeviceRequest => "application/hrc-device-request+cbor;v=1",
            Self::DeviceChallenge => "application/hrc-device-challenge+cbor;v=1",
            Self::DeviceProof => "application/hrc-device-proof+cbor;v=1",
            Self::DeviceReceipt => "application/hrc-device-receipt+cbor;v=1",
            Self::ReplacementKey => "application/hrc-replacement-key+cbor;v=1",
            Self::GatewayMessage => "application/hrc-gateway-message+cbor;v=1",
            Self::RemoteSessionRequest => "application/hrc-remote-session-request+cbor;v=1",
            Self::RemoteSessionReady => "application/hrc-remote-session-ready+cbor;v=1",
            Self::OriginIdentityCheckpoint => "application/hrc-origin-identity-checkpoint+cbor;v=1",
            Self::FederationControl => "application/hrc-federation-control+cbor;v=1",
            Self::OriginIdentityPage => "application/hrc-origin-identity-page+cbor;v=1",
            Self::IdentityFreshness => "application/hrc-identity-freshness+cbor;v=1",
        }
    }
}

/// Verified key possession and immutable bytes. Domain authorization remains separate.
#[derive(Clone, Debug)]
pub struct Verified<T> {
    object: T,
    payload: Vec<u8>,
    signed: Vec<u8>,
    digest: Id,
    signer_key: Id,
}
impl<T> Verified<T> {
    pub fn value(&self) -> &T {
        &self.object
    }
    pub fn digest(&self) -> Id {
        self.digest
    }
    pub fn signer_key(&self) -> Id {
        self.signer_key
    }
    /// Exact canonical signed payload, suitable for digest and immutable-outcome comparison.
    pub fn bytes(&self) -> &[u8] {
        &self.payload
    }
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }
}
pub type VerifiedAction = Verified<Action>;
impl Verified<Action> {
    pub fn action(&self) -> &Action {
        &self.object
    }
}

pub fn digest(bytes: &[u8]) -> Id {
    Id::from_bytes(Sha256::digest(bytes).into())
}
pub fn key_id(key: &VerifyingKey) -> Id {
    digest(key.as_bytes())
}
/// Unauthenticated bounded routing data only. The caller must still verify role 19
/// using the already accepted gateway key and exact actual transport context.
pub fn gateway_hello_hint(bytes: &[u8]) -> Result<(AgreementRef, Id)> {
    let Value::Array(outer) = cbor::canonical_decode(bytes, 8192)? else {
        return Err(Error::Encoding);
    };
    if outer.len() != 4 {
        return Err(Error::Encoding);
    }
    let Value::Bytes(payload) = &outer[2] else {
        return Err(Error::Encoding);
    };
    let Value::Array(parts) = cbor::canonical_decode(payload, 8192)? else {
        return Err(Error::Encoding);
    };
    let [Value::Integer(version), Value::Integer(role), value] = parts.as_slice() else {
        return Err(Error::Encoding);
    };
    if u64::try_from(*version).map_err(|_| Error::Version)? != VERSION
        || u64::try_from(*role).map_err(|_| Error::Binding)? != 19
    {
        return Err(Error::Binding);
    }
    let hello: GatewayMessage = value.deserialized().map_err(|_| Error::Encoding)?;
    super::federation::check_gateway(&hello)?;
    if let GatewayMessage::Hello {
        agreement, gateway, ..
    } = hello
    {
        Ok((agreement, gateway))
    } else {
        Err(Error::Binding)
    }
}
fn header(role: Role, key: &VerifyingKey) -> Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::Ed25519)
        .content_type(role.content_type().to_owned())
        .key_id(key_id(key).as_bytes().to_vec())
        .build()
}
fn payload<T: Serialize>(role: Role, value: &T, maximum: usize) -> Result<Vec<u8>> {
    let object = Value::serialized(value).map_err(|_| Error::Encoding)?;
    let bytes = cbor::canonical_encode(
        &Value::Array(vec![
            Value::Integer(VERSION.into()),
            Value::Integer((role as u64).into()),
            object,
        ]),
        maximum,
    )?;
    cbor::validate(&bytes, maximum, super::MAX_DEPTH - 2)?;
    Ok(bytes)
}
fn sign<T: Serialize>(role: Role, value: &T, key: &SigningKey, maximum: usize) -> Result<Vec<u8>> {
    let body = payload(role, value, maximum)?;
    let signed = CoseSign1Builder::new()
        .protected(header(role, &key.verifying_key()))
        .payload(body)
        .create_signature(AAD, |data| key.sign(data).to_bytes().to_vec())
        .build();
    let bytes = signed.to_vec().map_err(|_| Error::Encoding)?;
    cbor::validate(&bytes, maximum, super::MAX_DEPTH)?;
    Ok(bytes)
}
fn verify<T: DeserializeOwned + Serialize>(
    role: Role,
    bytes: &[u8],
    key: &VerifyingKey,
    maximum: usize,
) -> Result<Verified<T>> {
    if key.is_weak() {
        return Err(Error::Binding);
    }
    let outer = cbor::canonical_decode(bytes, maximum)?;
    let Value::Array(fields) = outer else {
        return Err(Error::Encoding);
    };
    let [
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(body),
        Value::Bytes(signature),
    ] = fields.as_slice()
    else {
        return Err(Error::Encoding);
    };
    if !unprotected.is_empty() || signature.len() != 64 {
        return Err(Error::Encoding);
    }
    // Inspect embedded CBOR before coset parses it. Comparing the complete protected map
    // rejects unknown, duplicated or unprotected algorithm and role parameters.
    cbor::validate(protected, 512, 2)?;
    if *protected != header(role, key).to_vec().map_err(|_| Error::Encoding)? {
        return Err(Error::Binding);
    }
    let object = cbor::decode_at_depth(body, maximum, super::MAX_DEPTH - 2)?;
    let Value::Array(fields) = object else {
        return Err(Error::Encoding);
    };
    let [Value::Integer(version), Value::Integer(kind), object] = fields.as_slice() else {
        return Err(Error::Encoding);
    };
    if u64::try_from(*version).map_err(|_| Error::Version)? != VERSION {
        return Err(Error::Version);
    }
    if u64::try_from(*kind).map_err(|_| Error::Binding)? != role as u64 {
        return Err(Error::Binding);
    }
    let signed = CoseSign1::from_slice(bytes).map_err(|_| Error::Encoding)?;
    signed.verify_signature(AAD, |signature, data| {
        let signature = Signature::from_slice(signature).map_err(|_| Error::Signature)?;
        key.verify_strict(data, &signature)
            .map_err(|_| Error::Signature)
    })?;
    let decoded: T = object.deserialized().map_err(|_| Error::Encoding)?;
    // Missing optional fields and noncanonical typed representations are not extensions.
    // This comparison validates shape; verification above used the original payload bytes.
    if payload(role, &decoded, maximum)? != *body {
        return Err(Error::Encoding);
    }
    Ok(Verified {
        object: decoded,
        payload: body.clone(),
        signed: bytes.to_vec(),
        digest: digest(body),
        signer_key: Id::from_bytes(key.to_bytes()),
    })
}
fn check_key(key: Id) -> Result<()> {
    let key = VerifyingKey::from_bytes(key.as_bytes()).map_err(|_| Error::Invalid)?;
    if key.is_weak() {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn check_registration(r: &AccountRegistration) -> Result<()> {
    if r.account.origin != r.home.network {
        return Err(Error::Binding);
    }
    check_key(r.endpoint_key)?;
    check_key(r.recovery_key)
}
fn check_binding(b: &EndpointBinding) -> Result<()> {
    if b.account.origin != b.origin.network
        || b.security_generation == 0
        || b.enrolment_generation == 0
        || b.not_before_ms >= b.expires_ms
    {
        return Err(Error::Invalid);
    }
    check_key(b.endpoint_key)
}
pub fn binding_digest(binding: &EndpointBinding) -> Result<Id> {
    check_binding(binding)?;
    Ok(digest(&payload(
        Role::EndpointBinding,
        binding,
        ORDINARY_FRAME_BYTES - 1,
    )?))
}
fn check_response(r: &Response) -> Result<()> {
    match &r.outcome {
        Outcome::Committed { position, .. } if *position == 0 => Err(Error::Invalid),
        Outcome::Rejected { detail, .. } | Outcome::Refused { detail, .. }
            if detail.is_empty()
                || detail.len() > 64
                || !detail
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) =>
        {
            Err(Error::Invalid)
        }
        Outcome::Refused {
            retry_after_ms: Some(delay),
            ..
        } if *delay > 60_000 => Err(Error::Invalid),
        _ => Ok(()),
    }
}
fn check_event(e: &Event) -> Result<()> {
    if e.room.home != e.home || e.sequence == 0 {
        return Err(Error::Binding);
    }
    e.actor.validate()
}

pub fn sign_action(action: &Action, key: &SigningKey) -> Result<Vec<u8>> {
    action.validate()?;
    sign(
        Role::Action,
        action,
        key,
        if action.operation.is_crypto_transition() {
            CRYPTO_FRAME_BYTES - 1
        } else {
            ORDINARY_FRAME_BYTES - 1
        },
    )
}
pub fn verify_action(bytes: &[u8], key: &VerifyingKey) -> Result<VerifiedAction> {
    let value: VerifiedAction = verify(Role::Action, bytes, key, CRYPTO_FRAME_BYTES - 1)?;
    value.action().validate()?;
    if !value.action().operation.is_crypto_transition() && bytes.len() >= ORDINARY_FRAME_BYTES {
        return Err(Error::Limit);
    }
    Ok(value)
}
pub fn action_bytes(action: &Action) -> Result<Vec<u8>> {
    action.validate()?;
    payload(
        Role::Action,
        action,
        if action.operation.is_crypto_transition() {
            CRYPTO_FRAME_BYTES - 1
        } else {
            ORDINARY_FRAME_BYTES - 1
        },
    )
}
pub fn action_digest(action: &Action) -> Result<Id> {
    Ok(digest(&action_bytes(action)?))
}

macro_rules! object_api {
    ($sign:ident,$verify:ident,$ty:ty,$role:ident,$check:expr) => {
        pub fn $sign(value: &$ty, key: &SigningKey) -> Result<Vec<u8>> {
            ($check)(value)?;
            sign(Role::$role, value, key, ORDINARY_FRAME_BYTES - 1)
        }
        pub fn $verify(bytes: &[u8], key: &VerifyingKey) -> Result<Verified<$ty>> {
            let value: Verified<$ty> = verify(Role::$role, bytes, key, ORDINARY_FRAME_BYTES - 1)?;
            ($check)(value.value())?;
            Ok(value)
        }
    };
}
object_api!(
    sign_endpoint_binding,
    verify_endpoint_binding,
    EndpointBinding,
    EndpointBinding,
    check_binding
);
object_api!(
    sign_challenge,
    verify_challenge,
    SessionChallenge,
    Challenge,
    |v: &SessionChallenge| if v.expires_ms == 0 {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
);
object_api!(
    sign_proof,
    verify_proof,
    SessionProof,
    Proof,
    |_: &SessionProof| Ok(())
);
object_api!(
    sign_ready,
    verify_ready,
    SessionReady,
    Ready,
    |v: &SessionReady| {
        if v.maximum_frame_bytes != ORDINARY_FRAME_BYTES as u64
            || v.maximum_crypto_frame_bytes != CRYPTO_FRAME_BYTES as u64
            || v.window.expires_ms == 0
            || v.account_revision == 0
            || v.acting.security_generation == 0
            || v.acting.enrolment_generation == 0
            || v.acting.binding_digest != v.binding_digest
            || v.capabilities.len() > 16
            || v.capabilities
                .iter()
                .any(|s| s.is_empty() || s.len() > 64 || !s.bytes().all(|c| c.is_ascii_graphic()))
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
);
object_api!(
    sign_response,
    verify_response,
    Response,
    Response,
    check_response
);
/// The caller must correlate this larger response with an admitted crypto operation.
pub fn sign_crypto_response(value: &Response, key: &SigningKey) -> Result<Vec<u8>> {
    check_response(value)?;
    sign(Role::Response, value, key, CRYPTO_FRAME_BYTES - 1)
}
pub fn verify_crypto_response(bytes: &[u8], key: &VerifyingKey) -> Result<Verified<Response>> {
    let value: Verified<Response> = verify(Role::Response, bytes, key, CRYPTO_FRAME_BYTES - 1)?;
    check_response(value.value())?;
    Ok(value)
}
pub fn sign_registration(value: &AccountRegistration, key: &SigningKey) -> Result<Vec<u8>> {
    check_registration(value)?;
    if value.endpoint_key.as_bytes() != key.verifying_key().as_bytes() {
        return Err(Error::Binding);
    }
    sign(Role::Registration, value, key, ORDINARY_FRAME_BYTES - 1)
}
pub fn verify_registration(
    bytes: &[u8],
    key: &VerifyingKey,
) -> Result<Verified<AccountRegistration>> {
    let value: Verified<AccountRegistration> =
        verify(Role::Registration, bytes, key, ORDINARY_FRAME_BYTES - 1)?;
    check_registration(value.value())?;
    if value.value().endpoint_key.as_bytes() != key.as_bytes() {
        return Err(Error::Binding);
    }
    Ok(value)
}
pub fn sign_event(value: &Event, key: &SigningKey) -> Result<Vec<u8>> {
    check_event(value)?;
    sign(
        Role::Event,
        value,
        key,
        if value.kind.is_crypto_transition() {
            CRYPTO_FRAME_BYTES - 1
        } else {
            ORDINARY_FRAME_BYTES - 1
        },
    )
}
pub fn verify_event(bytes: &[u8], key: &VerifyingKey) -> Result<Verified<Event>> {
    let value: Verified<Event> = verify(Role::Event, bytes, key, CRYPTO_FRAME_BYTES - 1)?;
    check_event(value.value())?;
    if !value.value().kind.is_crypto_transition() && bytes.len() >= ORDINARY_FRAME_BYTES {
        return Err(Error::Limit);
    }
    Ok(value)
}
pub fn encode_hello(value: &SessionHello) -> Result<Vec<u8>> {
    value.validate()?;
    super::canonical_encode(
        &Value::Array(vec![
            Value::Integer(VERSION.into()),
            Value::serialized(value).map_err(|_| Error::Encoding)?,
        ]),
        4096,
    )
}
pub fn decode_hello(bytes: &[u8]) -> Result<SessionHello> {
    let value = super::canonical_decode(bytes, 4096)?;
    let Value::Array(fields) = value else {
        return Err(Error::Encoding);
    };
    let [Value::Integer(version), value] = fields.as_slice() else {
        return Err(Error::Encoding);
    };
    if u64::try_from(*version).map_err(|_| Error::Version)? != VERSION {
        return Err(Error::Version);
    }
    let hello: SessionHello = value.deserialized().map_err(|_| Error::Encoding)?;
    hello.validate()?;
    if encode_hello(&hello)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(hello)
}

object_api!(
    sign_cursor,
    verify_cursor,
    HistoryCursor,
    HistoryCursor,
    |v: &HistoryCursor| {
        if v.room.home != v.home || v.membership_revision == 0 || v.expires_ms == 0 {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
);
object_api!(
    sign_approval,
    verify_approval,
    Approval,
    Approval,
    |v: &Approval| {
        if v.owner.security_generation == 0
            || v.owner.enrolment_generation == 0
            || v.grant.generation == 0
            || v.expires_ms == 0
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
);
object_api!(
    sign_federation_challenge,
    verify_federation_challenge,
    FederationChallenge,
    FederationChallenge,
    |v: &FederationChallenge| {
        if v.profile != FEDERATION_PROFILE
            || v.admission.revision == 0
            || v.home.network == v.origin.network
            || v.agreement.revision == 0
            || v.expires_ms <= v.issued_ms
            || v.expires_ms - v.issued_ms > 5000
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
);
object_api!(
    sign_origin_assertion,
    verify_origin_assertion,
    OriginAssertion,
    OriginAssertion,
    |v: &OriginAssertion| {
        if v.profile != FEDERATION_PROFILE
            || v.admission.revision == 0
            || v.checkpoints.is_empty()
            || v.checkpoints.len() > 3
            || v.checkpoints
                .windows(2)
                .any(|p| p[0].account >= p[1].account)
            || v.source_privacy.validate().is_err()
            || v.home.network == v.origin.network
            || v.transport_network != v.origin.network
            || v.agreement.revision == 0
            || v.security_generation == 0
            || v.enrolment_generation == 0
            || v.control_generation == 0
            || v.source_not_after_ms <= v.source_evaluated_ms
            || v.source_not_after_ms - v.source_evaluated_ms > 5000
            || v.source_uncertainty_ms > 250
            || v.authority.expires_at_ms <= v.authority.evaluated_at_ms
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
);
fn check_agreement(v: &FederationAgreement) -> Result<()> {
    if v.profile != FEDERATION_PROFILE
        || v.home.network == v.origin.network
        || v.revision == 0
        || v.expires_ms <= v.not_before_ms
        || v.rooms.len() > 32
    {
        return Err(Error::Invalid);
    }
    check_key(v.home_service_key)?;
    check_key(v.origin_service_key)?;
    check_key(v.origin_attestor_key)?;
    for (g, receiver) in [(&v.home_gateway, v.home), (&v.origin_gateway, v.origin)] {
        check_key(g.signing_key)?;
        if g.network != receiver.network || g.destination != receiver || g.protocol != PROTOCOL {
            return Err(Error::Binding);
        }
    }
    for (i, room) in v.rooms.iter().enumerate() {
        if room.room.home != v.home
            || room.retention_ms == 0
            || room.moderator_accounts.len() > 32
            || v.rooms[..i].iter().any(|other| other.room == room.room)
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
object_api!(
    sign_agreement,
    verify_agreement,
    FederationAgreement,
    Agreement,
    check_agreement
);
fn validate_forwarded(bytes: &[u8], maximum: usize) -> Result<()> {
    let object = cbor::decode_at_depth(bytes, maximum, super::MAX_DEPTH - 3)?;
    let Value::Array(fields) = object else {
        return Err(Error::Encoding);
    };
    let [
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(payload),
        Value::Bytes(signature),
    ] = fields.as_slice()
    else {
        return Err(Error::Encoding);
    };
    if !unprotected.is_empty() || signature.len() != 64 {
        return Err(Error::Encoding);
    }
    cbor::validate(protected, 512, 2)?;
    cbor::validate(payload, maximum, super::MAX_DEPTH - 5)
}
pub fn encode_federation(value: &FederationEnvelope) -> Result<Vec<u8>> {
    if value.profile != FEDERATION_PROFILE
        || value.admission.revision == 0
        || value.agreement.revision == 0
    {
        return Err(Error::Invalid);
    }
    validate_forwarded(&value.action.0, CRYPTO_FRAME_BYTES - 1)?;
    for bytes in [
        &value.endpoint_binding,
        &value.challenge,
        &value.origin_assertion,
    ] {
        validate_forwarded(&bytes.0, ORDINARY_FRAME_BYTES - 1)?;
    }
    super::canonical_encode(
        &Value::Array(vec![
            Value::Integer(VERSION.into()),
            Value::serialized(value).map_err(|_| Error::Encoding)?,
        ]),
        CRYPTO_FRAME_BYTES - 1,
    )
}
pub fn decode_federation(bytes: &[u8]) -> Result<FederationEnvelope> {
    let value = super::canonical_decode(bytes, CRYPTO_FRAME_BYTES - 1)?;
    let Value::Array(fields) = value else {
        return Err(Error::Encoding);
    };
    let [Value::Integer(version), value] = fields.as_slice() else {
        return Err(Error::Encoding);
    };
    if u64::try_from(*version).map_err(|_| Error::Version)? != VERSION {
        return Err(Error::Version);
    }
    let envelope: FederationEnvelope = value.deserialized().map_err(|_| Error::Encoding)?;
    if encode_federation(&envelope)? != bytes {
        return Err(Error::Encoding);
    }
    Ok(envelope)
}

/// Verify possession of the registration's self-selected endpoint key. An invitation
/// and explicit controller or administrator admission are still required.
pub fn verify_registration_request(bytes: &[u8]) -> Result<Verified<AccountRegistration>> {
    let outer = cbor::canonical_decode(bytes, ORDINARY_FRAME_BYTES - 1)?;
    let Value::Array(fields) = outer else {
        return Err(Error::Encoding);
    };
    let [
        Value::Bytes(_),
        Value::Map(_),
        Value::Bytes(body),
        Value::Bytes(_),
    ] = fields.as_slice()
    else {
        return Err(Error::Encoding);
    };
    let body = cbor::decode_at_depth(body, ORDINARY_FRAME_BYTES - 1, super::MAX_DEPTH - 2)?;
    let Value::Array(parts) = body else {
        return Err(Error::Encoding);
    };
    let [Value::Integer(version), Value::Integer(role), object] = parts.as_slice() else {
        return Err(Error::Encoding);
    };
    if u64::try_from(*version).map_err(|_| Error::Version)? != VERSION {
        return Err(Error::Version);
    }
    if u64::try_from(*role).map_err(|_| Error::Binding)? != Role::Registration as u64 {
        return Err(Error::Binding);
    }
    let registration: AccountRegistration = object.deserialized().map_err(|_| Error::Encoding)?;
    let key = VerifyingKey::from_bytes(registration.endpoint_key.as_bytes())
        .map_err(|_| Error::Invalid)?;
    verify_registration(bytes, &key)
}

object_api!(
    sign_device_request,
    verify_device_request,
    DeviceRequest,
    DeviceRequest,
    |v: &DeviceRequest| {
        if v.account.origin != v.home.network
            || v.expires_ms <= v.created_ms
            || v.expires_ms - v.created_ms > 86_400_000
            || (v.purpose == DevicePurpose::RotateRecovery) != v.replacement.is_some()
        {
            return Err(Error::Invalid);
        }
        if let Some(proof) = &v.replacement {
            let replacement = verify_new_recovery_key(&proof.0)?;
            let p = replacement.value();
            if p.home != v.home || p.account != v.account || p.request != v.request {
                return Err(Error::Invalid);
            }
        }
        check_key(v.endpoint_key)
    }
);
object_api!(
    sign_device_challenge,
    verify_device_challenge,
    DeviceChallenge,
    DeviceChallenge,
    |v: &DeviceChallenge| {
        if v.account.origin != v.home.network
            || v.security_generation == 0
            || v.recovery_generation == 0
            || v.transport_generation == 0
            || v.expires_ms <= v.issued_ms
            || v.expires_ms - v.issued_ms > 5000
        {
            return Err(Error::Invalid);
        }
        check_key(v.recovery_key)
    }
);
object_api!(
    sign_device_proof,
    verify_device_proof,
    DeviceProof,
    DeviceProof,
    |v: &DeviceProof| {
        if v.account.origin != v.home.network {
            Err(Error::Binding)
        } else {
            Ok(())
        }
    }
);
object_api!(
    sign_device_receipt,
    verify_device_receipt,
    DeviceReceipt,
    DeviceReceipt,
    |v: &DeviceReceipt| {
        if v.account.origin != v.home.network {
            return Err(Error::Binding);
        }
        check_response(&Response {
            home: v.home,
            operation_id: OperationId {
                window: v.request,
                operation: v.request,
            },
            action_digest: v.request_digest,
            outcome: v.outcome.clone(),
        })
    }
);
object_api!(
    sign_replacement_key,
    verify_replacement_key,
    ReplacementKeyProof,
    ReplacementKey,
    |v: &ReplacementKeyProof| {
        if v.account.origin != v.home.network {
            return Err(Error::Binding);
        }
        check_key(v.key)
    }
);
fn self_selected<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = cbor::decode_at_depth(bytes, ORDINARY_FRAME_BYTES, super::MAX_DEPTH)?;
    let Value::Array(parts) = value else {
        return Err(Error::Encoding);
    };
    let [_, _, Value::Bytes(payload), _] = parts.as_slice() else {
        return Err(Error::Encoding);
    };
    let value = cbor::decode_at_depth(payload, ORDINARY_FRAME_BYTES, super::MAX_DEPTH - 2)?;
    let Value::Array(parts) = value else {
        return Err(Error::Encoding);
    };
    let [_, _, body] = parts.as_slice() else {
        return Err(Error::Encoding);
    };
    body.deserialized().map_err(|_| Error::Encoding)
}
/// This proves only the proposed endpoint's key possession; admission is a separate boundary.
pub fn verify_new_device(bytes: &[u8]) -> Result<Verified<DeviceRequest>> {
    let value: DeviceRequest = self_selected(bytes)?;
    let key =
        VerifyingKey::from_bytes(value.endpoint_key.as_bytes()).map_err(|_| Error::Invalid)?;
    verify_device_request(bytes, &key)
}
pub fn verify_new_recovery_key(bytes: &[u8]) -> Result<Verified<ReplacementKeyProof>> {
    let value: ReplacementKeyProof = self_selected(bytes)?;
    let key = VerifyingKey::from_bytes(value.key.as_bytes()).map_err(|_| Error::Invalid)?;
    let verified = verify_replacement_key(bytes, &key)?;
    if verified.signer_key() != value.key {
        return Err(Error::Binding);
    };
    Ok(verified)
}

object_api!(
    sign_gateway_message,
    verify_gateway_message,
    GatewayMessage,
    GatewayMessage,
    super::federation::check_gateway
);
object_api!(
    sign_remote_session_request,
    verify_remote_session_request,
    RemoteSessionRequest,
    RemoteSessionRequest,
    super::federation::check_session_request
);
object_api!(
    sign_remote_session_ready,
    verify_remote_session_ready,
    RemoteSessionReady,
    RemoteSessionReady,
    super::federation::check_session_ready
);
object_api!(
    sign_origin_identity_checkpoint,
    verify_origin_identity_checkpoint,
    OriginIdentityCheckpoint,
    OriginIdentityCheckpoint,
    super::federation::check_checkpoint
);
object_api!(
    sign_federation_control,
    verify_federation_control,
    FederationControl,
    FederationControl,
    super::federation::check_control
);
object_api!(
    sign_origin_identity_page,
    verify_origin_identity_page,
    OriginIdentityPage,
    OriginIdentityPage,
    super::federation::check_page
);
object_api!(
    sign_identity_freshness,
    verify_identity_freshness,
    IdentityFreshness,
    IdentityFreshness,
    super::federation::check_freshness
);
