// SPDX-License-Identifier: Apache-2.0
//! Explicit bilateral authority. Network I/O belongs to the service adapter.
#[path = "Agreements.rs"]
mod agreements;
#[path = "Exchange.rs"]
mod exchange;
#[path = "Freshness.rs"]
mod freshness;
#[path = "Identities.rs"]
mod identities;
#[path = "Origin.rs"]
mod origin;
#[path = "Schema.rs"]
mod schema;
use crate::{
    clock::TimeBounds,
    home::{Home, types::*},
    protocol::*,
    storage::{self, Commit},
};
pub(crate) use agreements::{actor_admitted, admission, current, expire_in, recipient_admitted};
pub use exchange::VerifiedRemoteSubmission;
pub(crate) use exchange::{authenticate_in, constrain, consume_in, final_check, record_creation};
pub use freshness::{OriginWatchPage, WatchedIdentity};
pub(crate) use freshness::{mark_identity_changed, recipient_fresh, reset_freshness};
pub use identities::{IdentityImport, OriginSubject, SourceSubject, TrustAnchor};
pub(crate) use identities::{foreign_identity, foreign_page};
use rusqlite::{Connection, Transaction};
pub(crate) use schema::initialize;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("federation storage unavailable")]
    Storage(#[from] storage::Error),
    #[error("invalid federation evidence")]
    Protocol(#[from] crate::protocol::Error),
    #[error("{detail}")]
    Refused {
        code: ErrorCode,
        detail: &'static str,
    },
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.into())
    }
}
fn refused(detail: &'static str) -> Error {
    Error::Refused {
        code: ErrorCode::Denied,
        detail,
    }
}
fn convert(error: Fault) -> Error {
    match error {
        Fault::Sql(e) => e.into(),
        Fault::Reject(code, detail) => Error::Refused { code, detail },
    }
}
fn key(id: Id) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(id.as_bytes()).map_err(|_| refused("FederationKey"))
}
fn now(clock: TimeBounds) -> Result<TimeBounds> {
    clock.refresh().map_err(|_| Error::Refused {
        code: ErrorCode::Unavailable,
        detail: "ClockUnavailable",
    })
}
fn write<T: Serialize>(
    home: &mut Home,
    change: &(impl Serialize + ?Sized),
    clock: TimeBounds,
    operation: impl FnOnce(&Transaction<'_>, TimeBounds) -> Domain<T>,
) -> Result<T> {
    let sampled = now(clock)?;
    let result = home.store.write(|db| {
        let floor: u64 = db.query_row(
            "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if sampled.after_floor(floor).is_err() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        db.execute_batch("SAVEPOINT hrc_domain_effects")?;
        let value = match operation(db, sampled) {
            Ok(v) => {
                db.execute_batch("RELEASE hrc_domain_effects")?;
                Ok(v)
            }
            Err(Fault::Reject(c, d)) => {
                db.execute_batch("ROLLBACK TO hrc_domain_effects; RELEASE hrc_domain_effects")?;
                Err((c, d))
            }
            Err(Fault::Sql(e)) => return Err(e),
        };
        let final_time = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
        db.execute(
            "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
            [final_time.lower_ms],
        )?;
        let record = encode(&(change, &value, final_time.lower_ms))?;
        Ok(Commit::new(value, record))
    })?;
    result.map_err(|(code, detail)| Error::Refused { code, detail })
}

/// Administrative trust pins come from independently accepted local configuration.
#[derive(Clone, Debug)]
pub struct AgreementPins {
    pub home: ServiceId,
    pub origin: ServiceId,
    pub home_key: Id,
    pub origin_key: Id,
    pub origin_attestor: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgreementState {
    pub reference: AgreementRef,
    pub agreement: FederationAgreement,
    pub home_signature: Blob,
    pub origin_signature: Blob,
    pub withdrawn: bool,
    pub barrier_position: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteAdmission {
    pub reference: AdmissionRef,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub acting: EndpointActor,
    pub checkpoint: Id,
    pub rooms: Vec<RoomId>,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub withdrawn: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmitEndpoint {
    pub agreement: AgreementRef,
    pub account: AccountId,
    pub endpoint: Id,
    pub binding_digest: Id,
    pub checkpoint: Id,
    pub rooms: Vec<RoomId>,
    pub expires_ms: u64,
    pub expected_revision: u64,
}

/// Actual receiving-stream context; this is not accepted as a wire object.
#[derive(Clone, Debug)]
pub struct GatewayTransport {
    pub network: NetworkId,
    pub destination: ServiceId,
    pub principal: Id,
    pub service_endpoint: Id,
    pub session: Id,
    pub generation: u64,
}
#[derive(Clone, Debug)]
pub struct GatewayContext {
    pub(crate) agreement: AgreementRef,
    pub(crate) transport: GatewayTransport,
}
impl GatewayContext {
    /// Verify role-separated possession against both the accepted agreement and actual stream.
    /// The service also owns the challenge nonce and fresh HyperNet check for this stream.
    pub fn verify(
        agreement: &Verified<FederationAgreement>,
        transport: GatewayTransport,
        challenge: &Verified<GatewayMessage>,
        proof: &Verified<GatewayMessage>,
        clock: TimeBounds,
    ) -> Result<Self> {
        let a = agreement.value();
        let receiver = transport.destination;
        if agreement.signer_key() != a.home_service_key
            && agreement.signer_key() != a.origin_service_key
        {
            return Err(refused("AgreementSigner"));
        }
        let g = if receiver == a.home {
            &a.home_gateway
        } else if receiver == a.origin {
            &a.origin_gateway
        } else {
            return Err(refused("GatewayReceiver"));
        };
        let reference = AgreementRef {
            id: a.id,
            revision: a.revision,
            digest: agreement.digest(),
        };
        let service_key = if receiver == a.home {
            a.home_service_key
        } else {
            a.origin_service_key
        };
        if transport.network != g.network
            || transport.principal != g.principal
            || transport.service_endpoint != g.service_endpoint
            || transport.generation == 0
            || challenge.signer_key() != service_key
            || proof.signer_key() != g.signing_key
        {
            return Err(refused("GatewayBinding"));
        }
        let GatewayMessage::Challenge {
            agreement: ca,
            gateway,
            receiver: cr,
            principal,
            session,
            transport_generation,
            issued_ms,
            expires_ms,
            ..
        } = challenge.value()
        else {
            return Err(refused("GatewayChallenge"));
        };
        let GatewayMessage::Proof {
            agreement: pa,
            challenge_digest,
            ..
        } = proof.value()
        else {
            return Err(refused("GatewayProof"));
        };
        if *ca != reference
            || *pa != reference
            || *gateway != g.principal
            || *cr != receiver
            || *principal != g.principal
            || *session != transport.session
            || *transport_generation != transport.generation
            || *challenge_digest != challenge.digest()
            || !now(clock)?.permits(*issued_ms, *expires_ms)
        {
            return Err(refused("GatewayChallenge"));
        }
        Ok(Self {
            agreement: reference,
            transport,
        })
    }
    pub fn agreement(&self) -> AgreementRef {
        self.agreement
    }
    pub fn principal(&self) -> Id {
        self.transport.principal
    }
}

pub(crate) fn invalidate(db: &Transaction<'_>, accounts: &[AccountId]) -> rusqlite::Result<()> {
    for account in accounts {
        let rows=db.prepare("SELECT id,grant_data FROM hrc_grants WHERE state=0 AND (owner=?1 OR agent=?1 OR operator=?1) LIMIT 1025")?.query_map([account.to_string()],|r|Ok((r.get::<_,String>(0)?,decode::<crate::delegation::Grant>(&r.get::<_,Vec<u8>>(1)?)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 1024 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        for (id, mut grant) in rows {
            if grant.owner != *account
                && grant.operator != *account
                && grant.scope.agent.account != *account
            {
                continue;
            }
            grant.state = crate::delegation::State::Paused;
            grant.reference.generation = grant
                .reference
                .generation
                .checked_add(1)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            db.execute(
                "UPDATE hrc_grants SET state=1,generation=?1,grant_data=?2 WHERE id=?3",
                rusqlite::params![grant.reference.generation, encode(&grant)?, id],
            )?;
            db.execute(
                "UPDATE hrc_approvals SET state=2 WHERE grant_id=?1 AND state<2",
                [id],
            )?;
        }
    }
    crate::confidential::invalidate_accounts(db, accounts)
}

pub(crate) fn is_foreign(db: &Connection, account: AccountId) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM federation_identities WHERE account=?1)",
        [account.to_string()],
        |r| r.get(0),
    )
}
