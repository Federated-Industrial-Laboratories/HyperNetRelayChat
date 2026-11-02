// SPDX-License-Identifier: Apache-2.0
//! Shared operation lifecycle for every HRC frontend and deterministic service bot.
use super::{
    Profile,
    network::{self, Session},
    outbox,
};
use crate::{protocol::*, service::files, storage::Store};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("private endpoint configuration is unavailable")]
    Configuration,
    #[error("client storage is unavailable")]
    Storage,
    #[error("current clock observation is unavailable")]
    Clock,
    #[error("invalid operation request")]
    Input,
    #[error(transparent)]
    Network(#[from] network::Error),
    #[error("client is offline")]
    Offline,
    #[error("operation refused: {detail}")]
    Rejected { code: ErrorCode, detail: String },
    #[error("operation was not admitted: {detail}")]
    Refused {
        code: ErrorCode,
        detail: String,
        retry_after_ms: Option<u64>,
    },
    #[error("an operation outcome remains unknown")]
    Unknown,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "ClientConfigurationUnavailable",
            Self::Storage => "ClientStorageUnavailable",
            Self::Clock => "ClockUnavailable",
            Self::Input => "InvalidOperation",
            Self::Network(error) => error.code(),
            Self::Unknown => "OutcomeUnknown",
            Self::Offline => "Offline",
            Self::Rejected {
                code: ErrorCode::Denied,
                ..
            }
            | Self::Refused {
                code: ErrorCode::Denied,
                ..
            } => "OperationDenied",
            Self::Rejected {
                code: ErrorCode::Expired,
                ..
            }
            | Self::Refused {
                code: ErrorCode::Expired,
                ..
            } => "OperationExpired",
            Self::Rejected { .. } => "OperationRefused",
            Self::Refused { .. } if self.retry_delay_ms().is_some() => {
                "OperationTemporarilyUnavailable"
            }
            Self::Refused { .. } => "OperationRefused",
        }
    }
    pub(crate) fn from_outcome(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Refused {
                code,
                detail,
                retry_after_ms,
            } => Self::Refused {
                code,
                detail,
                retry_after_ms,
            },
            Outcome::Rejected { code, detail } => Self::Rejected { code, detail },
            _ => Self::Unknown,
        }
    }
    /// A verified temporary service or forwarding refusal leaves the session synchronized.
    /// This permits bounded recovery, not stale authority or a replacement operation.
    pub fn can_reuse_session(&self) -> bool {
        matches!(
            self,
            Self::Refused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            } | Self::Network(network::Error::ForwardRefused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            })
        )
    }
    /// Reconnection may resolve exact retained effects; it never creates a replacement action.
    pub(crate) fn retry_delay_ms(&self) -> Option<u64> {
        use network::Error as Network;
        match self {
            Self::Clock | Self::Unknown => Some(0),
            Self::Refused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                retry_after_ms,
                ..
            }
            | Self::Network(Network::ForwardRefused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                retry_after_ms,
                ..
            }) => Some(retry_after_ms.unwrap_or(1000).min(60000)),
            Self::Network(error) if error.retryable_session() => Some(0),
            _ => None,
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Client {
    pub profile: Profile,
    pub store: Store,
    pub(super) key: SigningKey,
    session: Option<Session>,
    directory: std::path::PathBuf,
}
impl Client {
    pub fn open_offline(directory: &Path) -> Result<Self> {
        let profile = Profile::load(directory).map_err(|_| Error::Configuration)?;
        let key = files::key(&directory.join("Endpoint.key")).map_err(|_| Error::Configuration)?;
        let store = profile.store(directory).map_err(|_| Error::Storage)?;
        let mut client = Self {
            profile,
            store,
            key,
            session: None,
            directory: directory.to_owned(),
        };
        super::cache::initialize(&mut client.store, client.profile.server.home)
            .map_err(|_| Error::Storage)?;
        crate::crypto::initialize(&mut client.store).map_err(|_| Error::Storage)?;
        super::archive::initialize(&mut client.store).map_err(|_| Error::Storage)?;
        super::cache::maintain(&mut client.store).map_err(|_| Error::Storage)?;
        Ok(client)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        let mut client = Self::open_offline(directory)?;
        client.connect()?;
        Ok(client)
    }
    pub fn session(&self) -> Result<&Session> {
        self.session.as_ref().ok_or(Error::Offline)
    }
    pub fn connect(&mut self) -> Result<()> {
        self.disconnect();
        let session = Session::open(&self.profile, &self.key)?;
        outbox::retain(
            &mut self.store,
            self.profile.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(|_| Error::Storage)?;
        self.session = Some(session);
        Ok(())
    }
    pub fn disconnect(&mut self) {
        if let Some(session) = self.session.take() {
            session.close();
        }
    }
    pub fn select_service(&mut self, agreement: Option<AgreementRef>) -> Result<()> {
        let mut profile = self.profile.clone();
        profile.federation = agreement;
        profile.validate_federation().map_err(|_| Error::Input)?;
        self.disconnect();
        super::federation::save(&self.directory, &profile).map_err(|_| Error::Storage)?;
        self.profile = profile;
        Ok(())
    }
    pub fn prepare(&self, operation: Operation, target: Target, body: Value) -> Result<Action> {
        Ok(self.session()?.action(operation, target, body)?)
    }
    pub fn execute(&mut self, action: &Action) -> Result<Response> {
        let bytes = self.sign(action)?;
        self.execute_signed(&bytes)
    }
    pub fn sign(&self, action: &Action) -> Result<Vec<u8>> {
        if action.home != self.profile.active_server().home
            || action.actor.acting() != &self.session()?.ready.acting
        {
            return Err(Error::Input);
        }
        sign_action(action, &self.key).map_err(|_| Error::Input)
    }
    pub fn execute_signed(&mut self, bytes: &[u8]) -> Result<Response> {
        let verified = verify_action(bytes, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        if crate::home::is_read_operation(verified.action().operation) {
            return Ok(self
                .session()?
                .submit(bytes, &self.key.verifying_key())?
                .value()
                .clone());
        }
        self.validate_message_mode(verified.action())?;
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        let window = self.session()?.ready.window.clone();
        outbox::prepare(&mut self.store, &verified, &window, now).map_err(|_| Error::Storage)?;
        let response = self.session()?.submit(bytes, &self.key.verifying_key())?;
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        outbox::record(&mut self.store, &verified, &response, now).map_err(|_| Error::Storage)?;
        Ok(response.value().clone())
    }
    pub fn call<T: serde::Serialize>(
        &mut self,
        operation: Operation,
        target: Target,
        body: &T,
    ) -> Result<Response> {
        let body = Value::serialized(body).map_err(|_| Error::Input)?;
        let action = self.prepare(operation, target, body)?;
        self.execute(&action)
    }
    pub fn pending(&mut self) -> Result<Vec<outbox::Pending>> {
        let home = self.profile.active_server().home;
        Ok(outbox::pending(&mut self.store, &self.key.verifying_key())
            .map_err(|_| Error::Storage)?
            .into_iter()
            .filter(|p| p.action.action().home == home)
            .collect())
    }
    /// Resolve original identities before retrying any effect. No replacement operation is created.
    pub fn resolve_pending(&mut self) -> Result<Vec<Response>> {
        self.pending()?
            .into_iter()
            .filter(|p| !p.abandoned && !p.held)
            .map(|p| self.resolve_record(p, true))
            .collect()
    }
    /// Resolve and, only after certified absence, retry one exact owned operation.
    pub fn retry_pending(&mut self, id: OperationId, digest: Id) -> Result<Response> {
        let p = self
            .pending()?
            .into_iter()
            .find(|p| {
                p.action.action().operation_id == id
                    && p.action.digest() == digest
                    && !p.abandoned
                    && !p.held
            })
            .ok_or(Error::Input)?;
        self.resolve_record(p, true)
    }
    fn resolve_record(&mut self, p: outbox::Pending, retry: bool) -> Result<Response> {
        let body = crate::home::Resolve {
            operation_id: p.action.action().operation_id,
            action_digest: p.action.digest(),
        };
        let query = self.prepare(
            Operation::OperationResolve,
            Target::Service,
            Value::serialized(&body).map_err(|_| Error::Input)?,
        )?;
        let signed = sign_action(&query, &self.key).map_err(|_| Error::Input)?;
        let verified =
            verify_action(&signed, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        let response = self.session()?.submit(&signed, &self.key.verifying_key())?;
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        outbox::record_resolution(&mut self.store, &p.action, &verified, &response, now)
            .map_err(|_| Error::Storage)?;
        let absent = match &response.value().outcome {
            Outcome::Result { body } => {
                let resolved: crate::home::ResolveResult =
                    body.deserialized().map_err(|_| Error::Input)?;
                if resolved.operation_id != p.action.action().operation_id
                    || resolved.action_digest != p.action.digest()
                {
                    return Err(Error::Input);
                }
                matches!(resolved.outcome, Outcome::Absent)
            }
            _ => false,
        };
        if absent && retry && !p.abandoned && !p.held {
            self.validate_message_mode(p.action.action())?;
            let retried = self
                .session()?
                .submit(p.action.signed_bytes(), &self.key.verifying_key())?;
            let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
            outbox::record(&mut self.store, &p.action, &retried, now)
                .map_err(|_| Error::Storage)?;
            Ok(retried.value().clone())
        } else {
            Ok(response.value().clone())
        }
    }
    pub fn search_cancellable(
        &self,
        action: &Action,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<Response> {
        let bytes = self.sign(action)?;
        let verified =
            verify_action(&bytes, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        let mut control = self.prepare(
            Operation::SearchCancel,
            Target::Service,
            Value::serialized(&crate::home::Resolve {
                operation_id: action.operation_id,
                action_digest: verified.digest(),
            })
            .map_err(|_| Error::Input)?,
        )?;
        control.actor = action.actor.clone();
        let signed = self.sign(&control)?;
        Ok(self
            .session()?
            .submit_cancellable(&bytes, &signed, &self.key.verifying_key(), cancel)?
            .value()
            .clone())
    }
    pub fn abandon(&mut self, id: OperationId, digest: Id) -> Result<()> {
        outbox::abandon(&mut self.store, id, digest).map_err(|_| Error::Storage)
    }
    /// Inspect a retained identity without resubmitting an abandoned effect.
    pub fn resolve_retained(&mut self, id: OperationId, digest: Id) -> Result<Response> {
        let p = self
            .pending()?
            .into_iter()
            .find(|p| p.action.action().operation_id == id && p.action.digest() == digest)
            .ok_or(Error::Input)?;
        self.resolve_record(p, false)
    }
    pub fn save_draft(&mut self, room: RoomId, text: &str) -> Result<()> {
        outbox::save_draft(&mut self.store, room, text).map_err(|_| Error::Storage)
    }
    pub fn draft(&mut self, room: RoomId) -> Result<Option<String>> {
        outbox::draft(&mut self.store, room).map_err(|_| Error::Storage)
    }
}

impl Client {
    pub fn save_draft_mentions(
        &mut self,
        room: RoomId,
        text: &str,
        mentions: &[crate::messaging::Mention],
    ) -> Result<()> {
        outbox::save_draft_mentions(&mut self.store, room, text, mentions)
            .map_err(|_| Error::Storage)
    }
    pub fn draft_mentions(&mut self, room: RoomId) -> Result<Vec<crate::messaging::Mention>> {
        outbox::draft_mentions(&mut self.store, room).map_err(|_| Error::Storage)
    }
}
