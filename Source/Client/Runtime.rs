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
    #[error("an operation outcome remains unknown")]
    Unknown,
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Client {
    pub profile: Profile,
    pub store: Store,
    key: SigningKey,
    pub session: Session,
}
impl Client {
    pub fn open(directory: &Path) -> Result<Self> {
        let profile = Profile::load(directory).map_err(|_| Error::Configuration)?;
        let key = files::key(&directory.join("Endpoint.key")).map_err(|_| Error::Configuration)?;
        let mut store = profile.store(directory).map_err(|_| Error::Storage)?;
        let session = Session::open(&profile, &key)?;
        outbox::retain(
            &mut store,
            profile.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(|_| Error::Storage)?;
        Ok(Self {
            profile,
            store,
            key,
            session,
        })
    }
    pub fn prepare(&self, operation: Operation, target: Target, body: Value) -> Result<Action> {
        Ok(self.session.action(operation, target, body)?)
    }
    pub fn execute(&mut self, action: &Action) -> Result<Response> {
        let bytes = self.sign(action)?;
        self.execute_signed(&bytes)
    }
    pub fn sign(&self, action: &Action) -> Result<Vec<u8>> {
        if action.home != self.profile.server.home
            || action.actor.acting() != &self.session.ready.acting
        {
            return Err(Error::Input);
        }
        sign_action(action, &self.key).map_err(|_| Error::Input)
    }
    pub fn execute_signed(&mut self, bytes: &[u8]) -> Result<Response> {
        let verified = verify_action(bytes, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        if crate::home::is_read_operation(verified.action().operation) {
            return Ok(self
                .session
                .submit(bytes, &self.key.verifying_key())?
                .value()
                .clone());
        }
        let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
        outbox::prepare(&mut self.store, &verified, &self.session.ready.window, now)
            .map_err(|_| Error::Storage)?;
        let response = self.session.submit(bytes, &self.key.verifying_key())?;
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
        outbox::pending(&mut self.store, &self.key.verifying_key()).map_err(|_| Error::Storage)
    }
    /// Resolve original identities before retrying any effect. No replacement operation is created.
    pub fn resolve_pending(&mut self) -> Result<Vec<Response>> {
        let pending = self.pending()?;
        let mut responses = Vec::new();
        for p in pending {
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
            let response = self.session.submit(&signed, &self.key.verifying_key())?;
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
            if absent {
                let retried = self
                    .session
                    .submit(p.action.signed_bytes(), &self.key.verifying_key())?;
                let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
                outbox::record(&mut self.store, &p.action, &retried, now)
                    .map_err(|_| Error::Storage)?;
                responses.push(retried.value().clone());
            } else {
                responses.push(response.value().clone());
            }
        }
        Ok(responses)
    }
    pub fn save_draft(&mut self, room: RoomId, text: &str) -> Result<()> {
        outbox::save_draft(&mut self.store, room, text).map_err(|_| Error::Storage)
    }
    pub fn draft(&mut self, room: RoomId) -> Result<Option<String>> {
        outbox::draft(&mut self.store, room).map_err(|_| Error::Storage)
    }
}
