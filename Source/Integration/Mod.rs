// SPDX-License-Identifier: Apache-2.0
//! Scoped local participant API with one encrypted profile owner and durable outcomes.
#[path = "Broker.rs"]
mod broker;
#[path = "Configuration.rs"]
mod configuration;
#[path = "State.rs"]
mod state;
#[path = "Transport.rs"]
mod transport;
use crate::client;
pub use configuration::{
    Configuration, Credential, Scope, credential_scope, initialise, issue, revoke, socket_path,
};
use serde_json::{Value, json};
pub use transport::{request, serve};

pub const REQUEST_BYTES: usize = 65536;
pub const RESPONSE_BYTES: usize = 1024 * 1024;
pub const API_VERSION: &str = "1.0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid JSON")]
    Parse,
    #[error("invalid JSON-RPC request")]
    InvalidRpc,
    #[error("unknown integration method")]
    Method,
    #[error("invalid integration input")]
    Invalid,
    #[error("integration permission is unavailable")]
    Denied,
    #[error("integration configuration or encrypted state is unavailable")]
    State,
    #[error("the profile is already in use")]
    ProfileInUse,
    #[error("an agent profile is required")]
    AgentRequired,
    #[error("the integration has reached its bounded capacity")]
    Capacity,
    #[error("the request identifier conflicts with retained content")]
    Conflict,
    #[error("the request identifier has retired and cannot be reused")]
    Retired,
    #[error("the event consumer requires explicit resynchronisation")]
    ResynchronisationRequired,
    #[error("the local transport is unavailable")]
    Transport,
    #[error(transparent)]
    Client(#[from] client::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse => "ParseError",
            Self::InvalidRpc => "InvalidRequest",
            Self::Method => "MethodNotFound",
            Self::Invalid => "InvalidIntegrationRequest",
            Self::Denied => "IntegrationDenied",
            Self::State => "IntegrationStateUnavailable",
            Self::ProfileInUse => "ProfileInUse",
            Self::AgentRequired => "AgentProfileRequired",
            Self::Capacity => "IntegrationCapacity",
            Self::Conflict => "RequestConflict",
            Self::Retired => "RequestRetired",
            Self::ResynchronisationRequired => "ResynchronisationRequired",
            Self::Transport => "IntegrationTransportUnavailable",
            Self::Client(e) => e.code(),
        }
    }
    fn response(&self, id: Value) -> Value {
        let rpc_code = match self {
            Self::Parse => -32700,
            Self::InvalidRpc => -32600,
            Self::Method => -32601,
            Self::Invalid => -32602,
            _ => -32000,
        };
        let retry = match self {
            Self::Client(e) => e.retry_delay_ms(),
            Self::Transport => Some(1000),
            _ => None,
        };
        json!({"jsonrpc":"2.0","id":id,"error":{"code":rpc_code,
            "message":self.code(),"data":{"code":self.code(),
            "retryable":retry.is_some(),"retryAfterMs":retry}}})
    }
}

#[cfg(test)]
#[path = "../../Tests/IntegrationApi/State.rs"]
mod tests;
