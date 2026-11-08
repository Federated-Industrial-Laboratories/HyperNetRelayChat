// SPDX-License-Identifier: Apache-2.0
//! Optional invitation exchange; chat and Page traffic remain native HyperNet traffic.
#[path = "Backend/Mod.rs"]
pub(crate) mod backend;
#[path = "Client.rs"]
pub(crate) mod client;
#[path = "Commands.rs"]
pub(crate) mod commands;
#[path = "Server.rs"]
mod server;
#[path = "Store.rs"]
mod store;
#[path = "Transport.rs"]
mod transport;
#[path = "Types.rs"]
mod types;

pub(crate) use types::*;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("The private invitation or admission response is invalid.")]
    Invalid,
    #[error("The invitation expired or its access was revoked.")]
    Expired,
    #[error("The invitation is already bound to another recipient.")]
    Bound,
    #[error("The admission service is busy. Retry with the same invitation and profile.")]
    Busy,
    #[error("The admission connection could not be verified or completed.")]
    Connection,
    #[error("Admission was cancelled. Existing keys and pending outcomes were retained.")]
    Cancelled,
    #[error("Admission reached its deadline. Resume with the same local profile.")]
    Deadline,
    #[error("Private admission state could not be verified or stored.")]
    State,
    #[error("Native admission needs operator inspection. Existing state was retained.")]
    Native,
    #[error("Invalid admission configuration: {0}")]
    Configuration(&'static str),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;
