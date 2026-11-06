// SPDX-License-Identifier: Apache-2.0
//! User-owned HyperNet hosting through pinned native package and consent contracts.
#[path = "Bootstrap.rs"]
mod bootstrap;
#[path = "Clients.rs"]
mod clients;
#[path = "Configuration.rs"]
mod configuration;
#[path = "Engine.rs"]
mod engine;
#[path = "Lifecycle.rs"]
mod lifecycle;
#[path = "Renewal.rs"]
mod renewal;
#[path = "Services.rs"]
mod services;
#[path = "Subnets.rs"]
mod subnets;

pub use clients::{enrol_client, invite_client};
pub use configuration::{
    Configuration, Preview, Requirement, Status, local_addresses, valid_host_address,
};
pub use engine::{apply, preview, progress};
pub use lifecycle::{start, status, stop};
pub use renewal::{pending_renewal, renew, renewal_preview};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid hosting setting: {0}")]
    Configuration(&'static str),
    #[error("Required host component is unavailable: {0}")]
    Prerequisite(&'static str),
    #[error("The installed package differs from the supported signed release.")]
    Package,
    #[error("The reviewed hosting configuration changed. Review the new preview.")]
    PreviewChanged,
    #[error("Existing hosting state differs from this setup. It was preserved.")]
    State,
    #[error("Another hosting operation is running.")]
    Busy,
    #[error(
        "The native operation was refused at {0}. Existing keys and pending requests were preserved."
    )]
    Native(String),
    #[error(
        "{0} The previously running chat service could not restart. Check its status and start it again."
    )]
    ServiceRestore(String),
    #[error("Hosting setup was cancelled. Resume the same configuration to continue.")]
    Cancelled,
    #[error("Hosting setup reached its deadline. Resume the same configuration to continue.")]
    Deadline,
    #[error("A stopped native successor is required after reboot or consent expiry.")]
    RenewalRequired,
    #[error("The hosting operation completed, but current HRC authentication is not ready.")]
    NotReady,
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[path = "../../../Tests/Unit/Operations/Network/Contracts.rs"]
mod tests;
