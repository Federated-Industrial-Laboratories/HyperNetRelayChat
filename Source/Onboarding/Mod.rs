// SPDX-License-Identifier: Apache-2.0
//! Local guided setup. Network authority remains in the released native clients.
#[path = "Bundle.rs"]
mod bundle;
#[path = "Native.rs"]
pub(crate) mod native;
#[path = "Packages.rs"]
mod packages;
#[path = "Runtime.rs"]
mod runtime;
#[path = "SelfService.rs"]
mod self_service;
#[path = "Simple.rs"]
pub(crate) mod simple;
#[path = "SimpleAgents.rs"]
pub(crate) mod simple_agents;
#[path = "Wizard.rs"]
mod wizard;

pub use bundle::{BundleInputs, build_bundle};
pub use runtime::{PrivateChrony, RuntimeConfig, prepare_existing};
pub(crate) use self_service::{prepare_reader, renewal_due};
pub use wizard::Wizard;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("Choose an existing private local folder or configuration file.")]
    LocalConfiguration,
    #[error("The setup bundle or its independently supplied fingerprint does not match.")]
    BundleBinding,
    #[error("The route allowance cannot cover its stated reconnect count.")]
    RouteBudget,
    #[error(
        "Install or repair the verified native tools in Join a server, or configure existing tools for manual setup."
    )]
    RuntimeMissing,
    #[error("A trusted readable chrony socket is required. No system settings were changed.")]
    ClockPrerequisite,
    #[error("The local signed clock observation is not current.")]
    ClockUnavailable,
    #[error(
        "The native setup command did not complete. Existing keys and pending outcomes were preserved."
    )]
    NativeRefused,
    #[error("The setup operation exceeded its original time limit.")]
    Deadline,
    #[error("Setup was cancelled. Existing keys and pending outcomes were preserved.")]
    Cancelled,
    #[error("The native command exceeded its output limit.")]
    OutputLimit,
    #[error("The existing companion belongs to a different profile or network.")]
    CompanionBinding,
    #[error("The endpoint is not active yet. Return its registration to the service operator.")]
    ActivationPending,
    #[error(
        "Private invitation setup could not complete. Resume with the same invitation and setup folder."
    )]
    Admission,
    #[error(
        "This invitation or its access has expired or was revoked. Existing keys and history were retained."
    )]
    AdmissionExpired,
    #[error(
        "Initial network admission expired. Keep this setup folder and ask the host for a new invitation."
    )]
    AdmissionJoinExpired,
    #[error(
        "Choose a new private setup folder for a new invitation, or load the existing invitation's runtime configuration. The existing profile was not changed."
    )]
    AdmissionFolder,
    #[error(
        "The local companion socket path is too long. Choose a shorter private setup folder before joining."
    )]
    CompanionSocketPath,
    #[error("This private invitation is bound to another recipient or profile.")]
    AdmissionBound,
    #[error(
        "Another operation owns this profile. Close its browser or wait for setup to finish, then retry."
    )]
    Busy,
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[path = "../../Tests/Unit/Onboarding/Boundaries.rs"]
mod tests;

#[cfg(test)]
#[path = "../../Tests/Unit/Onboarding/Simple.rs"]
mod simple_tests;
