// SPDX-License-Identifier: Apache-2.0
//! Local guided setup. Network authority remains in the released native clients.
#[path = "Bundle.rs"]
mod bundle;
#[path = "Native.rs"]
pub(crate) mod native;
#[path = "Runtime.rs"]
mod runtime;
#[path = "Wizard.rs"]
mod wizard;

pub use bundle::{BundleInputs, build_bundle};
pub use runtime::{PrivateChrony, RuntimeConfig, prepare_existing};
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
        "Install the released HyperNet and HyperNetSuite tools, then choose their local executables."
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
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[path = "../../Tests/Unit/Onboarding/Boundaries.rs"]
mod tests;
