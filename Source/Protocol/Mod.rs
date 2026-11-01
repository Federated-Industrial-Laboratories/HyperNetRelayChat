// SPDX-License-Identifier: Apache-2.0
//! Bounded HRC wire objects and role-separated COSE signatures.
//! Verified signatures establish key possession, not room or delegation permission.
#[path = "Cbor.rs"]
mod cbor;
#[path = "Federation.rs"]
mod federation;
pub use federation::*;
#[path = "Frame.rs"]
mod frame;
#[path = "Lifecycle.rs"]
mod lifecycle;
#[path = "Signed.rs"]
mod signed;
#[path = "Types.rs"]
mod types;

pub use cbor::{canonical_decode, canonical_encode};
pub use ciborium::Value;
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use frame::{Frame, FrameHeader, FrameKind};
pub use lifecycle::*;
pub use signed::*;
pub use types::*;

pub const VERSION: u64 = 1;
pub const PROTOCOL: &str = "hrc/1";
pub const ORDINARY_FRAME_BYTES: usize = 65_536;
pub const CRYPTO_FRAME_BYTES: usize = 262_144;
pub const MAX_DEPTH: usize = 16;
pub const MAX_COLLECTION: usize = 256;
pub const MAX_NODES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("wire input exceeds its bound")]
    Limit,
    #[error("wire input is malformed or noncanonical")]
    Encoding,
    #[error("wire version is unsupported")]
    Version,
    #[error("wire feature is unsupported")]
    Feature,
    #[error("signed object has an unexpected role or key")]
    Binding,
    #[error("signature verification failed")]
    Signature,
    #[error("wire identity or state is invalid")]
    Invalid,
    #[error("random identifier is unavailable")]
    Random,
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[path = "../../Tests/Protocol/Wire.rs"]
mod tests;
