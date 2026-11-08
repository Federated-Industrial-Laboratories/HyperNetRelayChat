// SPDX-License-Identifier: Apache-2.0
//! Fixed native admission operations for managed and explicitly imported local hosts.
#[path = "Configuration.rs"]
mod configuration;
#[path = "Native.rs"]
mod native;
#[path = "Routes.rs"]
mod routes;
#[path = "State.rs"]
mod state;
#[path = "Workflow.rs"]
mod workflow;

use super::types::{digest, is_id, now_ms};
use super::{Artifact, Delivery, Error, NetworkMetadata, ReaderDelivery, Result, RouteDelivery};
use crate::operations::native as process;
pub(crate) use configuration::{Config, RouteConfig, from_managed};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Instant,
};
pub(crate) use workflow::{enrol, issue, metadata, renew, revoke};

fn string(value: &Value, key: &str) -> Result<String> {
    value[key].as_str().map(str::to_owned).ok_or(Error::State)
}
fn text(path: &Path) -> Result<String> {
    process::path(path).map_err(|_| Error::State)
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}
fn id() -> Result<String> {
    hrc::protocol::Id::random()
        .map(|value| value.as_hex())
        .map_err(|_| Error::State)
}
