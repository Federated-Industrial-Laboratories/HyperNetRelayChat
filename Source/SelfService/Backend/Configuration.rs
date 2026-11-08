// SPDX-License-Identifier: Apache-2.0
//! Operator-owned paths and service identities; recipient input cannot select execution settings.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RouteConfig {
    pub service: String,
    pub profile: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReaderConfig {
    pub content: RouteConfig,
    pub page_host_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Config {
    pub core: PathBuf,
    pub suite: PathBuf,
    pub publisher_key: PathBuf,
    pub bootstrap: PathBuf,
    pub operator_directory: PathBuf,
    pub operator_key: PathBuf,
    pub operator_lock: PathBuf,
    pub authority_control_directory: PathBuf,
    pub clock_directory: PathBuf,
    pub clock_metadata: PathBuf,
    pub image: String,
    pub home_config: PathBuf,
    pub relay: RouteConfig,
    pub authority: RouteConfig,
    pub application: RouteConfig,
    pub reader: Option<ReaderConfig>,
    pub access_expires_ms: u64,
}
impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        for path in [
            &self.core,
            &self.suite,
            &self.publisher_key,
            &self.bootstrap,
            &self.operator_directory,
            &self.operator_key,
            &self.operator_lock,
            &self.authority_control_directory,
            &self.clock_directory,
            &self.clock_metadata,
            &self.home_config,
            &self.relay.profile,
            &self.authority.profile,
            &self.application.profile,
        ] {
            clean_path(path)?;
        }
        if !self.image.strip_prefix("sha256:").is_some_and(is_id)
            || self.access_expires_ms == 0
            || [
                &self.relay.service,
                &self.authority.service,
                &self.application.service,
            ]
            .iter()
            .any(|id| !is_id(id))
            || self.relay.service == self.authority.service
            || self.relay.service == self.application.service
            || self.authority.service == self.application.service
        {
            return Err(Error::Configuration("native identities or expiry"));
        }
        if let Some(reader) = &self.reader {
            clean_path(&reader.content.profile)?;
            if !is_id(&reader.content.service)
                || !is_id(&reader.page_host_key)
                || [
                    &self.relay.service,
                    &self.authority.service,
                    &self.application.service,
                ]
                .contains(&&reader.content.service)
            {
                return Err(Error::Configuration("reader service identity"));
            }
        }
        Ok(())
    }
}
pub(super) fn clean_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || path.to_str().is_none_or(|value| {
            value.chars().any(char::is_control) || value.contains(':') || value.contains(',')
        })
    {
        return Err(Error::Configuration(
            "absolute local path without mount separators",
        ));
    }
    Ok(())
}
pub(crate) fn from_managed(
    config: &crate::operations::network::Configuration,
    operator_lock: PathBuf,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Config> {
    process::check(cancel, end).map_err(|_| Error::Cancelled)?;
    crate::operations::network::admission_config(config, operator_lock, cancel)
        .map_err(|_| Error::State)
}
