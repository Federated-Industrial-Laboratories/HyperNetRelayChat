// SPDX-License-Identifier: Apache-2.0
//! Explicit host policy and public operation summaries.
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    pub memory_bytes_per_role: u64,
    pub state_bytes_per_role: u64,
    pub cpu_quota_per_role: u64,
    pub pids_per_role: u64,
    pub connection_bytes: u64,
    pub connection_seconds: u64,
    pub relay_connections: u64,
    pub endpoint_connections: u64,
}
impl Default for Resources {
    fn default() -> Self {
        Self {
            memory_bytes_per_role: 536_870_912,
            state_bytes_per_role: 1_073_741_824,
            cpu_quota_per_role: 100_000,
            pids_per_role: 128,
            connection_bytes: 268_435_456,
            connection_seconds: 3600,
            relay_connections: 32,
            endpoint_connections: 8,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub name: String,
    pub nickname: String,
    pub root: PathBuf,
    pub recovery_directory: PathBuf,
    /// Executable from the verified supported Core installation.
    pub core: PathBuf,
    /// Executable from the verified supported Suite installation.
    pub suite: PathBuf,
    /// Publisher public key; its canonical value must match the pinned release root.
    pub publisher_key: PathBuf,
    pub chronyc: PathBuf,
    pub chrony_socket: PathBuf,
    pub bind_address: Ipv4Addr,
    pub advertised_address: Ipv4Addr,
    pub relay_port: u16,
    pub authority_first_port: u16,
    /// Distinct rootless /24 subnets, starting at 10.89.N.0, for the four replicas.
    pub subnet_octet: u8,
    /// Required explicit acknowledgement for this single-operator topology.
    pub same_organisation: bool,
    /// Finite initial hosting consent; renewal always requires another preview.
    pub lifetime_hours: u16,
    /// Initial administrator and bootstrap validity; separate from finite hosting consent.
    pub governance_days: u16,
    pub resources: Resources,
}
impl Configuration {
    pub fn at(root: PathBuf) -> Self {
        let recovery_directory = root.with_file_name(format!(
            "{}-Recovery",
            root.file_name().and_then(|v| v.to_str()).unwrap_or("HRC")
        ));
        Self {
            name: "My HyperNet".into(),
            nickname: "Owner".into(),
            root,
            recovery_directory,
            core: crate::operations::native::discover("HyperNet"),
            suite: crate::operations::native::discover("HyperNetSuite"),
            publisher_key: PathBuf::new(),
            chronyc: PathBuf::from("/usr/bin/chronyc"),
            chrony_socket: PathBuf::from("/run/chrony/chronyd.sock"),
            bind_address: Ipv4Addr::LOCALHOST,
            advertised_address: Ipv4Addr::LOCALHOST,
            relay_port: 24443,
            authority_first_port: 24450,
            subnet_octet: 220,
            same_organisation: false,
            lifetime_hours: 24,
            governance_days: 365,
            resources: Resources::default(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [(&self.name, "network name"), (&self.nickname, "nickname")] {
            if value.trim().is_empty() || value.len() > 96 || value.chars().any(char::is_control) {
                return Err(Error::Configuration(label));
            }
        }
        hrc::text::handle(&self.nickname).map_err(|_| Error::Configuration("nickname"))?;
        for path in [
            &self.root,
            &self.recovery_directory,
            &self.core,
            &self.suite,
            &self.publisher_key,
            &self.chronyc,
            &self.chrony_socket,
        ] {
            clean_path(path)?;
        }
        if self.root.as_os_str().len() > 65 {
            return Err(Error::Configuration(
                "hosting folder is too long for native sockets (maximum 65 bytes)",
            ));
        }
        if self.recovery_directory.starts_with(&self.root)
            || self.root.starts_with(&self.recovery_directory)
        {
            return Err(Error::Configuration(
                "keep recovery material outside the hosting folder",
            ));
        }
        if !self.same_organisation {
            return Err(Error::Configuration(
                "acknowledge that this host operates both relay and destination",
            ));
        }
        if invalid_address(self.advertised_address)
            || self.bind_address.is_multicast()
            || self.bind_address.is_broadcast()
        {
            return Err(Error::Configuration("explicit unicast IPv4 address"));
        }
        if self.bind_address != self.advertised_address {
            return Err(Error::Configuration(
                "this native hosting profile requires the advertised IPv4 address to be assigned to this host; separate NAT bind addresses are unsupported",
            ));
        }
        if self.relay_port <= 1024
            || self.authority_first_port <= 1024
            || self.authority_first_port > 65532
            || (self.authority_first_port..=self.authority_first_port + 3)
                .contains(&self.relay_port)
            || self.subnet_octet > 251
        {
            return Err(Error::Configuration(
                "distinct unprivileged relay and authority ports/subnets",
            ));
        }
        if !(1..=168).contains(&self.lifetime_hours) {
            return Err(Error::Configuration(
                "hosting lifetime must be 1 to 168 hours",
            ));
        }
        if !(7..=3650).contains(&self.governance_days) {
            return Err(Error::Configuration(
                "governance validity must be 7 to 3650 days",
            ));
        }
        let r = &self.resources;
        if !(268_435_456..=8_589_934_592).contains(&r.memory_bytes_per_role)
            || !(1_073_741_824..=1_099_511_627_776).contains(&r.state_bytes_per_role)
            || !(10_000..=800_000).contains(&r.cpu_quota_per_role)
            || !(64..=1024).contains(&r.pids_per_role)
            || !(16384..=1_073_741_824).contains(&r.connection_bytes)
            || !(60..=3600).contains(&r.connection_seconds)
            || !(1..=16).contains(&r.endpoint_connections)
            || r.relay_connections < 2 * r.endpoint_connections
            || r.relay_connections > 128
        {
            return Err(Error::Configuration(
                "bounded host resource and connection budgets",
            ));
        }
        Ok(())
    }
    pub fn hrc_profile(&self) -> PathBuf {
        self.root.join("Client/HRC")
    }
    pub fn service_directory(&self) -> PathBuf {
        self.root.join("HRC")
    }
}
pub(super) fn clean_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || path
            .to_str()
            .is_none_or(|p| p.chars().any(char::is_control) || p.contains(':') || p.contains(','))
    {
        return Err(Error::Configuration(
            "absolute local path without control characters or mount separators",
        ));
    }
    Ok(())
}
fn invalid_address(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Requirement {
    pub component: String,
    pub ready: bool,
    pub action: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub digest: String,
    pub configuration: Configuration,
    pub requirements: Vec<Requirement>,
    pub ready: bool,
    pub authority_replicas: u8,
    pub host_failure_independence: bool,
    pub privacy: String,
    pub memory_admission_bytes: u64,
    pub storage_admission_bytes: u64,
    pub core_package: serde_json::Value,
    pub suite_package: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub state: String,
    pub phase: String,
    pub network: Option<String>,
    pub incarnation: Option<String>,
    pub expires_ms: Option<u64>,
    pub quorum_verified: bool,
    pub client_authenticated: bool,
    pub profile: PathBuf,
    pub service_directory: PathBuf,
    pub units: Vec<serde_json::Value>,
}
