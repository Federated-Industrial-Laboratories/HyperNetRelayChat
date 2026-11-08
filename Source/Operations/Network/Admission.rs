// SPDX-License-Identifier: Apache-2.0
//! Export existing managed hosting state without provisioning or replacing native identities.
use super::{Configuration, Result, engine::*, services};
use crate::self_service::backend::{Config, RouteConfig};
use std::{path::PathBuf, sync::atomic::AtomicBool};

pub(crate) fn admission_config(
    c: &Configuration,
    operator_lock: PathBuf,
    cancel: &AtomicBool,
) -> Result<Config> {
    let host = Host::open(c, cancel, None)?;
    if !host.state.completed {
        return Err(super::Error::State);
    }
    if operator_lock != host.p("Operation.lock") {
        return Err(super::Error::Configuration(
            "managed admission must share the host Operation.lock",
        ));
    }
    let route = |name: &str, identity: &str| -> Result<RouteConfig> {
        Ok(RouteConfig {
            service: host
                .state
                .ids
                .get(identity)
                .ok_or(super::Error::State)?
                .clone(),
            profile: services::active_directory(&host, name)?.join("Inputs/RouteProfile.cbor"),
        })
    };
    // The existing home can be controlled through the normal imported-service configuration.
    let home_config = host.p("AdmissionHome.json");
    if !home_config.exists() {
        write(
            &home_config,
            &crate::operations::home::Configuration::at(c.service_directory()),
        )?;
    }
    let clock_metadata = host.p("AdmissionClock.json");
    write(
        &clock_metadata,
        &host.state.results.get("clock").ok_or(super::Error::State)?,
    )?;
    Ok(Config {
        core: c.core.clone(),
        suite: c.suite.clone(),
        publisher_key: c.publisher_key.clone(),
        bootstrap: host.p("Network/Bootstrap.cbor"),
        operator_directory: host.p("OpAdministrator"),
        operator_key: host.p("Keys/Administrator.json"),
        operator_lock,
        authority_control_directory: host.p("A1/Launch/State/Control"),
        clock_directory: host.p("Clock/Public"),
        clock_metadata,
        image: host.state.image.clone(),
        home_config,
        relay: route("Relay", "relay")?,
        authority: route("AuthorityEndpoint", "authority")?,
        application: route("ApplicationEndpoint", "application")?,
        reader: None,
        access_expires_ms: host.state.expires_ms,
    })
}
