// SPDX-License-Identifier: Apache-2.0
//! Explicit local gateway routes; each companion is independently admitted in its destination.
use super::{Config, files};
use crate::{home::Home, protocol::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Route {
    pub agreement: AgreementRef,
    pub companion: PathBuf,
    pub gateway_key: PathBuf,
    pub attestor_key: PathBuf,
}

fn shape(routes: &[Route]) -> files::Result<()> {
    if routes.len() > 2
        || routes
            .iter()
            .map(|r| r.agreement.id)
            .collect::<BTreeSet<_>>()
            .len()
            != routes.len()
        || routes.iter().any(|r| {
            !r.companion.is_absolute()
                || !r.gateway_key.is_absolute()
                || !r.attestor_key.is_absolute()
        })
    {
        return Err(files::Invalid);
    }
    Ok(())
}

pub(crate) fn load(directory: &Path) -> files::Result<Vec<Route>> {
    let path = directory.join("FederationRoutes.json");
    let routes = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(files::Invalid),
        Ok(_) => files::json(&path)?,
    };
    shape(&routes)?;
    Ok(routes)
}

/// The exclusive home store prevents changing gateway configuration while the service runs.
pub fn install(directory: &Path, configuration: &Path) -> files::Result<usize> {
    let config = Config::load(directory)?;
    let routes: Vec<Route> = files::json(configuration)?;
    shape(&routes)?;
    let signer = files::key(&directory.join("Signing.key"))?;
    let mut home = Home::open(
        config.store(directory).map_err(|_| files::Invalid)?,
        config.descriptor.home,
        signer,
    )
    .map_err(|_| files::Invalid)?;
    for route in &routes {
        let now = config.clock.sample().map_err(|_| files::Invalid)?;
        let state = home
            .federation_agreement(route.agreement, now)
            .map_err(|_| files::Invalid)?;
        let agreement = &state.agreement;
        if agreement.origin != config.descriptor.home
            || agreement.home_gateway.destination != agreement.home
            || agreement.home_gateway.network != agreement.home.network
        {
            return Err(files::Invalid);
        }
        files::directory(&route.companion, false)?;
        if files::key(&route.gateway_key)?.verifying_key().as_bytes()
            != agreement.home_gateway.signing_key.as_bytes()
            || files::key(&route.attestor_key)?.verifying_key().as_bytes()
                != agreement.origin_attestor_key.as_bytes()
        {
            return Err(files::Invalid);
        }
    }
    let destination = directory.join("FederationRoutes.json");
    if fs::symlink_metadata(&destination).is_ok() {
        files::read(&destination, 16_384)?;
    }
    let temporary = directory.join(format!(
        ".FederationRoutes.{}.tmp",
        Id::random().map_err(|_| files::Invalid)?
    ));
    files::create_json(&temporary, &routes)?;
    if fs::rename(&temporary, &destination).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(files::Invalid);
    }
    fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| files::Invalid)?;
    Ok(routes.len())
}
