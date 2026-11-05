// SPDX-License-Identifier: Apache-2.0
//! Explicit foreign-home selection retains the origin account and endpoint keys.
use super::Profile;
use crate::{
    protocol::*,
    service::{Descriptor, files},
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub home: Descriptor,
    pub origin: Descriptor,
    pub agreement: AgreementRef,
    pub home_signature: Blob,
    pub origin_signature: Blob,
}
impl Selection {
    pub fn validate(&self) -> files::Result<FederationAgreement> {
        self.home.validate()?;
        self.origin.validate()?;
        let home_key = VerifyingKey::from_bytes(self.home.signing_key.as_bytes())
            .map_err(|_| files::Invalid)?;
        let origin_key = VerifyingKey::from_bytes(self.origin.signing_key.as_bytes())
            .map_err(|_| files::Invalid)?;
        let home =
            verify_agreement(&self.home_signature.0, &home_key).map_err(|_| files::Invalid)?;
        let other =
            verify_agreement(&self.origin_signature.0, &origin_key).map_err(|_| files::Invalid)?;
        let agreement = home.value();
        if home.digest() != other.digest()
            || agreement.home != self.home.home
            || agreement.origin != self.origin.home
            || agreement.home_service_key != self.home.signing_key
            || agreement.origin_service_key != self.origin.signing_key
            || agreement.id != self.agreement.id
            || agreement.revision != self.agreement.revision
            || home.digest() != self.agreement.digest
        {
            return Err(files::Invalid);
        }
        Ok(agreement.clone())
    }
}

/// The ordinary endpoint store lock prevents reconfiguration under a running client.
pub fn select(directory: &Path, selected: Option<Selection>, activate: bool) -> files::Result<()> {
    let mut profile = Profile::load(directory)?;
    let _store = profile.store(directory).map_err(|_| files::Invalid)?;
    if let Some(value) = selected {
        value.validate()?;
        if activate
            && (value.origin.home != profile.server.home
                || value.origin.signing_key != profile.server.signing_key)
        {
            return Err(files::Invalid);
        }
        profile
            .agreements
            .retain(|old| old.agreement.id != value.agreement.id);
        if activate {
            profile.federation = Some(value.agreement);
        }
        profile.agreements.push(value);
    } else {
        profile.federation = None;
    }
    save(directory, &profile)
}

pub(super) fn save(directory: &Path, profile: &Profile) -> files::Result<()> {
    profile.validate_federation()?;
    let temporary = directory.join(format!(
        ".Profile.{}.tmp",
        Id::random().map_err(|_| files::Invalid)?
    ));
    let bytes = serde_json::to_vec_pretty(profile).map_err(|_| files::Invalid)?;
    if bytes.len() > super::PROFILE_BYTES {
        return Err(files::Invalid);
    }
    files::create(&temporary, &bytes)?;
    if fs::rename(&temporary, directory.join("Profile.json")).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(files::Invalid);
    }
    fs::File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| files::Invalid)
}
