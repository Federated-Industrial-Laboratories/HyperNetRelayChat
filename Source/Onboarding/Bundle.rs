// SPDX-License-Identifier: Apache-2.0
//! An authenticated delivery container; native Suite still verifies every authority artifact.
use super::{Error, Result, native};
use ciborium::Value as Cbor;
use hrc::{home::Invitation, protocol::canonical_decode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const MAXIMUM_BUNDLE: usize = 8 * 1024 * 1024;
const MAXIMUM_ARTIFACT: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Artifact {
    sha256: String,
    hex: String,
}
impl Artifact {
    fn from_path(path: &Path) -> Result<Self> {
        let bytes = native::public_file(path, MAXIMUM_ARTIFACT)?;
        Ok(Self {
            sha256: fingerprint(&bytes),
            hex: hex::encode(bytes),
        })
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.hex.len() > MAXIMUM_ARTIFACT * 2 || !is_digest(&self.sha256) {
            return Err(Error::BundleBinding);
        }
        let bytes = hex::decode(&self.hex).map_err(|_| Error::BundleBinding)?;
        if hex::encode(&bytes) != self.hex || fingerprint(&bytes) != self.sha256 {
            return Err(Error::BundleBinding);
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> &str {
        &self.sha256
    }
}

/// Public inputs only. All private identities remain on their originating hosts.
pub struct BundleInputs {
    pub bootstrap: PathBuf,
    pub network_invitation: PathBuf,
    pub authority_route: PathBuf,
    pub application_route: PathBuf,
    pub hrc_invitation: PathBuf,
    /// Exact certified grant: lowercase ID:positive-generation:lowercase digest.
    pub connect_grant: String,
    /// Explicit automatic voucher renewal; zero is appropriate for an operator-sponsored voucher.
    pub renewal_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Bundle {
    format: String,
    pub bootstrap: Artifact,
    pub network_invitation: Artifact,
    pub authority_route: Artifact,
    pub application_route: Artifact,
    pub hrc_invitation: Artifact,
    pub connect_grant: String,
    pub renewal_ms: u64,
}

/// Returns deterministic bytes and their independent delivery fingerprint.
/// This does not issue invitations, consent, grants, or network authority.
pub fn build_bundle(inputs: BundleInputs) -> Result<(Vec<u8>, String)> {
    let bundle = Bundle {
        format: "HrcClientSetup/1".into(),
        bootstrap: Artifact::from_path(&inputs.bootstrap)?,
        network_invitation: Artifact::from_path(&inputs.network_invitation)?,
        authority_route: Artifact::from_path(&inputs.authority_route)?,
        application_route: Artifact::from_path(&inputs.application_route)?,
        hrc_invitation: Artifact::from_path(&inputs.hrc_invitation)?,
        connect_grant: inputs.connect_grant,
        renewal_ms: inputs.renewal_ms,
    };
    bundle.validate()?;
    let bytes = serde_json::to_vec(&bundle).map_err(|_| Error::BundleBinding)?;
    if bytes.len() > MAXIMUM_BUNDLE {
        return Err(Error::BundleBinding);
    }
    let digest = fingerprint(&bytes);
    Ok((bytes, digest))
}

pub(super) fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn grant_reference(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 3
        && is_digest(parts[0])
        && is_digest(parts[2])
        && parts[1]
            .parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == parts[1])
}
fn id(value: &Value) -> Result<String> {
    let bytes: [u8; 32] =
        serde_json::from_value(value.clone()).map_err(|_| Error::BundleBinding)?;
    if bytes == [0; 32] {
        return Err(Error::BundleBinding);
    }
    Ok(hex::encode(bytes))
}
fn array(value: &Cbor) -> Result<&[Cbor]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error::BundleBinding)
}
fn number(value: &Cbor) -> Result<u64> {
    value
        .as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::BundleBinding)
}

#[derive(Clone)]
pub(super) struct Route {
    pub service: String,
    pub network: String,
    pub incarnation: String,
    pub possession: String,
    pub connections: u64,
    pub expires_ms: u64,
}
pub(super) fn route(bytes: &[u8], protocol: u64) -> Result<Route> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::BundleBinding)?;
    if value["version"] != 1 || value["protocol"] != protocol {
        return Err(Error::BundleBinding);
    }
    let voucher: Vec<u8> =
        serde_json::from_value(value["voucher"].clone()).map_err(|_| Error::BundleBinding)?;
    // Inspect only the public reservation arithmetic; the native client verifies the full proof.
    let decoded = canonical_decode(&voucher, 65536).map_err(|_| Error::BundleBinding)?;
    let record = array(&decoded)?;
    if record.len() != 8 || number(&record[0])? != 166 || number(&record[1])? != 1 {
        return Err(Error::BundleBinding);
    }
    let fields = array(&record[7])?;
    let fields = match fields.len() {
        11 => fields,
        14 if number(&fields[0])? == 2 => &fields[1..12],
        _ => return Err(Error::BundleBinding),
    };
    let connections = number(&fields[7])?;
    let allowance = number(&fields[8])?;
    let per_connection = value["limits"]["bytes"]
        .as_u64()
        .ok_or(Error::RouteBudget)?;
    if !(1..=4096).contains(&connections)
        || !(16384..=1024 * 1024 * 1024).contains(&per_connection)
        || connections
            .checked_mul(per_connection)
            .is_none_or(|needed| needed > allowance)
    {
        return Err(Error::RouteBudget);
    }
    let possession = fields[4]
        .as_bytes()
        .filter(|b| b.len() == 32)
        .ok_or(Error::BundleBinding)?;
    Ok(Route {
        service: id(&value["destination"]["service"])?,
        network: id(&value["network"])?,
        incarnation: id(&value["incarnation"])?,
        possession: hex::encode(possession),
        connections,
        expires_ms: number(&fields[9])?,
    })
}
impl Bundle {
    pub fn load(path: &Path, expected: &str) -> Result<Self> {
        let bytes = native::public_file(path, MAXIMUM_BUNDLE)?;
        if !is_digest(expected) || fingerprint(&bytes) != expected {
            return Err(Error::BundleBinding);
        }
        let bundle: Self = serde_json::from_slice(&bytes).map_err(|_| Error::BundleBinding)?;
        if serde_json::to_vec(&bundle).map_err(|_| Error::BundleBinding)? != bytes {
            return Err(Error::BundleBinding);
        }
        bundle.validate()?;
        Ok(bundle)
    }
    pub fn invitation(&self) -> Result<Invitation> {
        serde_json::from_slice(&self.hrc_invitation.bytes()?).map_err(|_| Error::BundleBinding)
    }
    pub fn validate(&self) -> Result<()> {
        if self.format != "HrcClientSetup/1"
            || !grant_reference(&self.connect_grant)
            || self.renewal_ms > 3_600_000
        {
            return Err(Error::BundleBinding);
        }
        self.bootstrap.bytes()?;
        let invitation: Value = serde_json::from_slice(&self.network_invitation.bytes()?)
            .map_err(|_| Error::BundleBinding)?;
        if invitation["format"] != "HyperNetInvitation/1"
            || invitation["bootstrapDigest"] != self.bootstrap.sha256
        {
            return Err(Error::BundleBinding);
        }
        let authority = route(&self.authority_route.bytes()?, 1)?;
        let application = route(&self.application_route.bytes()?, 7)?;
        let hrc = self.invitation()?;
        if authority.network != application.network
            || authority.incarnation != application.incarnation
            || authority.possession != application.possession
            || application.network != hrc.home.network.network.as_hex()
            || application.incarnation != hrc.home.network.incarnation.as_hex()
            || application.service != hrc.home.service.as_hex()
        {
            return Err(Error::BundleBinding);
        }
        Ok(())
    }
    pub fn materialize(&self, directory: &Path) -> Result<()> {
        for (name, artifact) in [
            ("Bootstrap.cbor", &self.bootstrap),
            ("NetworkInvitation.json", &self.network_invitation),
            ("AuthorityRoute.json", &self.authority_route),
            ("ApplicationRoute.json", &self.application_route),
            ("HrcInvitation.json", &self.hrc_invitation),
        ] {
            native::exact_file(&directory.join(name), &artifact.bytes()?)?;
        }
        Ok(())
    }
}
