// SPDX-License-Identifier: Apache-2.0
//! Recipient-owned invitation authentication and retry-safe pinned exchanges.
use super::{
    Action, Error, INVITATION_FORMAT, Invitation, MAX_REQUEST, MAX_RESPONSE, PROTOCOL, RequestData,
    Response, Result, SignedRequest, is_id, now_ms, transport,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hrc::service::files;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Greeting {
    pub protocol: String,
    pub challenge: String,
}
pub(super) fn signed_bytes(challenge: &str, data: &RequestData) -> Result<Vec<u8>> {
    if !is_id(challenge) {
        return Err(Error::Invalid);
    }
    let mut bytes = b"HRC/AdmissionRequest/1\0".to_vec();
    bytes.extend_from_slice(&hex::decode(challenge).map_err(|_| Error::Invalid)?);
    bytes.extend_from_slice(&serde_json::to_vec(data).map_err(|_| Error::Invalid)?);
    Ok(bytes)
}
pub(super) fn verify(challenge: &str, request: &SignedRequest) -> Result<()> {
    if !is_id(&request.data.invitation_id)
        || !is_id(&request.data.authentication_key)
        || request.signature.len() != 128
    {
        return Err(Error::Invalid);
    }
    let key: [u8; 32] = hex::decode(&request.data.authentication_key)
        .map_err(|_| Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let signature =
        Signature::from_slice(&hex::decode(&request.signature).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| Error::Invalid)?
        .verify_strict(&signed_bytes(challenge, &request.data)?, &signature)
        .map_err(|_| Error::Invalid)
}
impl Invitation {
    pub fn validate(&self) -> Result<()> {
        if self.format != INVITATION_FORMAT
            || self.name.trim().is_empty()
            || self.name.len() > 96
            || self.name.chars().any(char::is_control)
            || self.address.port() <= 1024
            || self.address.ip().is_unspecified()
            || self.address.ip().is_multicast()
            || self.address.ip().is_broadcast()
            || self.certificate_authority_pem.len() > 16384
            || self.certificate_authority_pem.is_empty()
            || [
                &self.server_certificate_sha256,
                &self.network,
                &self.incarnation,
                &self.bootstrap_sha256,
                &self.bootstrap_fingerprint,
                &self.id,
                &self.secret,
            ]
            .into_iter()
            .any(|s| !is_id(s))
            || self.expires_ms == 0
            || self.expires_ms > self.access_expires_ms
        {
            return Err(Error::Invalid);
        }
        if self.access_expires_ms <= now_ms()? {
            return Err(Error::Expired);
        }
        Ok(())
    }
}
pub(crate) fn parse_invitation(text: &str) -> Result<Invitation> {
    let text = text.trim();
    if text.len() > 65536 {
        return Err(Error::Invalid);
    }
    let bytes = if let Some(encoded) = text.strip_prefix("hrc-invite:1:") {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Invalid)?
    } else {
        text.as_bytes().to_vec()
    };
    let invitation: Invitation = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    invitation.validate()?;
    Ok(invitation)
}
pub(crate) fn invitation_code(invitation: &Invitation) -> Result<String> {
    invitation.validate()?;
    Ok(format!(
        "hrc-invite:1:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(invitation).map_err(|_| Error::Invalid)?)
    ))
}
pub(crate) struct Client {
    pub invitation: Invitation,
    key: SigningKey,
    _directory: PathBuf,
}
impl Client {
    pub fn open(directory: &Path, invitation: Invitation) -> Result<Self> {
        invitation.validate()?;
        files::directory(directory, !directory.exists()).map_err(|_| Error::State)?;
        let saved = directory.join("Invitation.json");
        let bytes = serde_json::to_vec(&invitation).map_err(|_| Error::Invalid)?;
        let path = directory.join("Authentication.key");
        let key = if saved.exists() {
            if files::read(&saved, 65536).map_err(|_| Error::State)? != bytes {
                return Err(Error::Bound);
            }
            files::key(&path).map_err(|_| Error::State)?
        } else {
            let key = if path.exists() {
                files::key(&path)
            } else {
                files::create_key(&path)
            }
            .map_err(|_| Error::State)?;
            files::create(&saved, &bytes).map_err(|_| Error::State)?;
            key
        };
        Ok(Self {
            invitation,
            key,
            _directory: directory.to_owned(),
        })
    }
    pub fn exchange(&self, action: Action, cancel: &AtomicBool, end: Instant) -> Result<Response> {
        if cancel.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        self.invitation.validate()?;
        let result = (|| {
            let mut tls = transport::connect(
                &self.invitation,
                cancel,
                end.min(Instant::now() + Duration::from_secs(15)),
            )?;
            let greeting: Greeting = transport::read(&mut tls, 1024)?;
            if greeting.protocol != PROTOCOL || !is_id(&greeting.challenge) {
                return Err(Error::Invalid);
            }
            let data = RequestData {
                invitation_id: self.invitation.id.clone(),
                authentication_key: hex::encode(self.key.verifying_key().to_bytes()),
                action,
            };
            let signature = hex::encode(
                self.key
                    .sign(&signed_bytes(&greeting.challenge, &data)?)
                    .to_bytes(),
            );
            transport::write(&mut tls, &SignedRequest { data, signature }, MAX_REQUEST)?;
            transport::read(&mut tls, MAX_RESPONSE)
        })();
        if cancel.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else if Instant::now() >= end {
            Err(Error::Deadline)
        } else {
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_binds_challenge_and_operation() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let challenge = "11".repeat(32);
        let data = RequestData {
            invitation_id: "22".repeat(32),
            authentication_key: hex::encode(key.verifying_key().to_bytes()),
            action: Action::Status,
        };
        let signature = hex::encode(
            key.sign(&signed_bytes(&challenge, &data).unwrap())
                .to_bytes(),
        );
        let mut request = SignedRequest { data, signature };
        verify(&challenge, &request).unwrap();
        assert!(verify(&"33".repeat(32), &request).is_err());
        request.data.action = Action::Renew;
        assert!(verify(&challenge, &request).is_err());
    }
}
