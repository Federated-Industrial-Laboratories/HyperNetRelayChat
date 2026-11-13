// SPDX-License-Identifier: Apache-2.0
//! Fixed private registrar control; no public listener can select credentials or a command.
#[path = "AdmissionBridge.rs"]
pub(crate) mod bridge;
use super::files;
use crate::{
    home::admission::{self, Policy, Request, Response},
    protocol::*,
};
pub use bridge::Configuration as Bridge;
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const WIRE_MAX: usize = admission::MAXIMUM * 2 + 4096;
const DOMAIN: &[u8] = b"HyperNet.HrcAdmission.Control/1\0";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub directory: PathBuf,
    /// Present only for the socket-only bridge in an isolated registrar namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_uid: Option<u32>,
    pub home: ServiceId,
    pub service_key: Id,
    pub registrar_key_file: PathBuf,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Control {
    Request {
        request: Request,
    },
    Configure {
        policy: Policy,
    },
    ConfigureHost {
        policy: Policy,
    },
    LegacyInvite {
        principal: Id,
        id: Id,
        expires_ms: u64,
    },
    LegacyEnrol {
        registration: admission::Artifact,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Payload {
    pub home: ServiceId,
    pub boot: Id,
    pub nonce: Id,
    pub expires_boot_ms: u64,
    pub control: Control,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Envelope {
    pub signer: Id,
    pub payload: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Reply {
    pub boot: Id,
    pub nonce: Id,
    pub result: serde_json::Value,
}
/// The held directory descriptor keeps long private paths within the Unix address limit.
pub(crate) fn socket_directory(directory: &Path) -> files::Result<(File, PathBuf)> {
    files::directory(directory, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|_| files::Invalid)?;
    let held = file.metadata().map_err(|_| files::Invalid)?;
    let current = std::fs::symlink_metadata(directory).map_err(|_| files::Invalid)?;
    if held.dev() != current.dev()
        || held.ino() != current.ino()
        || held.mode() & 0o7777 != 0o700
        || held.uid() != unsafe { libc::geteuid() }
    {
        return Err(files::Invalid);
    }
    files::directory(directory, false)?;
    let path = PathBuf::from(format!("/proc/self/fd/{}/Admission.sock", file.as_raw_fd()));
    Ok((file, path))
}
fn signed<T: Serialize>(value: &T, key: &SigningKey) -> files::Result<Envelope> {
    let bytes = serde_json::to_vec(value).map_err(|_| files::Invalid)?;
    if bytes.len() > admission::MAXIMUM {
        return Err(files::Invalid);
    }
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    Ok(Envelope {
        signer: Id::from_bytes(key.verifying_key().to_bytes()),
        payload: hex::encode(bytes),
        signature: hex::encode(key.sign(&signed).to_bytes()),
    })
}
pub(crate) fn verify<T: serde::de::DeserializeOwned>(envelope: &Envelope) -> files::Result<T> {
    if envelope.payload.len() > admission::MAXIMUM * 2
        || envelope.signature.len() != 128
        || !envelope
            .payload
            .bytes()
            .chain(envelope.signature.bytes())
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(files::Invalid);
    }
    let bytes = hex::decode(&envelope.payload).map_err(|_| files::Invalid)?;
    let signature =
        Signature::from_slice(&hex::decode(&envelope.signature).map_err(|_| files::Invalid)?)
            .map_err(|_| files::Invalid)?;
    let key = VerifyingKey::from_bytes(envelope.signer.as_bytes()).map_err(|_| files::Invalid)?;
    let mut input = DOMAIN.to_vec();
    input.extend_from_slice(&bytes);
    key.verify_strict(&input, &signature)
        .map_err(|_| files::Invalid)?;
    serde_json::from_slice(&bytes).map_err(|_| files::Invalid)
}
fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], end: Instant) -> files::Result<()> {
    while !bytes.is_empty() {
        let remaining = end
            .checked_duration_since(Instant::now())
            .ok_or(files::Invalid)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| files::Invalid)?;
        let n = stream.read(bytes).map_err(|_| files::Invalid)?;
        if n == 0 {
            return Err(files::Invalid);
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}
pub(crate) fn receive(stream: &mut UnixStream, end: Instant) -> files::Result<Envelope> {
    let mut prefix = [0u8; 4];
    read_exact(stream, &mut prefix, end)?;
    let count = u32::from_be_bytes(prefix) as usize;
    if count == 0 || count > WIRE_MAX {
        return Err(files::Invalid);
    }
    let mut bytes = vec![0; count];
    read_exact(stream, &mut bytes, end)?;
    serde_json::from_slice(&bytes).map_err(|_| files::Invalid)
}
pub(crate) fn send<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    key: &SigningKey,
    end: Instant,
) -> files::Result<()> {
    let bytes = serde_json::to_vec(&signed(value, key)?).map_err(|_| files::Invalid)?;
    if bytes.len() > WIRE_MAX {
        return Err(files::Invalid);
    }
    let mut output = (bytes.len() as u32).to_be_bytes().to_vec();
    output.extend_from_slice(&bytes);
    let mut rest = output.as_slice();
    while !rest.is_empty() {
        stream
            .set_write_timeout(Some(
                end.checked_duration_since(Instant::now())
                    .ok_or(files::Invalid)?,
            ))
            .map_err(|_| files::Invalid)?;
        let n = stream.write(rest).map_err(|_| files::Invalid)?;
        if n == 0 {
            return Err(files::Invalid);
        }
        rest = &rest[n..];
    }
    Ok(())
}
pub(crate) fn call(
    binding: &Binding,
    key: &SigningKey,
    control: Control,
) -> files::Result<serde_json::Value> {
    if let Some(owner) = binding.peer_uid {
        return bridge::call(binding, owner, key, control);
    }
    files::directory(&binding.directory, false)?;
    let boot: Id = files::json(&binding.directory.join("Admission.boot"))?;
    let nonce = Id::random().map_err(|_| files::Invalid)?;
    let payload = Payload {
        home: binding.home,
        boot,
        nonce,
        expires_boot_ms: crate::clock::boot_ms().map_err(|_| files::Invalid)? + 5000,
        control,
    };
    let (_directory, socket) = socket_directory(&binding.directory)?;
    let mut stream = bridge::connect(&socket)?;
    bridge::peer(&stream, unsafe { libc::geteuid() })?;
    let end = Instant::now() + Duration::from_secs(5);
    send(&mut stream, &payload, key, end)?;
    let envelope = receive(&mut stream, end)?;
    if envelope.signer != binding.service_key {
        return Err(files::Invalid);
    }
    let reply: Reply = verify(&envelope)?;
    if reply.boot != boot || reply.nonce != nonce {
        return Err(files::Invalid);
    }
    Ok(reply.result)
}
pub fn request(config: &Path, request: &Request) -> files::Result<Response> {
    let binding: Binding = files::json(config)?;
    let key = files::key(&binding.registrar_key_file)?;
    serde_json::from_value(call(
        &binding,
        &key,
        Control::Request {
            request: request.clone(),
        },
    )?)
    .map_err(|_| files::Invalid)
}
fn owner(directory: &Path) -> files::Result<(Binding, SigningKey)> {
    let config = super::Config::load(directory)?;
    let key = files::key(&directory.join("Signing.key"))?;
    Ok((
        Binding {
            directory: directory.to_owned(),
            peer_uid: None,
            home: config.descriptor.home,
            service_key: config.descriptor.signing_key,
            registrar_key_file: directory.join("Signing.key"),
        },
        key,
    ))
}
pub fn configure(directory: &Path, policy: Policy) -> files::Result<()> {
    let (binding, key) = owner(directory)?;
    if call(&binding, &key, Control::Configure { policy })?
        != serde_json::json!({"configured":true})
    {
        return Err(files::Invalid);
    }
    Ok(())
}
/// Bootstrap receipt is atomic with policy; retry never restores later disabled admission.
pub(crate) fn configure_host(directory: &Path, policy: Policy) -> files::Result<()> {
    let (binding, key) = owner(directory)?;
    if call(&binding, &key, Control::ConfigureHost { policy })?
        != serde_json::json!({"configured":true})
    {
        return Err(files::Invalid);
    }
    Ok(())
}
pub fn legacy_invite(
    directory: &Path,
    principal: Id,
    id: Id,
    expires_ms: u64,
) -> files::Result<crate::home::Invitation> {
    let (binding, key) = owner(directory)?;
    serde_json::from_value(call(
        &binding,
        &key,
        Control::LegacyInvite {
            principal,
            id,
            expires_ms,
        },
    )?)
    .map_err(|_| files::Invalid)
}
pub fn legacy_enrol(directory: &Path, registration: &[u8]) -> files::Result<EndpointActor> {
    let (binding, key) = owner(directory)?;
    serde_json::from_value(call(
        &binding,
        &key,
        Control::LegacyEnrol {
            registration: admission::Artifact::new(registration),
        },
    )?)
    .map_err(|_| files::Invalid)
}
