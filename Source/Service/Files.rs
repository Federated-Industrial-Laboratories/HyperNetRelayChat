// SPDX-License-Identifier: Apache-2.0
//! Private service/device configuration and signing key files.
use ed25519_dalek::SigningKey;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("private configuration is invalid or unavailable")]
pub struct Invalid;
pub type Result<T> = std::result::Result<T, Invalid>;

pub fn directory(path: &Path, create: bool) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Invalid);
    }
    if create {
        let mut b = fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700).create(path).map_err(|_| Invalid)?;
    }
    let m = fs::symlink_metadata(path).map_err(|_| Invalid)?;
    if !m.is_dir()
        || m.mode() & 0o7777 != 0o700
        || m.uid() != unsafe { libc::geteuid() }
        || path.canonicalize().map_err(|_| Invalid)? != path
    {
        return Err(Invalid);
    }
    Ok(path.to_owned())
}
pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| Invalid)? != path {
        return Err(Invalid);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Invalid)?;
    let m = file.metadata().map_err(|_| Invalid)?;
    if !m.is_file()
        || m.mode() & 0o7777 != 0o600
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.len() > maximum as u64
    {
        return Err(Invalid);
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Invalid)?;
    if bytes.len() > maximum {
        return Err(Invalid);
    }
    Ok(bytes)
}
pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    directory(path.parent().ok_or(Invalid)?, false)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Invalid)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| Invalid)?;
    file.write_all(bytes).map_err(|_| Invalid)?;
    file.sync_all().map_err(|_| Invalid)?;
    fs::File::open(path.parent().ok_or(Invalid)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| Invalid)
}
pub fn json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read(path, 16384)?).map_err(|_| Invalid)
}
pub fn create_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| Invalid)?;
    if bytes.len() > 16384 {
        return Err(Invalid);
    }
    create(path, &bytes)
}
pub fn key(path: &Path) -> Result<SigningKey> {
    let bytes = Zeroizing::new(read(path, 32)?);
    let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Invalid)?;
    let secret = Zeroizing::new(secret);
    Ok(SigningKey::from_bytes(&secret))
}
pub fn create_key(path: &Path) -> Result<SigningKey> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *secret).map_err(|_| Invalid)?;
    let key = SigningKey::from_bytes(&secret);
    create(path, &*secret)?;
    Ok(key)
}
