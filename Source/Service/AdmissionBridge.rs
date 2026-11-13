// SPDX-License-Identifier: Apache-2.0
//! An isolated registrar sees one authenticated request socket, never Home administrative files.
use super::*;
use std::{
    fs,
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
        },
    },
    path::Component,
};

const FORMAT: &str = "HyperNet.HrcAdmission.Bridge/1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub directory: PathBuf,
    pub uid: u32,
}
impl Configuration {
    pub fn validate(&self) -> files::Result<()> {
        if !self.directory.is_absolute()
            || self.directory.as_os_str().len() > 4096
            || self.directory.components().count() < 2
            || self
                .directory
                .components()
                .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
            || self.uid == u32::MAX
        {
            return Err(files::Invalid);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Challenge {
    pub format: String,
    pub home: ServiceId,
    pub boot: Id,
    pub nonce: Id,
    pub expires_boot_ms: u64,
}
impl Challenge {
    pub(crate) fn new(home: ServiceId, boot: Id) -> files::Result<Self> {
        Ok(Self {
            format: FORMAT.into(),
            home,
            boot,
            nonce: Id::random().map_err(|_| files::Invalid)?,
            expires_boot_ms: crate::clock::boot_ms().map_err(|_| files::Invalid)? + 5000,
        })
    }
}
pub(crate) fn peer(stream: &UnixStream, uid: u32) -> files::Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || credentials.uid != uid
    {
        return Err(files::Invalid);
    }
    Ok(())
}
/// A full local accept queue must refuse immediately, not block outside the frame deadline.
pub(crate) fn connect(path: &Path) -> files::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(files::Invalid);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
        *out = *byte as libc::c_char;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(files::Invalid);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let socket = UnixStream::from(fd);
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(files::Invalid);
    }
    socket.set_nonblocking(false).map_err(|_| files::Invalid)?;
    Ok(socket)
}
/// Retain a directory descriptor so long host paths do not enlarge Unix addresses.
pub(crate) fn directory(path: &Path, owner: u32, create: bool) -> files::Result<(File, PathBuf)> {
    Configuration {
        directory: path.to_owned(),
        uid: owner,
    }
    .validate()?;
    let mut walked = PathBuf::new();
    for part in path.parent().ok_or(files::Invalid)?.components() {
        walked.push(part);
        let meta = fs::symlink_metadata(&walked).map_err(|_| files::Invalid)?;
        // A root-owned sticky temporary directory may contain the private test
        // or runtime parent. Other ancestors must not permit outsider writes.
        let sticky_root = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != owner)
            || (meta.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(files::Invalid);
        }
    }
    if create && !path.exists() {
        fs::DirBuilder::new()
            .mode(0o711)
            .create(path)
            .map_err(|_| files::Invalid)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o711)).map_err(|_| files::Invalid)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| files::Invalid)?;
    let held = file.metadata().map_err(|_| files::Invalid)?;
    let current = fs::symlink_metadata(path).map_err(|_| files::Invalid)?;
    if !current.is_dir()
        || (held.dev(), held.ino()) != (current.dev(), current.ino())
        || held.uid() != owner
        || held.mode() & 0o7777 != 0o711
    {
        return Err(files::Invalid);
    }
    let socket = PathBuf::from(format!("/proc/self/fd/{}/Admission.sock", file.as_raw_fd()));
    Ok((file, socket))
}
pub(super) fn call(
    binding: &Binding,
    owner: u32,
    key: &SigningKey,
    control: Control,
) -> files::Result<serde_json::Value> {
    if !matches!(control, Control::Request { .. }) {
        return Err(files::Invalid);
    }
    let (_directory, socket) = directory(&binding.directory, owner, false)?;
    let metadata = fs::symlink_metadata(&socket).map_err(|_| files::Invalid)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner
        || metadata.mode() & 0o7777 != 0o666
        || metadata.nlink() != 1
    {
        return Err(files::Invalid);
    }
    let mut stream = connect(&socket)?;
    peer(&stream, owner)?;
    let end = Instant::now() + Duration::from_secs(5);
    let envelope = receive(&mut stream, end)?;
    if envelope.signer != binding.service_key {
        return Err(files::Invalid);
    }
    let challenge: Challenge = verify(&envelope)?;
    let current = crate::clock::boot_ms().map_err(|_| files::Invalid)?;
    if challenge.format != FORMAT
        || challenge.home != binding.home
        || challenge.expires_boot_ms <= current
        || challenge.expires_boot_ms > current + 5000
        || challenge.nonce.as_bytes() == &[0; 32]
    {
        return Err(files::Invalid);
    }
    let payload = Payload {
        home: binding.home,
        boot: challenge.boot,
        nonce: challenge.nonce,
        expires_boot_ms: challenge.expires_boot_ms,
        control,
    };
    send(&mut stream, &payload, key, end)?;
    let envelope = receive(&mut stream, end)?;
    if envelope.signer != binding.service_key {
        return Err(files::Invalid);
    }
    let reply: Reply = verify(&envelope)?;
    if reply.boot != challenge.boot || reply.nonce != challenge.nonce {
        return Err(files::Invalid);
    }
    Ok(reply.result)
}
