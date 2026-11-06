// SPDX-License-Identifier: Apache-2.0
//! Fixed native commands, bounded pipes, and cancellation without shell interpretation.
use super::{Error, Result};
use hrc::service::files;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub(crate) fn public_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| Error::LocalConfiguration)? != path {
        return Err(Error::LocalConfiguration);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error::LocalConfiguration)?;
    let m = file.metadata().map_err(|_| Error::LocalConfiguration)?;
    if !m.is_file()
        || m.len() > maximum as u64
        || m.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
    {
        return Err(Error::LocalConfiguration);
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::LocalConfiguration)?;
    if bytes.len() > maximum {
        return Err(Error::OutputLimit);
    }
    Ok(bytes)
}
pub(crate) fn executable(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.canonicalize().map_err(|_| Error::RuntimeMissing)? != path {
        return Err(Error::RuntimeMissing);
    }
    let m = fs::symlink_metadata(path).map_err(|_| Error::RuntimeMissing)?;
    if !m.is_file()
        || m.mode() & 0o022 != 0
        || m.mode() & 0o111 == 0
        || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
    {
        return Err(Error::RuntimeMissing);
    }
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent).map_err(|_| Error::RuntimeMissing)?;
        if !m.is_dir()
            || m.mode() & 0o022 != 0
            || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
        {
            return Err(Error::RuntimeMissing);
        }
    }
    Ok(())
}
pub(crate) fn discover(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(name))
                .filter_map(|p| p.canonicalize().ok())
                .find(|p| executable(p).is_ok())
        })
        .unwrap_or_default()
}
pub(crate) fn directory(path: &Path) -> Result<()> {
    files::directory(path, !path.exists())
        .map(|_| ())
        .map_err(|_| Error::LocalConfiguration)
}
pub(crate) fn exact_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if files::read(path, bytes.len()).map_err(|_| Error::LocalConfiguration)? != bytes {
            return Err(Error::BundleBinding);
        }
        return Ok(());
    }
    files::create(path, bytes).map_err(|_| Error::LocalConfiguration)
}
pub(crate) fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::LocalConfiguration)?;
    files::directory(parent, false).map_err(|_| Error::LocalConfiguration)?;
    if path.exists() {
        files::read(path, 65536).map_err(|_| Error::LocalConfiguration)?;
    }
    let name = hrc::protocol::Id::random()
        .map_err(|_| Error::LocalConfiguration)?
        .as_hex();
    let temporary = parent.join(format!(".setup-{name}"));
    files::create(&temporary, bytes).map_err(|_| Error::LocalConfiguration)?;
    let outcome = fs::rename(&temporary, path).and_then(|_| fs::File::open(parent)?.sync_all());
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome.map_err(|_| Error::LocalConfiguration)
}
pub(crate) fn check(cancel: &AtomicBool, end: Instant) -> Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    Ok(())
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            // Only the process group created below belongs to this command.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn nonblocking(pipe: &impl AsRawFd) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::NativeRefused);
    }
    Ok(())
}
fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, maximum: usize) -> Result<bool> {
    loop {
        let mut buffer = [0; 4096];
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if bytes.len().saturating_add(n) > maximum {
                    return Err(Error::OutputLimit);
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::NativeRefused),
        }
    }
}
pub(crate) fn run(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Vec<u8>> {
    check(cancel, end)?;
    executable(program)?;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = OwnedChild(command.spawn().map_err(|_| Error::NativeRefused)?);
    let mut stdout = child.0.stdout.take().ok_or(Error::NativeRefused)?;
    let mut stderr = child.0.stderr.take().ok_or(Error::NativeRefused)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        check(cancel, end)?;
        let out_done = drain(&mut stdout, &mut out, 2 * 1024 * 1024)?;
        let err_done = drain(&mut stderr, &mut err, 65536)?;
        if let Some(status) = child.0.try_wait().map_err(|_| Error::NativeRefused)?
            && out_done
            && err_done
        {
            check(cancel, end)?;
            return if status.success() {
                Ok(out)
            } else {
                Err(Error::NativeRefused)
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(crate) fn json(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
) -> Result<serde_json::Value> {
    serde_json::from_slice(&run(program, args, cancel, end)?).map_err(|_| Error::NativeRefused)
}
pub(crate) fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
pub(crate) fn current_user() -> Result<String> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16384];
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 || result.is_null() || entry.pw_name.is_null() {
        return Err(Error::LocalConfiguration);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::LocalConfiguration)?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(Error::LocalConfiguration);
    }
    Ok(name.to_owned())
}
pub(crate) fn path(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .filter(|v| !v.chars().any(char::is_control))
        .ok_or(Error::LocalConfiguration)
}
pub(crate) fn private_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let m = fs::symlink_metadata(path).map_err(|_| Error::ClockPrerequisite)?;
    if !m.file_type().is_socket()
        || m.permissions().mode() & 0o002 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
    {
        return Err(Error::ClockPrerequisite);
    }
    Ok(())
}

/// Probe local IPC without blocking on a full listener backlog or deleting stale state.
pub(crate) fn socket_live(path: &Path) -> Result<bool> {
    use std::os::{
        fd::{FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    };
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(Error::LocalConfiguration);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::NativeRefused);
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let status = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if status == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ENOENT | libc::ECONNREFUSED) => Ok(false),
        Some(libc::EAGAIN | libc::EINPROGRESS) => Ok(true),
        _ => Err(Error::NativeRefused),
    }
}
