// SPDX-License-Identifier: Apache-2.0
//! Per-desktop activation prevents a second GUI from locking the same profile.
use super::Options;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixDatagram,
        },
    },
    path::PathBuf,
    time::Duration,
};

pub(super) struct Instance {
    _lock: File,
    socket: UnixDatagram,
    path: PathBuf,
}
impl Instance {
    pub fn acquire(options: &Options) -> Result<Option<Self>, &'static str> {
        let directory = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("DesktopRuntimeUnavailable")?;
        hrc::service::files::directory(&directory, false)
            .map_err(|_| "DesktopRuntimeUnavailable")?;
        let lock_path = directory.join("hrc-desktop.lock");
        let mut lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lock_path)
            .map_err(|_| "DesktopLockUnavailable")?;
        let meta = lock.metadata().map_err(|_| "DesktopLockUnavailable")?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.mode() & 0o7777 != 0o600
        {
            return Err("DesktopLockUnavailable");
        }
        let path = directory.join("hrc-desktop.sock");
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err("DesktopLockUnavailable");
            }
            let bytes = serde_json::to_vec(options).map_err(|_| "InvalidDesktopRequest")?;
            if bytes.len() > 4096 {
                return Err("InvalidDesktopRequest");
            }
            let socket = UnixDatagram::unbound().map_err(|_| "DesktopActivationUnavailable")?;
            socket
                .set_write_timeout(Some(Duration::from_millis(100)))
                .map_err(|_| "DesktopActivationUnavailable")?;
            for _ in 0..10 {
                if socket.send_to(&bytes, &path).is_ok() {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            return Err("DesktopActivationUnavailable");
        }
        lock.set_len(0)
            .and_then(|()| write!(lock, "{}", std::process::id()))
            .map_err(|_| "DesktopLockUnavailable")?;
        match fs::remove_file(&path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("DesktopActivationUnavailable"),
        }
        let socket = UnixDatagram::bind(&path).map_err(|_| "DesktopActivationUnavailable")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "DesktopActivationUnavailable")?;
        socket
            .set_nonblocking(true)
            .map_err(|_| "DesktopActivationUnavailable")?;
        Ok(Some(Self {
            _lock: lock,
            socket,
            path,
        }))
    }
    pub fn requests(&self) -> Vec<Options> {
        let mut result = Vec::new();
        let mut bytes = [0; 4097];
        for _ in 0..8 {
            let Ok(size) = self.socket.recv(&mut bytes) else {
                break;
            };
            if size <= 4096
                && let Ok(request) = serde_json::from_slice(&bytes[..size])
            {
                result.push(request);
            }
        }
        result
    }
}
impl Drop for Instance {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
