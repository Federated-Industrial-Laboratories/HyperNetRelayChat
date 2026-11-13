// SPDX-License-Identifier: Apache-2.0
//! Per-desktop activation prevents a second GUI from locking the same profile.
use super::Options;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixDatagram,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Instance {
    _lock: File,
    socket: UnixDatagram,
    path: PathBuf,
}
fn runtime_directory(path: &Path) -> Result<(), &'static str> {
    let owner = unsafe { libc::geteuid() };
    let metadata = fs::symlink_metadata(path).map_err(|_| "DesktopRuntimeUnavailable")?;
    if !path.is_absolute()
        || path
            .canonicalize()
            .map_err(|_| "DesktopRuntimeUnavailable")?
            != path
        || !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.mode() & 0o022 != 0
    {
        return Err("DesktopRuntimeUnavailable");
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| "DesktopRuntimeUnavailable")?;
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err("DesktopRuntimeUnavailable");
        }
    }
    Ok(())
}
struct SocketDirectory(PathBuf);
impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("Socket"));
        let _ = fs::remove_dir(&self.0);
    }
}
fn private_activation_socket(
    directory: &Path,
) -> Result<(SocketDirectory, UnixDatagram), &'static str> {
    let nonce = hrc::protocol::Id::random().map_err(|_| "DesktopActivationUnavailable")?;
    let path = directory.join(format!(".hrc-desktop-{nonce}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| "DesktopActivationUnavailable")?;
    let staging = SocketDirectory(path);
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staging.0)
        .map_err(|_| "DesktopActivationUnavailable")?;
    let metadata = handle
        .metadata()
        .map_err(|_| "DesktopActivationUnavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("DesktopActivationUnavailable");
    }
    let socket = UnixDatagram::bind(format!("/proc/self/fd/{}/Socket", handle.as_raw_fd()))
        .map_err(|_| "DesktopActivationUnavailable")?;
    let path = staging.0.join("Socket");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "DesktopActivationUnavailable")?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| "DesktopActivationUnavailable")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("DesktopActivationUnavailable");
    }
    Ok((staging, socket))
}
impl Instance {
    pub fn acquire(options: &Options) -> Result<Option<Self>, &'static str> {
        let directory = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("DesktopRuntimeUnavailable")?;
        Self::acquire_in(&directory, options)
    }
    fn acquire_in(directory: &Path, options: &Options) -> Result<Option<Self>, &'static str> {
        runtime_directory(directory)?;
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
        let (staging, socket) = private_activation_socket(directory)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| "DesktopActivationUnavailable")?;
        fs::rename(staging.0.join("Socket"), &path).map_err(|_| "DesktopActivationUnavailable")?;
        drop(staging);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("HI{}", hrc::protocol::Id::random().unwrap()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root)
        }
        fn runtime(&self) -> PathBuf {
            let path = self.0.join("Runtime");
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            path
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn desktop_runtime_stages_private_socket_before_atomic_publication() {
        let directory = Directory::new();
        let runtime = directory.runtime();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o711)).unwrap();
        let (staging, socket) = private_activation_socket(&runtime).unwrap();
        let staged_path = staging.0.clone();
        assert_eq!(fs::metadata(&staged_path).unwrap().mode() & 0o7777, 0o700);
        let metadata = fs::symlink_metadata(staged_path.join("Socket")).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert!(!runtime.join("hrc-desktop.sock").exists());
        let refused_destination = runtime.join("Occupied");
        fs::create_dir(&refused_destination).unwrap();
        assert!(fs::rename(staged_path.join("Socket"), &refused_destination).is_err());
        drop(socket);
        drop(staging);
        assert!(!staged_path.exists());
        assert!(refused_destination.is_dir());
    }

    #[test]
    fn desktop_runtime_preserves_private_activation_on_traversable_parent() {
        for mode in [0o700, 0o711] {
            let directory = Directory::new();
            let runtime = directory.runtime();
            fs::set_permissions(&runtime, fs::Permissions::from_mode(mode)).unwrap();
            let primary = Instance::acquire_in(&runtime, &Options::default())
                .unwrap()
                .unwrap();
            let lock = fs::symlink_metadata(runtime.join("hrc-desktop.lock")).unwrap();
            let socket = fs::symlink_metadata(runtime.join("hrc-desktop.sock")).unwrap();
            assert!(lock.is_file() && socket.file_type().is_socket());
            for metadata in [&lock, &socket] {
                assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
                assert_eq!(metadata.mode() & 0o7777, 0o600);
            }
            let activation = Options {
                profile: Some(PathBuf::from("/selected/profile")),
                offline: true,
                setup: true,
            };
            assert!(
                Instance::acquire_in(&runtime, &activation)
                    .unwrap()
                    .is_none()
            );
            let requests = primary.requests();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                serde_json::to_value(&requests[0]).unwrap(),
                serde_json::to_value(&activation).unwrap()
            );
            assert_eq!(fs::metadata(&runtime).unwrap().mode() & 0o7777, mode);
            if mode == 0o711 {
                assert!(hrc::service::files::directory(&runtime, false).is_err());
            }
            drop(primary);
            assert!(!runtime.join("hrc-desktop.sock").exists());
            assert!(
                Instance::acquire_in(&runtime, &Options::default())
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn desktop_runtime_refuses_replaceable_foreign_and_linked_parents() {
        let directory = Directory::new();
        let runtime = directory.runtime();
        for mode in [0o770, 0o707, 0o777] {
            fs::set_permissions(&runtime, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                runtime_directory(&runtime),
                Err("DesktopRuntimeUnavailable")
            );
        }
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o711)).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o722)).unwrap();
        assert!(runtime_directory(&runtime).is_err());
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.0.join("Linked");
        symlink(&runtime, &link).unwrap();
        assert!(runtime_directory(&link).is_err());
        let child = runtime.join("Child");
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        assert!(runtime_directory(&link.join("Child")).is_err());
        let file = directory.0.join("File");
        fs::write(&file, []).unwrap();
        assert!(runtime_directory(&file).is_err());
        assert!(runtime_directory(Path::new("Runtime")).is_err());
        if unsafe { libc::geteuid() } != 0 {
            assert!(runtime_directory(Path::new("/")).is_err());
        }
    }

    #[test]
    fn desktop_runtime_refuses_nonprivate_linked_and_aliased_locks() {
        let directory = Directory::new();
        let runtime = directory.runtime();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o711)).unwrap();
        let target = directory.0.join("Retained");
        hrc::service::files::create(&target, b"retained").unwrap();
        let lock = runtime.join("hrc-desktop.lock");
        fs::write(&lock, b"private").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Instance::acquire_in(&runtime, &Options::default()),
            Err("DesktopLockUnavailable")
        ));
        assert_eq!(fs::read(&lock).unwrap(), b"private");
        fs::remove_file(&lock).unwrap();
        symlink(&target, &lock).unwrap();
        assert!(matches!(
            Instance::acquire_in(&runtime, &Options::default()),
            Err("DesktopLockUnavailable")
        ));
        fs::remove_file(&lock).unwrap();
        fs::hard_link(&target, &lock).unwrap();
        assert!(matches!(
            Instance::acquire_in(&runtime, &Options::default()),
            Err("DesktopLockUnavailable")
        ));
        assert_eq!(fs::read(&target).unwrap(), b"retained");
        assert!(!runtime.join("hrc-desktop.sock").exists());
    }
}
