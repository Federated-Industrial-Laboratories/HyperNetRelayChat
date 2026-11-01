//! Owner-private files and the single-writer lease.
use super::{Error, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub struct Key(Zeroizing<[u8; 32]>);
impl Key {
    /// Create a new random key. Existing files are never overwritten.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        parent(path)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::Unavailable)?;
        let mut file = create(path)?;
        file.write_all(bytes.as_ref())
            .map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        sync_directory(path.parent().ok_or(Error::Path)?)?;
        Ok(Self(bytes))
    }
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        parent(path)?;
        let mut file = open(path, false)?;
        if file.metadata().map_err(|_| Error::Unavailable)?.len() != 32 {
            return Err(Error::Key);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        file.read_exact(bytes.as_mut()).map_err(|_| Error::Key)?;
        Ok(Self(bytes))
    }
    pub(super) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(super) fn directory(path: &Path) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| Error::Path)? != path {
        return Err(Error::Path);
    }
    let m = fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    // The effective UID owns both the process and its private data directory.
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
        return Err(Error::Permissions);
    }
    Ok(())
}
pub(super) fn directory_identity(path: &Path) -> Result<(u64, u64)> {
    directory(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    Ok((metadata.dev(), metadata.ino()))
}
pub(super) fn file_identity(path: &Path) -> Result<(u64, u64)> {
    let metadata = open(path, false)?
        .metadata()
        .map_err(|_| Error::Unavailable)?;
    Ok((metadata.dev(), metadata.ino()))
}
pub(super) fn parent(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(Error::Path);
    }
    directory(path.parent().ok_or(Error::Path)?)
}
fn validate(path: &Path, file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| Error::Unavailable)?;
    let p = fs::symlink_metadata(path).map_err(|_| Error::Path)?;
    if !m.is_file()
        || !p.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || (m.dev(), m.ino()) != (p.dev(), p.ino())
    {
        return Err(Error::Permissions);
    }
    Ok(())
}
pub(super) fn create(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Exists
            } else {
                Error::Unavailable
            }
        })?;
    validate(path, &file)?;
    Ok(file)
}
pub(super) fn open(path: &Path, write: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    validate(path, &file)?;
    Ok(file)
}
pub(super) fn lock(directory: &Path) -> Result<File> {
    let path = directory.join("Writer.lock");
    let file = match create(&path) {
        Ok(f) => f,
        Err(Error::Exists) => open(&path, true)?,
        Err(e) => return Err(e),
    };
    // flock is nonblocking and applies to this owned descriptor until Store drops.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Busy);
    }
    Ok(file)
}
pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| Error::Unavailable)
}
pub(super) fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = open(path, false)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(Error::Continuity);
    }
    Ok(bytes)
}
pub(super) fn replace(directory: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
    let temporary = directory.join(format!("Guard-{}.pending", hex::encode(nonce)));
    let result = (|| {
        let mut file = create(&temporary)?;
        file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        file.sync_all().map_err(|_| Error::Unavailable)?;
        fs::rename(&temporary, target).map_err(|_| Error::Unavailable)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub(super) fn database_files(directory: &Path) -> [PathBuf; 3] {
    [
        directory.join("History.db"),
        directory.join("History.db-wal"),
        directory.join("History.db-shm"),
    ]
}
pub(super) fn check_sidecars(directory: &Path) -> Result<()> {
    for path in database_files(directory) {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                open(&path, true)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}
