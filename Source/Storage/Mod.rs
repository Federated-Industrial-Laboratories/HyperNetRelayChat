//! Encrypted local persistence with one writer and an independent continuity guard.
#[path = "Continuity.rs"]
mod continuity;
#[path = "Engine.rs"]
mod engine;
#[path = "Files.rs"]
mod files;
use continuity::Head;
pub use engine::{SQLCIPHER_VERSION, SQLITE_SOURCE_ID, SQLITE_VERSION};
pub use files::Key;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage path is not a canonical private location")]
    Path,
    #[error("storage permissions or file identity differ")]
    Permissions,
    #[error("storage already exists")]
    Exists,
    #[error("storage writer is busy")]
    Busy,
    #[error("approved SQLCipher engine is unavailable")]
    Engine,
    #[error("database key or encrypted pages are invalid")]
    Key,
    #[error("database operation failed")]
    Database,
    #[error("storage continuity cannot be established")]
    Continuity,
    #[error("storage is fenced until its durable outcome is recovered")]
    Fenced,
    #[error("storage quota is exhausted")]
    Quota,
    #[error("storage operation deadline expired")]
    Deadline,
    #[error("invalid storage operation")]
    InvalidInput,
    #[error("storage is unavailable")]
    Unavailable,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Path => "InvalidPath",
            Self::Permissions => "InvalidPermissions",
            Self::Exists => "Exists",
            Self::Busy => "Overloaded",
            Self::Engine => "UnsupportedStorage",
            Self::Key => "InvalidKeyOrData",
            Self::Database => "StorageFailure",
            Self::Continuity => "ContinuityLost",
            Self::Fenced => "OutcomeUnknown",
            Self::Quota => "StorageQuota",
            Self::Deadline => "DeadlineExceeded",
            Self::InvalidInput => "InvalidInput",
            Self::Unavailable => "Unavailable",
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            Some(rusqlite::ErrorCode::DiskFull) => Self::Quota,
            Some(rusqlite::ErrorCode::OperationInterrupted) => Self::Deadline,
            _ => Self::Database,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_database_bytes: u64,
    pub max_wal_bytes: u64,
    pub max_change_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_database_bytes: 16 * 1024 * 1024 * 1024,
            max_wal_bytes: 64 * 1024 * 1024,
            max_change_bytes: 64 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<Self> {
        if !(64 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.max_database_bytes)
            || !(64 * 1024..=256 * 1024 * 1024).contains(&self.max_wal_bytes)
            || !(32..=256 * 1024).contains(&self.max_change_bytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(self)
    }
}
/// The feature owner supplies its exact bounded authoritative change record.
pub struct Commit<T> {
    value: T,
    change: Vec<u8>,
}
impl<T> Commit<T> {
    pub fn new(value: T, change: Vec<u8>) -> Self {
        Self { value, change }
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub database_bytes: u64,
    pub wal_bytes: u64,
    pub commit_counter: u64,
}

pub struct Store {
    connection: Connection,
    directory: PathBuf,
    guard_directory: PathBuf,
    head: Head,
    limits: Limits,
    fenced: bool,
    _lease: File,
    path_identities: [(u64, u64); 3],
    #[cfg(test)]
    fail_after_commit: bool,
}
impl Store {
    fn locations(directory: &Path, guard_directory: &Path) -> Result<()> {
        files::directory(directory)?;
        files::directory(guard_directory)?;
        if directory.starts_with(guard_directory) || guard_directory.starts_with(directory) {
            return Err(Error::Path);
        }
        Ok(())
    }
    pub fn create(
        directory: impl AsRef<Path>,
        guard_directory: impl AsRef<Path>,
        key: &Key,
        identity: [u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        let directory = directory.as_ref();
        let guard_directory = guard_directory.as_ref();
        Self::locations(directory, guard_directory)?;
        let limits = limits.validate()?;
        if identity == [0; 32] {
            return Err(Error::InvalidInput);
        }
        let lease = files::lock(directory)?;
        if directory
            .join("History.db")
            .try_exists()
            .map_err(|_| Error::Unavailable)?
            || guard_directory
                .join("Continuity.json")
                .try_exists()
                .map_err(|_| Error::Unavailable)?
        {
            return Err(Error::Exists);
        }
        files::create(&directory.join("History.db"))?
            .sync_all()
            .map_err(|_| Error::Unavailable)?;
        files::sync_directory(directory)?;
        let mut connection = engine::open(&directory.join("History.db"), key, limits)?;
        let head = Head::initial(identity);
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        head.create(&transaction)?;
        transaction.commit()?;
        head.persist(guard_directory)?;
        let mut store = Self {
            connection,
            directory: directory.to_owned(),
            guard_directory: guard_directory.to_owned(),
            head,
            limits,
            fenced: false,
            _lease: lease,
            path_identities: [
                files::directory_identity(directory)?,
                files::directory_identity(guard_directory)?,
                files::file_identity(&directory.join("History.db"))?,
            ],
            #[cfg(test)]
            fail_after_commit: false,
        };
        store.checkpoint()?;
        Ok(store)
    }
    pub fn open(
        directory: impl AsRef<Path>,
        guard_directory: impl AsRef<Path>,
        key: &Key,
        identity: [u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        let directory = directory.as_ref();
        let guard_directory = guard_directory.as_ref();
        Self::locations(directory, guard_directory)?;
        let limits = limits.validate()?;
        let lease = files::lock(directory)?;
        files::open(&directory.join("History.db"), true)?;
        files::check_sidecars(directory)?;
        let guard = Head::load_guard(guard_directory)?;
        if guard.identity != identity {
            return Err(Error::Continuity);
        }
        let connection = engine::open(&directory.join("History.db"), key, limits)?;
        let head = Head::load(&connection)?;
        if head.identity != identity {
            return Err(Error::Continuity);
        }
        if head.reconcile(&guard)? {
            head.persist(guard_directory)?;
        }
        let mut store = Self {
            connection,
            directory: directory.to_owned(),
            guard_directory: guard_directory.to_owned(),
            head,
            limits,
            fenced: false,
            _lease: lease,
            path_identities: [
                files::directory_identity(directory)?,
                files::directory_identity(guard_directory)?,
                files::file_identity(&directory.join("History.db"))?,
            ],
            #[cfg(test)]
            fail_after_commit: false,
        };
        store.checkpoint()?;
        Ok(store)
    }
    pub fn identity(&self) -> [u8; 32] {
        self.head.identity
    }
    pub fn commit_counter(&self) -> u64 {
        self.head.counter
    }
    pub fn is_fenced(&self) -> bool {
        self.fenced
    }
    pub fn usage(&self) -> Result<Usage> {
        let size = |path: &Path| -> Result<u64> {
            match fs::symlink_metadata(path) {
                Ok(meta) if meta.is_file() => Ok(meta.len()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
                _ => Err(Error::Permissions),
            }
        };
        Ok(Usage {
            database_bytes: size(&self.directory.join("History.db"))?,
            wal_bytes: size(&self.directory.join("History.db-wal"))?,
            commit_counter: self.head.counter,
        })
    }
    fn ready(&mut self) -> Result<()> {
        if self.fenced {
            return Err(Error::Fenced);
        }
        let current = (|| {
            let identities = [
                files::directory_identity(&self.directory)?,
                files::directory_identity(&self.guard_directory)?,
                files::file_identity(&self.directory.join("History.db"))?,
            ];
            if identities != self.path_identities
                || Head::load_guard(&self.guard_directory)? != self.head
            {
                return Err(Error::Continuity);
            }
            files::check_sidecars(&self.directory)
        })();
        if current.is_err() {
            self.fenced = true;
        }
        current
    }
    fn capacity(&self) -> Result<()> {
        let usage = self.usage()?;
        if usage.database_bytes > self.limits.max_database_bytes
            || usage.wal_bytes >= self.limits.max_wal_bytes
        {
            return Err(Error::Quota);
        }
        Ok(())
    }
    /// Commit feature state and its continuity record, then persist the guard before returning.
    pub fn write<T>(
        &mut self,
        operation: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<Commit<T>>,
    ) -> Result<T> {
        self.ready()?;
        self.capacity()?;
        let deadline = engine::deadline(Duration::from_secs(2))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.fenced = true;
        let scope = engine::Scope::install(&transaction, deadline, false);
        let result = operation(&transaction);
        let expired = scope.expired();
        drop(scope);
        let change = match result {
            Ok(change) if !expired => change,
            result => {
                transaction.finish().map_err(|_| Error::Fenced)?;
                self.fenced = false;
                return Err(if expired {
                    Error::Deadline
                } else {
                    result.err().map(Error::from).unwrap_or(Error::Database)
                });
            }
        };
        if change.change.is_empty() || change.change.len() > self.limits.max_change_bytes {
            transaction.finish().map_err(|_| Error::Fenced)?;
            self.fenced = false;
            return Err(Error::InvalidInput);
        }
        let next = match self.head.next(&change.change).and_then(|next| {
            next.update(&transaction, &self.head)?;
            Ok(next)
        }) {
            Ok(next) => next,
            Err(error) => {
                transaction.finish().map_err(|_| Error::Fenced)?;
                self.fenced = false;
                return Err(error);
            }
        };
        transaction.commit().map_err(|_| Error::Fenced)?;
        self.head = next;
        #[cfg(test)]
        if self.fail_after_commit {
            return Err(Error::Fenced);
        }
        self.head
            .persist(&self.guard_directory)
            .map_err(|_| Error::Fenced)?;
        // The single connection holds no reader at this point; trim retained WAL bytes.
        self.checkpoint_inner().map_err(|_| Error::Fenced)?;
        self.fenced = false;
        Ok(change.value)
    }
    /// Run a bounded, read-only snapshot. The closure cannot change storage settings.
    pub fn read<T>(
        &mut self,
        timeout: Duration,
        operation: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T> {
        self.ready()?;
        let deadline = engine::deadline(timeout)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let scope = engine::Scope::install(&transaction, deadline, true);
        let result = operation(&transaction);
        let expired = scope.expired();
        drop(scope);
        transaction.finish()?;
        if expired {
            return Err(Error::Deadline);
        }
        result.map_err(Error::from)
    }
    fn checkpoint_inner(&self) -> Result<()> {
        let (busy, _, _): (u64, u64, u64) =
            self.connection
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        if busy != 0 {
            return Err(Error::Busy);
        }
        files::check_sidecars(&self.directory)?;
        self.capacity()
    }
    pub fn checkpoint(&mut self) -> Result<()> {
        self.ready()?;
        self.checkpoint_inner()
    }
}

#[cfg(test)]
#[path = "../../Tests/Storage/Store.rs"]
mod tests;
