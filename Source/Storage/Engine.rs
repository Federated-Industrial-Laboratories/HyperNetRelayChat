//! Checked SQLCipher configuration and bounded database execution.
use super::{Error, Key, Limits, Result};
use rusqlite::{
    Connection, OpenFlags,
    config::DbConfig,
    hooks::{AuthAction, AuthContext, Authorization},
};
use std::{path::Path, time::Duration};

// The linked SQLCipher API extends SQLite's generated Rust bindings.
unsafe extern "C" {
    fn sqlite3_key(
        database: *mut rusqlite::ffi::sqlite3,
        key: *const libc::c_void,
        length: libc::c_int,
    ) -> libc::c_int;
}

pub const SQLCIPHER_VERSION: &str = "4.20.0 community";
pub const SQLITE_VERSION: &str = "3.54.1";
pub const SQLITE_SOURCE_ID: &str =
    "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6alt1";

pub(super) fn open(path: &Path, key: &Key, limits: Limits) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let version: String = conn
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .map_err(|_| Error::Engine)?;
    if version != SQLCIPHER_VERSION {
        return Err(Error::Engine);
    }
    // SQLCipher copies this bounded binary secret; no SQL text contains the key.
    let keyed = unsafe { sqlite3_key(conn.handle(), key.bytes().as_ptr().cast(), 32) };
    if keyed != rusqlite::ffi::SQLITE_OK {
        return Err(Error::Key);
    }
    // Authenticate the existing pages before any configuration that can write.
    conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
        r.get::<_, u64>(0)
    })
    .map_err(|_| Error::Key)?;
    let identity: (String, String) = conn
        .query_row("SELECT sqlite_version(),sqlite_source_id()", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(|_| Error::Engine)?;
    if identity.0 != SQLITE_VERSION || identity.1 != SQLITE_SOURCE_ID {
        return Err(Error::Engine);
    }
    for required in ["ENABLE_FTS5", "TEMP_STORE=3", "THREADSAFE=1"] {
        let present: bool =
            conn.query_row("SELECT sqlite_compileoption_used(?1)", [required], |r| {
                r.get(0)
            })?;
        if !present {
            return Err(Error::Engine);
        }
    }
    conn.busy_timeout(Duration::from_millis(25))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    conn.execute_batch("PRAGMA cipher_memory_security=ON; PRAGMA cipher_plaintext_header_size=0; PRAGMA temp_store=MEMORY; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA cache_size=-8192; PRAGMA mmap_size=0;")?;
    let journal: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if journal != "wal" {
        return Err(Error::Engine);
    }
    for (name, expected) in [
        ("synchronous", 2),
        ("foreign_keys", 1),
        ("temp_store", 2),
        ("trusted_schema", 0),
    ] {
        let value: i64 = conn.pragma_query_value(None, name, |r| r.get(0))?;
        if value != expected {
            return Err(Error::Engine);
        }
    }
    for (name, expected) in [
        ("cipher_memory_security", "1"),
        ("cipher_plaintext_header_size", "0"),
    ] {
        let value: String = conn.pragma_query_value(None, name, |r| r.get(0))?;
        if value != expected {
            return Err(Error::Engine);
        }
    }
    // SQLCipher intercepts page_size and returns its codec page size as text.
    let page_text: String = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let page_size: u64 = page_text.parse().map_err(|_| Error::Engine)?;
    if page_size != 4096 {
        return Err(Error::Engine);
    }
    let pages = limits.max_database_bytes / page_size;
    let actual: u64 = conn.pragma_update_and_check(None, "max_page_count", pages, |r| r.get(0))?;
    if actual != pages {
        return Err(Error::Quota);
    }
    let journal_limit: u64 =
        conn.pragma_update_and_check(None, "journal_size_limit", limits.max_wal_bytes, |r| {
            r.get(0)
        })?;
    if journal_limit != limits.max_wal_bytes {
        return Err(Error::Engine);
    }
    Ok(conn)
}

pub(super) fn boot_ms() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_BOOTTIME makes query limits include host suspend.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 || time.tv_sec < 0 {
        return Err(Error::Unavailable);
    }
    (time.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|v| v.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or(Error::Unavailable)
}
pub(super) fn deadline(timeout: Duration) -> Result<u64> {
    let millis = u64::try_from(timeout.as_millis()).map_err(|_| Error::InvalidInput)?;
    if !(1..=2000).contains(&millis) {
        return Err(Error::InvalidInput);
    }
    boot_ms()?.checked_add(millis).ok_or(Error::Unavailable)
}
fn authorise(context: AuthContext<'_>, read_only: bool) -> Authorization {
    use AuthAction::*;
    let permitted = match context.action {
        Select | Read { .. } | Recursive => true,
        // This nested feature boundary can undo tentative effects, but cannot commit the outer writer.
        Savepoint { savepoint_name, .. } => !read_only && savepoint_name == "hrc_domain_effects",
        Function { function_name } => ![
            "load_extension",
            "writefile",
            "readfile",
            "sqlcipher_export",
        ]
        .iter()
        .any(|name| function_name.eq_ignore_ascii_case(name)),
        Pragma {
            pragma_name,
            pragma_value: None,
        } => pragma_name.eq_ignore_ascii_case("data_version"),
        Insert { table_name }
        | Update { table_name, .. }
        | Delete { table_name }
        | CreateTable { table_name }
        | DropTable { table_name }
        | AlterTable { table_name, .. }
        | CreateIndex { table_name, .. }
        | DropIndex { table_name, .. }
        | CreateTrigger { table_name, .. }
        | DropTrigger { table_name, .. }
        | CreateVtable { table_name, .. }
        | DropVtable { table_name, .. }
        | Analyze { table_name } => !read_only && !table_name.starts_with("_hrc_"),
        CreateView { view_name } | DropView { view_name } => {
            !read_only && !view_name.starts_with("_hrc_")
        }
        Reindex { .. } => !read_only,
        _ => false,
    };
    if permitted {
        Authorization::Allow
    } else {
        Authorization::Deny
    }
}
/// Hooks exist only during application SQL, never during the boundary's commit.
pub(super) struct Scope<'a> {
    connection: &'a Connection,
    pub(super) deadline: u64,
}
impl<'a> Scope<'a> {
    pub(super) fn install(connection: &'a Connection, deadline: u64, read_only: bool) -> Self {
        connection.progress_handler(
            500,
            Some(move || !boot_ms().is_ok_and(|now| now < deadline)),
        );
        connection.authorizer(Some(move |context: AuthContext<'_>| {
            authorise(context, read_only)
        }));
        Self {
            connection,
            deadline,
        }
    }
    pub(super) fn expired(&self) -> bool {
        !boot_ms().is_ok_and(|now| now < self.deadline)
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        self.connection.progress_handler(0, None::<fn() -> bool>);
        self.connection
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    }
}
