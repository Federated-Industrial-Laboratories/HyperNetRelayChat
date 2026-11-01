// SPDX-License-Identifier: Apache-2.0
//! Borrow the same SQLCipher transaction for OpenMLS and application state.
use super::*;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};

#[derive(Default)]
pub(super) struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> std::result::Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}
pub(super) struct Provider<'a> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, &'a Connection>,
}
impl<'a> Provider<'a> {
    pub fn new(connection: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}
impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, &'a Connection>;
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

/// Run at exclusive profile startup, before admission. Provider migration code
/// builds its empty schema in memory; only that DDL enters the guarded database.
/// No MLS key, content, or live profile is placed in the temporary connection.
pub fn initialize(store: &mut Store) -> Result<()> {
    let current = store.read(std::time::Duration::from_secs(1), |conn| {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='crypto_schema')",
            [],
            |r| r.get(0),
        )?;
        if exists {
            conn.query_row("SELECT version FROM crypto_schema", [], |r| {
                r.get::<_, u32>(0)
            })
            .map(Some)
        } else {
            Ok(None)
        }
    })?;
    if let Some(version) = current {
        return if version == 2 {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    let mut connection = Connection::open_in_memory()?;
    let mut provider = SqliteStorageProvider::<JsonCodec, _>::new(&mut connection);
    provider.run_migrations().map_err(|_| Error::Database)?;
    let ddl:Vec<String>=connection.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END,name")?.query_map([],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
    atomic(
        store,
        "schema",
        b"OpenMLS 0.9.1/sqlite storage 0.3.0/HRC 2",
        |tx| {
            for sql in ddl {
                tx.execute_batch(&sql)?;
            }
            tx.execute_batch(SCHEMA)?;
            Ok(((), b"schema 2".to_vec()))
        },
    )
}
const SCHEMA: &str = r#"
CREATE TABLE crypto_schema(version INTEGER NOT NULL CHECK(version=2));
INSERT INTO crypto_schema VALUES(2);
CREATE TABLE crypto_devices(endpoint BLOB PRIMARY KEY,actor BLOB NOT NULL,key BLOB NOT NULL);
CREATE TABLE crypto_groups(id BLOB PRIMARY KEY,room BLOB NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('member','public')),cursor INTEGER NOT NULL,frozen INTEGER NOT NULL DEFAULT 0,sends INTEGER NOT NULL DEFAULT 0,gaps INTEGER NOT NULL DEFAULT 0);
CREATE TABLE crypto_packages(digest BLOB PRIMARY KEY,endpoint BLOB NOT NULL,room BLOB NOT NULL,bytes BLOB NOT NULL,package_ref BLOB NOT NULL);
CREATE TABLE crypto_creation(group_id BLOB PRIMARY KEY,request BLOB NOT NULL,info BLOB NOT NULL);
CREATE TABLE crypto_transitions(group_id BLOB NOT NULL,sequence INTEGER NOT NULL,input_digest BLOB NOT NULL,result BLOB NOT NULL,PRIMARY KEY(group_id,sequence));
CREATE TABLE crypto_joins(group_id BLOB PRIMARY KEY,input_digest BLOB NOT NULL,result BLOB NOT NULL);
CREATE TABLE crypto_pending(group_id BLOB PRIMARY KEY,epoch INTEGER NOT NULL,request BLOB NOT NULL,commit_bytes BLOB NOT NULL,welcome BLOB,roster BLOB NOT NULL);
CREATE TABLE crypto_outbox(operation BLOB PRIMARY KEY,window_id BLOB NOT NULL,group_id BLOB NOT NULL,epoch INTEGER NOT NULL,input_digest BLOB NOT NULL,context BLOB NOT NULL,ciphertext BLOB NOT NULL,action BLOB NOT NULL,plaintext BLOB NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','committed','rejected','abandoned')));
CREATE UNIQUE INDEX crypto_one_pending_sender ON crypto_outbox(group_id) WHERE state='pending';
CREATE TABLE crypto_deliveries(group_id BLOB NOT NULL,sequence INTEGER NOT NULL,event BLOB NOT NULL,digest BLOB NOT NULL,result BLOB NOT NULL,PRIMARY KEY(group_id,sequence));
CREATE TABLE crypto_approvals(operation BLOB PRIMARY KEY,window_id BLOB NOT NULL,group_id BLOB NOT NULL,epoch INTEGER NOT NULL,sender BLOB NOT NULL,digest BLOB NOT NULL,result BLOB NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','delivered')));
CREATE UNIQUE INDEX crypto_one_preview ON crypto_approvals(group_id,sender) WHERE state IN ('pending','approved');
CREATE TABLE crypto_closed_windows(id BLOB PRIMARY KEY);
"#;
