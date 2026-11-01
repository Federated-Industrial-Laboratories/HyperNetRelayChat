//! Linux adapter to the version-2 HyperNetSuite companion interface.
//!
//! Peer context authenticates transport identities. It does not establish an HRC
//! account, room permission, delegation, or a portable authority certificate.
#[cfg(not(target_os = "linux"))]
compile_error!("The HyperNet companion adapter currently supports Linux only");
#[path = "Authority.rs"]
mod authority;
#[path = "Context.rs"]
mod context;
#[path = "Ipc.rs"]
mod ipc;

pub use authority::{AuthorityCheck, AuthorityObservation, Disposition};
pub use context::{
    Assurance, AuthorityCapability, ConnectionStatus, Direction, IncomingPeer, OutgoingPeer, Peer,
    Privacy, Provenance, RelayPath, Status, TransportProtection,
};
use context::{ControlIdentity, Id};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid bounded operation input")]
    InvalidInput,
    #[error("companion path must be absolute and canonical")]
    Path,
    #[error("companion directory, socket, or peer owner is not private")]
    Ownership,
    #[error("companion path changed during connection")]
    Changed,
    #[error("companion is unavailable")]
    Unavailable,
    #[error("stream closed; the remote operation outcome is unknown")]
    Closed,
    #[error("operation exceeded its original deadline")]
    Timeout,
    #[error("local frame exceeds its size bound")]
    Frame,
    #[error("companion response does not match the bounded protocol")]
    Protocol,
    #[error("companion version 2 is required")]
    UnsupportedVersion,
    #[error("companion stream capacity is exhausted")]
    Capacity,
    #[error("companion refused the request")]
    Refused,
    #[error("stream is not active for this operation")]
    NotActive,
    #[error("concurrent operation is already in progress")]
    Busy,
    #[error("unshifted host boot time is unavailable")]
    Clock,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "InvalidInput",
            Self::Path => "Path",
            Self::Ownership => "Ownership",
            Self::Changed => "Changed",
            Self::Unavailable => "Unavailable",
            Self::Closed => "Closed",
            Self::Timeout => "Timeout",
            Self::Frame => "Frame",
            Self::Protocol => "Protocol",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::Capacity => "Capacity",
            Self::Refused => "Refused",
            Self::NotActive => "NotActive",
            Self::Busy => "Busy",
            Self::Clock => "Clock",
        }
    }
}

#[derive(Default)]
struct State {
    control: Option<ControlIdentity>,
    streams: HashMap<String, Weak<Lifecycle>>,
}
struct Lifecycle {
    state: Mutex<Local>,
}
struct Local {
    active: bool,
    epoch: u64,
    eligible: bool,
    privacy: Privacy,
}
impl Local {
    fn invalidate(&mut self) {
        match self.epoch.checked_add(1) {
            Some(n) => self.epoch = n,
            None => self.active = false,
        }
    }
}
fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock().map_err(|_| Error::Unavailable)
}
impl State {
    fn prune(&mut self) {
        self.streams.retain(|_, value| {
            value
                .upgrade()
                .is_some_and(|life| lock(&life.state).is_ok_and(|local| local.active))
        });
    }
    fn observe(&mut self, identity: ControlIdentity) -> Result<()> {
        if self.control.as_ref() != Some(&identity) {
            self.prune();
            for value in self.streams.values().filter_map(Weak::upgrade) {
                let mut local = lock(&value.state)?;
                local.invalidate();
                local.privacy.mark_historical();
            }
            self.control = Some(identity);
        }
        Ok(())
    }
}

/// One local companion and the live streams obtained through this adapter.
#[derive(Clone)]
pub struct Companion {
    directory: PathBuf,
    state: Arc<Mutex<State>>,
}
impl Companion {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let directory = path.as_ref().to_owned();
        ipc::canonical(&directory)?;
        Ok(Self {
            directory,
            state: Arc::new(Mutex::new(State::default())),
        })
    }
    pub fn status(&self) -> Result<Status> {
        let end = ipc::deadline(Duration::from_secs(5), 60_000, 100)?;
        let (value, _) = ipc::request(
            &self.directory,
            json!({"version":2,"action":"status","timeoutMs":5000}),
            end,
        )?;
        let status = Status::parse(value)?;
        let mut state = lock(&self.state)?;
        state.observe(status.check_authority.identity())?;
        for (id, lifecycle) in &state.streams {
            if let Some(lifecycle) = lifecycle.upgrade() {
                let connection = status
                    .connections
                    .iter()
                    .find(|item| item.id.as_str() == id);
                let mut local = lock(&lifecycle.state)?;
                if connection
                    .is_some_and(|item| item.privacy.direction() != local.privacy.direction())
                {
                    local.invalidate();
                    local.privacy.mark_historical();
                    return Err(Error::Protocol);
                }
                let eligible = status.check_authority.supported()
                    && status.check_authority.endpoint_ready()
                    && connection.is_some_and(|item| item.check_authority);
                if !eligible {
                    local.invalidate();
                }
                if let Some(connection) = connection {
                    local.privacy = connection.privacy.clone();
                    if !local.active
                        || (local.privacy.direction() == Direction::Incoming
                            && !status.check_authority.endpoint_ready())
                    {
                        local.privacy.mark_historical();
                    }
                } else {
                    local.privacy.mark_historical();
                }
                local.eligible = eligible;
            }
        }
        Ok(status)
    }
    pub fn connect(&self, service: &str, protocol: &str, timeout: Duration) -> Result<Stream> {
        Id::parse(service).map_err(|_| Error::InvalidInput)?;
        if !context::protocol_valid(protocol) {
            return Err(Error::InvalidInput);
        }
        let ms = ipc::timeout_ms(timeout, 60_000, 100)?;
        let end = ipc::deadline(timeout, 60_000, 100)?;
        let (value, socket) = ipc::request(
            &self.directory,
            json!({"version":2,"action":"connect","service":service,"protocol":protocol,"timeoutMs":ms}),
            end,
        )?;
        let stream = self.handoff(value, socket, Direction::Outgoing)?;
        if stream.peer.service() != service || stream.peer.protocol() != protocol {
            return Err(Error::Protocol);
        }
        Ok(stream)
    }
    pub fn accept(&self, timeout: Duration) -> Result<Stream> {
        let ms = ipc::timeout_ms(timeout, 60_000, 100)?;
        let end = ipc::deadline(timeout, 60_000, 100)?;
        let (value, socket) = ipc::request(
            &self.directory,
            json!({"version":2,"action":"accept","timeoutMs":ms}),
            end,
        )?;
        self.handoff(value, socket, Direction::Incoming)
    }
    fn handoff(&self, value: Value, socket: UnixStream, direction: Direction) -> Result<Stream> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Handoff {
            version: u64,
            ok: bool,
            id: Id,
            peer: Value,
            privacy: Value,
            check_authority: bool,
        }
        let value: Handoff = context::decode(value)?;
        if value.version != 2
            || !value.ok
            || (direction == Direction::Outgoing && value.check_authority)
        {
            return Err(Error::Protocol);
        }
        let peer = Peer::parse(value.peer, direction)?;
        let privacy = Privacy::parse(value.privacy, direction, false)?;
        let life = Arc::new(Lifecycle {
            state: Mutex::new(Local {
                active: true,
                epoch: 0,
                eligible: value.check_authority,
                privacy,
            }),
        });
        let mut state = lock(&self.state)?;
        state.prune();
        if state.streams.len() >= 16 || state.streams.contains_key(value.id.as_str()) {
            return Err(Error::Protocol);
        }
        state
            .streams
            .insert(value.id.as_str().to_owned(), Arc::downgrade(&life));
        Ok(Stream {
            socket: Mutex::new(Some(socket)),
            id: value.id,
            peer,
            life,
            owner: Arc::downgrade(&self.state),
            reading: AtomicBool::new(false),
            writing: AtomicBool::new(false),
        })
    }
    fn owns(&self, stream: &Stream) -> bool {
        stream
            .owner
            .upgrade()
            .is_some_and(|s| Arc::ptr_eq(&s, &self.state))
    }
    /// Invalidate local observations immediately, then request companion cancellation.
    pub fn cancel(&self, stream: &Stream) -> Result<()> {
        if !self.owns(stream) {
            return Err(Error::NotActive);
        }
        {
            let mut local = lock(&stream.life.state)?;
            local.active = false;
            local.invalidate();
        }
        let result = (|| {
            let end = ipc::deadline(Duration::from_secs(5), 60_000, 100)?;
            let (value, _) = ipc::request(
                &self.directory,
                json!({"version":2,"action":"cancel","id":stream.id(),"timeoutMs":5000}),
                end,
            )?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Cancel {
                version: u64,
                ok: bool,
                id: Id,
                status: String,
            }
            let response: Cancel = context::decode(value)?;
            if response.version != 2
                || !response.ok
                || response.id != stream.id
                || response.status != "Cancelling"
            {
                return Err(Error::Protocol);
            }
            Ok(())
        })();
        stream.close();
        result
    }
}

/// An owned duplex connection. Incoming and outgoing context cannot be interchanged.
pub struct Stream {
    socket: Mutex<Option<UnixStream>>,
    id: Id,
    peer: Peer,
    life: Arc<Lifecycle>,
    owner: Weak<Mutex<State>>,
    reading: AtomicBool,
    writing: AtomicBool,
}
struct IoLease<'a>(&'a AtomicBool);
impl Drop for IoLease<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Stream {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }
    pub fn peer(&self) -> &Peer {
        &self.peer
    }
    pub fn privacy(&self) -> Privacy {
        match self.life.state.lock() {
            Ok(local) => {
                let mut privacy = local.privacy.clone();
                if !local.active {
                    privacy.mark_historical();
                }
                privacy
            }
            Err(poisoned) => {
                let mut privacy = poisoned.into_inner().privacy.clone();
                privacy.mark_historical();
                privacy
            }
        }
    }

    pub fn check_authority_supported(&self) -> bool {
        lock(&self.life.state).is_ok_and(|l| l.active && l.eligible)
    }
    fn lease(&self, reading: bool) -> Result<IoLease<'_>> {
        if !lock(&self.life.state)?.active {
            return Err(Error::NotActive);
        }
        let flag = if reading {
            &self.reading
        } else {
            &self.writing
        };
        if flag
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Busy);
        }
        Ok(IoLease(flag))
    }
    fn socket(&self) -> Result<UnixStream> {
        lock(&self.socket)?
            .as_ref()
            .ok_or(Error::NotActive)?
            .try_clone()
            .map_err(|_| Error::Unavailable)
    }
    pub fn send_all(&self, bytes: &[u8], timeout: Duration) -> Result<()> {
        if bytes.len() > ipc::MAX_PAYLOAD {
            return Err(Error::Frame);
        }
        let end = ipc::deadline(timeout, 60_000, 1)?;
        let _lease = self.lease(false)?;
        let result = ipc::send(&self.socket()?, bytes, end);
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn recv_exact(&self, bytes: &mut [u8], timeout: Duration) -> Result<()> {
        if bytes.len() > ipc::MAX_PAYLOAD {
            return Err(Error::Frame);
        }
        let end = ipc::deadline(timeout, 60_000, 1)?;
        let _lease = self.lease(true)?;
        let result = ipc::exact(&self.socket()?, bytes, end);
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn shutdown_write(&self) -> Result<()> {
        let _lease = self.lease(false)?;
        self.socket()?.shutdown(Shutdown::Write).map_err(|_| {
            self.close();
            Error::Closed
        })
    }
    pub fn close(&self) {
        let mut state = self.life.state.lock().unwrap_or_else(|p| p.into_inner());
        state.active = false;
        state.invalidate();
        state.privacy.mark_historical();
        drop(state);
        if let Some(socket) = self.socket.lock().unwrap_or_else(|p| p.into_inner()).take() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[path = "../../Tests/HyperNet/Adapter.rs"]
mod tests;
