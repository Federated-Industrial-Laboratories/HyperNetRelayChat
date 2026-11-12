// SPDX-License-Identifier: Apache-2.0
//! One bounded local control worker shares the running Home owner and never restarts it.
use super::*;
use crate::service::live_admission::{self as control, Control, Payload, Reply};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    time::Instant,
};
pub(super) struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    path: PathBuf,
    boot: Option<PathBuf>,
    _directory: fs::File,
    _bridge: Option<Box<Server>>,
}
impl Server {
    pub(super) fn start(directory: &Path, shared: Arc<Shared>) -> Result<Self> {
        let mut server = Self::start_socket(directory, Arc::clone(&shared), None)?;
        if let Some(bridge) = &shared.config.admission_bridge {
            server._bridge = Some(Box::new(Self::start_socket(
                &bridge.directory,
                Arc::clone(&shared),
                Some(bridge.uid),
            )?));
        }
        Ok(server)
    }
    fn start_socket(directory: &Path, shared: Arc<Shared>, bridge: Option<u32>) -> Result<Self> {
        let owner = unsafe { libc::geteuid() };
        let (held, socket) = if bridge.is_some() {
            let opened = control::bridge::directory(directory, owner, true)
                .map_err(|_| Error::Configuration)?;
            for item in fs::read_dir(directory).map_err(|_| Error::Configuration)? {
                if item.map_err(|_| Error::Configuration)?.file_name() != "Admission.sock" {
                    return Err(Error::Configuration);
                }
            }
            opened
        } else {
            control::socket_directory(directory).map_err(|_| Error::Configuration)?
        };
        let path = directory.join("Admission.sock");
        let boot = bridge.is_none().then(|| directory.join("Admission.boot"));
        if let Ok(m) = fs::symlink_metadata(&path) {
            if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
                return Err(Error::Configuration);
            }
            fs::remove_file(&path).map_err(|_| Error::State)?;
        }
        if let Some(boot) = &boot
            && boot.exists()
        {
            files::read(boot, 1024).map_err(|_| Error::State)?;
            fs::remove_file(boot).map_err(|_| Error::State)?;
        }
        let listener = UnixListener::bind(socket).map_err(|_| Error::State)?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if bridge.is_some() { 0o666 } else { 0o600 }),
        )
        .map_err(|_| Error::State)?;
        listener.set_nonblocking(true).map_err(|_| Error::State)?;
        if let Some(boot) = &boot {
            files::create_json(boot, &shared.boot).map_err(|_| Error::State)?;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut used = BTreeMap::<Id, u64>::new();
            while !stopped.load(Ordering::Acquire) && !shared.stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        if control::bridge::peer(&stream, bridge.unwrap_or(owner)).is_ok() {
                            let _ = serve(&shared, &mut stream, &mut used, bridge.is_some());
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            worker: Some(worker),
            path,
            boot,
            _directory: held,
            _bridge: None,
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.path);
        if let Some(boot) = &self.boot {
            let _ = fs::remove_file(boot);
        }
    }
}
fn serve(
    shared: &Shared,
    stream: &mut UnixStream,
    used: &mut BTreeMap<Id, u64>,
    bridge: bool,
) -> std::result::Result<(), files::Invalid> {
    let end = Instant::now() + Duration::from_secs(5);
    let challenge = if bridge {
        let challenge =
            control::bridge::Challenge::new(shared.config.descriptor.home, shared.boot)?;
        control::send(stream, &challenge, &shared.signer, end)?;
        Some(challenge)
    } else {
        None
    };
    let envelope = control::receive(stream, end)?;
    let payload: Payload = control::verify(&envelope)?;
    if let Some(challenge) = challenge
        && (!matches!(payload.control, Control::Request { .. })
            || payload.nonce != challenge.nonce
            || payload.expires_boot_ms != challenge.expires_boot_ms)
    {
        return Err(files::Invalid);
    }
    let current = clock::boot_ms().map_err(|_| files::Invalid)?;
    used.retain(|_, expires| *expires > current);
    if payload.home != shared.config.descriptor.home
        || payload.boot != shared.boot
        || payload.expires_boot_ms <= current
        || payload.expires_boot_ms > current + 5000
        || used.contains_key(&payload.nonce)
        || used.len() >= 128
    {
        return Err(files::Invalid);
    }
    used.insert(payload.nonce, payload.expires_boot_ms);
    let mut home = shared
        .home
        .acquire(Some(payload.expires_boot_ms), || {
            !shared.stop.load(Ordering::Acquire)
        })
        .map_err(|_| files::Invalid)?;
    let now = shared.config.clock.sample().map_err(|_| files::Invalid)?;
    let result = (|| -> std::result::Result<serde_json::Value, files::Invalid> {
        if let Control::Request { request } = &payload.control {
            return serde_json::to_value(
                home.admission_request(request, envelope.signer, now)
                    .map_err(|_| files::Invalid)?,
            )
            .map_err(|_| files::Invalid);
        }
        if envelope.signer != shared.config.descriptor.signing_key {
            return Err(files::Invalid);
        }
        match payload.control {
            Control::Configure { policy } => {
                home.configure_admission(policy, now)
                    .map_err(|_| files::Invalid)?;
                Ok(serde_json::json!({"configured":true}))
            }
            Control::ConfigureHost { policy } => {
                home.configure_host_admission(policy, now)
                    .map_err(|_| files::Invalid)?;
                Ok(serde_json::json!({"configured":true}))
            }
            Control::LegacyInvite {
                principal,
                id,
                expires_ms,
            } => serde_json::to_value(
                home.issue_invitation_exact(id, principal, AccountClass::Human, expires_ms, now)
                    .map_err(|_| files::Invalid)?,
            )
            .map_err(|_| files::Invalid),
            Control::LegacyEnrol { registration } => {
                let bytes = registration.bytes().map_err(|_| files::Invalid)?;
                let registration =
                    verify_registration_request(&bytes).map_err(|_| files::Invalid)?;
                let actor = match home
                    .registration_outcome(&registration)
                    .map_err(|_| files::Invalid)?
                {
                    Some(actor) => actor,
                    None => {
                        home.accept_registration(&registration, now)
                            .map_err(|_| files::Invalid)?
                            .acting
                    }
                };
                serde_json::to_value(actor).map_err(|_| files::Invalid)
            }
            Control::Request { .. } => unreachable!(),
        }
    })()
    .unwrap_or_else(|_| serde_json::json!({"status":"refused","code":"AdmissionControlRefused"}));
    drop(home);
    control::send(
        stream,
        &Reply {
            boot: shared.boot,
            nonce: payload.nonce,
            result,
        },
        &shared.signer,
        end,
    )
}

#[cfg(test)]
#[path = "../../Tests/Service/LiveAdmission.rs"]
mod tests;
