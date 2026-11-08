// SPDX-License-Identifier: Apache-2.0
//! Bounded optional invitation listener and one durable native-operation worker.
use super::{
    client::{Greeting, verify},
    store::{Configuration, Locked, Phase, Record},
    *,
};
use hrc::service::files;
use std::{
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn connection(
    stream: TcpStream,
    tls: Arc<rustls::ServerConfig>,
    c: &Configuration,
    cancel: &AtomicBool,
) -> Result<()> {
    let mut stream = transport::accept(stream, tls, cancel)?;
    let challenge = store::random()?;
    transport::write(
        &mut stream,
        &Greeting {
            protocol: PROTOCOL.into(),
            challenge: challenge.clone(),
        },
        1024,
    )?;
    let request: SignedRequest = transport::read(&mut stream, MAX_REQUEST)?;
    let response = (|| {
        verify(&challenge, &request)?;
        Locked::open(c)?.request(request.data)
    })();
    let response=match response {
        Ok(value)=>value,
        Err(Error::Busy)=>Response::Pending{phase:"Admission service is unavailable or busy".into(),retry_after_ms:2000},
        Err(Error::Bound)=>Response::Refused{reason:"This invitation belongs to a different recipient or request. Keep the original local profile.".into()},
        Err(Error::Expired)=>Response::Refused{reason:"This invitation or access has expired or been revoked.".into()},
        Err(_)=>Response::Refused{reason:"The invitation request could not be verified.".into()},
    };
    transport::write(&mut stream, &response, MAX_RESPONSE)
}
fn work(c: &Configuration, r: &Record, cancel: &AtomicBool) -> Result<Option<Delivery>> {
    let d = c.record_directory(&r.id)?;
    let native = d.join("Native");
    let end = Instant::now() + Duration::from_secs(600);
    match r.phase {
        Phase::Admitting => {
            let chat = files::read(&d.join("ChatRequest.cbor"), 4096).map_err(|_| Error::State)?;
            if Some(digest(&chat)) != r.chat_request_sha256 {
                return Err(Error::State);
            }
            let reader = if let Some(pin) = &r.reader_request_sha256 {
                let bytes =
                    files::read(&d.join("ReaderRequest.cbor"), 4096).map_err(|_| Error::State)?;
                if digest(&bytes) != *pin {
                    return Err(Error::State);
                }
                Some(bytes)
            } else {
                None
            };
            backend::issue(
                &c.backend,
                &native,
                &chat,
                reader.as_deref(),
                r.access_expires_ms,
                c.route_seconds,
                cancel,
                end,
            )
            .map(Some)
        }
        Phase::Enrolling => {
            let bytes =
                files::read(&d.join("Registration.cbor"), 262144).map_err(|_| Error::State)?;
            if Some(digest(&bytes)) != r.registration_sha256 {
                return Err(Error::State);
            }
            backend::enrol(&c.backend, &native, &bytes, cancel, end)?;
            Ok(None)
        }
        Phase::Renewing => backend::renew(&c.backend, &native, cancel, end).map(Some),
        Phase::Revoking => {
            backend::revoke(&c.backend, &native, cancel, end)?;
            Ok(None)
        }
        _ => Err(Error::Invalid),
    }
}
fn one_job(c: &Configuration, cancel: &AtomicBool) -> Result<bool> {
    let r = {
        let store = Locked::open(c)?;
        let enabled = store.control()?.enabled;
        let mut records = store.records()?;
        records.sort_by_key(|r| if r.phase == Phase::Revoking { 0 } else { 1 });
        records
            .into_iter()
            .find(|r| r.phase.pending() && (enabled || r.phase == Phase::Revoking))
    };
    let Some(r) = r else {
        return Ok(false);
    };
    let result = work(c, &r, cancel);
    // Cancellation can hide an already committed result. Preserve this exact job.
    if cancel.load(Ordering::Acquire) {
        return Ok(true);
    }
    let store = loop {
        match Locked::open(c) {
            Ok(store) => break store,
            Err(Error::Busy) => thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(e),
        }
        if cancel.load(Ordering::Acquire) {
            return Ok(true);
        }
    };
    let mut current = store.load(&r.id)?;
    if current.revoke_requested && r.phase != Phase::Revoking {
        current.phase = Phase::Revoking;
        store.save(&current)?;
        return Ok(true);
    }
    if current.phase != r.phase {
        return Err(Error::State);
    }
    match result {
        Ok(delivery) => {
            if let Some(delivery) = delivery {
                if delivery.access_expires_ms > r.access_expires_ms
                    || delivery.chat_request_sha256
                        != r.chat_request_sha256.clone().ok_or(Error::State)?
                {
                    return Err(Error::State);
                }
                if r.phase == Phase::Renewing {
                    let previous = store.delivery(&r)?;
                    if previous.setup_bundle != delivery.setup_bundle {
                        return Err(Error::State);
                    }
                }
                store::write(&c.record_directory(&r.id)?.join("Delivery.json"), &delivery)?;
            }
            if r.phase == Phase::Enrolling {
                current.enrolled = true;
            }
            current.phase = match r.phase {
                Phase::Admitting => Phase::Ready,
                Phase::Enrolling => Phase::Active,
                Phase::Renewing => {
                    if current.enrolled {
                        Phase::Active
                    } else {
                        Phase::Ready
                    }
                }
                Phase::Revoking => Phase::Revoked,
                _ => return Err(Error::State),
            };
            current.failed_phase = None;
        }
        Err(Error::Busy) => return Ok(true),
        Err(_) => {
            current.failed_phase = Some(r.phase);
            current.phase = Phase::Blocked;
        }
    }
    store.save(&current)?;
    Ok(true)
}
pub(super) fn run(path: &Path) -> Result<()> {
    let c = Configuration::load(path)?;
    let cancel = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, cancel.clone()).map_err(|_| Error::State)?;
    }
    let _serving = store::lock(&c.directory.join("Serving.lock"))?;
    let _ = Locked::open(&c)?;
    let actual = backend::metadata(
        &c.backend,
        &cancel,
        Instant::now() + Duration::from_secs(120),
    )?;
    if actual != c.metadata {
        return Err(Error::Configuration(
            "the accepted network or admission bounds changed",
        ));
    }
    let cert = files::read(&c.certificate, 65536).map_err(|_| Error::State)?;
    let key =
        zeroize::Zeroizing::new(files::read(&c.private_key, 16384).map_err(|_| Error::State)?);
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let leaf = CertificateDer::pem_slice_iter(&cert)
        .next()
        .ok_or(Error::Invalid)?
        .map_err(|_| Error::Invalid)?;
    if digest(leaf.as_ref()) != c.certificate_sha256 {
        return Err(Error::Invalid);
    }
    let tls = transport::server_config(&cert, &key)?;
    let listener = TcpListener::bind(c.address).map_err(|_| Error::Connection)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Error::Connection)?;
    let c = Arc::new(c);
    let worker_c = c.clone();
    let worker_cancel = cancel.clone();
    let worker = thread::spawn(move || {
        while !worker_cancel.load(Ordering::Acquire) {
            match one_job(&worker_c, &worker_cancel) {
                Ok(_) | Err(Error::Busy) => (),
                Err(_) => {
                    worker_cancel.store(true, Ordering::Release);
                    return Err(Error::State);
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        Ok(())
    });
    let mut clients: Vec<thread::JoinHandle<()>> = Vec::new();
    while !cancel.load(Ordering::Acquire) {
        if !now_ms().is_ok_and(|now| now < c.metadata.access_expires_ms) {
            cancel.store(true, Ordering::Release);
            break;
        }
        let mut i = 0;
        while i < clients.len() {
            if clients[i].is_finished() {
                let _ = clients.swap_remove(i).join();
            } else {
                i += 1;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if clients.len() >= 4 {
                    drop(stream);
                    continue;
                }
                let config = c.clone();
                let tls = tls.clone();
                let flag = cancel.clone();
                clients.push(thread::spawn(move || {
                    let _ = connection(stream, tls, &config, &flag);
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(_) => {
                cancel.store(true, Ordering::Release);
            }
        }
    }
    for client in clients {
        let _ = client.join();
    }
    worker.join().map_err(|_| Error::State)?
}
