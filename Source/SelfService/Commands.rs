// SPDX-License-Identifier: Apache-2.0
//! Explicit operator controls; self-service remains disabled until the host enables it.
use super::{
    store::{self, Configuration, Control, Locked, Phase},
    *,
};
use crate::operations::{native, units};
use hrc::service::files;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Value, json};
use std::{
    net::SocketAddrV4,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Export validated native admission paths from an existing managed HyperNet.
    ExportBackend {
        #[arg(long)]
        network_config: PathBuf,
        #[arg(long)]
        operator_lock: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare a private disabled admission service and its separately pinned TLS identity.
    Init {
        #[arg(long)]
        backend: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        address: SocketAddrV4,
        #[arg(long)]
        name: String,
        #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u16).range(1..=64))]
        maximum_invitations: u16,
        #[arg(long,default_value_t=86390,value_parser=clap::value_parser!(u64).range(120..=86390))]
        route_seconds: u64,
    },
    Enable {
        #[arg(long)]
        config: PathBuf,
    },
    Disable {
        #[arg(long)]
        config: PathBuf,
    },
    Start {
        #[arg(long)]
        config: PathBuf,
    },
    Stop {
        #[arg(long)]
        config: PathBuf,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the fixed native worker and bounded TLS listener in the foreground.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Issue one recipient credential; the secret is written only to a private file.
    Issue {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        label: String,
        #[arg(long,default_value_t=72,value_parser=clap::value_parser!(u16).range(1..=168))]
        hours: u16,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Recover the same private invitation export after an interrupted handoff.
    Export {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        output: PathBuf,
    },
    List {
        #[arg(long)]
        config: PathBuf,
    },
    /// Block the credential immediately and queue native grant revocation.
    Revoke {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Resume the exact blocked operation only after operator inspection.
    Retry {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
}
fn text(path: &Path) -> Result<String> {
    native::path(path).map_err(|_| Error::Invalid)
}
fn native_json(program: &Path, args: Vec<String>, cancel: &AtomicBool) -> Result<Value> {
    let output = native::run_diagnostic(
        program,
        &args,
        cancel,
        Instant::now() + Duration::from_secs(90),
    )
    .map_err(|_| Error::Native)?;
    serde_json::from_slice(&output).map_err(|_| Error::Native)
}
fn tls(
    backend: &backend::Config,
    directory: &Path,
    address: SocketAddrV4,
    cancel: &AtomicBool,
) -> Result<(PathBuf, PathBuf, PathBuf, String)> {
    let issuer = directory.join("TlsIssuer");
    let endpoint = directory.join("TlsEndpoint");
    let days =
        ((backend.access_expires_ms.saturating_sub(now_ms()?)).div_ceil(86_400_000)).clamp(1, 365);
    if !issuer.exists() {
        native_json(
            &backend.core,
            vec![
                "runtime".into(),
                "provision".into(),
                "issuer".into(),
                "--directory".into(),
                text(&issuer)?,
                "--days".into(),
                days.to_string(),
            ],
            cancel,
        )?;
    }
    let ca = issuer.join("Authority.pem");
    let authority = files::read(&ca, 16384).map_err(|_| Error::State)?;
    if !endpoint.exists() {
        native_json(
            &backend.core,
            vec![
                "runtime".into(),
                "provision".into(),
                "identity".into(),
                "--directory".into(),
                text(&endpoint)?,
                "--address".into(),
                address.ip().to_string(),
                "--port".into(),
                address.port().to_string(),
            ],
            cancel,
        )?;
    }
    let request = endpoint.join("TransportRequest.json");
    let request_bytes = files::read(&request, 65536).map_err(|_| Error::State)?;
    let request_value: Value = serde_json::from_slice(&request_bytes).map_err(|_| Error::State)?;
    if request_value["address"] != address.ip().to_string()
        || request_value["port"] != address.port()
    {
        return Err(Error::Configuration("retained TLS endpoint differs"));
    }
    let peer = directory.join("TlsPeer.json");
    if !peer.exists() {
        native_json(
            &backend.core,
            vec![
                "runtime".into(),
                "provision".into(),
                "issue".into(),
                "--directory".into(),
                text(&issuer)?,
                "--issuer-digest".into(),
                digest(&authority),
                "--request".into(),
                text(&request)?,
                "--request-digest".into(),
                digest(&request_bytes),
                "--days".into(),
                days.to_string(),
                "--output".into(),
                text(&peer)?,
            ],
            cancel,
        )?;
    }
    let public: Value = store::read(&peer, 65536)?;
    let certificate = public["certificatePem"].as_str().ok_or(Error::State)?;
    if public["authorityPem"].as_str().map(str::as_bytes) != Some(authority.as_slice()) {
        return Err(Error::State);
    }
    let certificate_path = directory.join("Certificate.pem");
    store::exact(&certificate_path, certificate.as_bytes())?;
    let leaf = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .next()
        .ok_or(Error::Invalid)?
        .map_err(|_| Error::Invalid)?;
    let key = endpoint.join("Transport.key");
    let secret = zeroize::Zeroizing::new(files::read(&key, 16384).map_err(|_| Error::State)?);
    transport::server_config(certificate.as_bytes(), &secret)?;
    Ok((ca, certificate_path, key, digest(leaf.as_ref())))
}
fn unit(c: &Configuration) -> String {
    format!(
        "hrc-managed-admission-{}",
        digest(c.directory.as_os_str().as_encoded_bytes())
    )
}
fn start(c: &Configuration, path: &Path, cancel: &AtomicBool) -> Result<Value> {
    if !Locked::open(c)?.control()?.enabled {
        return Err(Error::Configuration(
            "enable self-service explicitly before starting it",
        ));
    }
    if now_ms()? >= c.metadata.access_expires_ms {
        return Err(Error::Expired);
    }
    let executable = std::env::current_exe().map_err(|_| Error::State)?;
    let value = units::start(
        &unit(c),
        &executable,
        &[
            "admission".into(),
            "serve".into(),
            "--config".into(),
            text(path)?,
        ],
        &[],
        &units::Limits {
            memory_mib: 512,
            cpu_percent: 100,
            security: units::Security::Standard,
        },
        cancel,
    )
    .map_err(|_| Error::Native)?;
    serde_json::to_value(value).map_err(|_| Error::State)
}
fn export(c: &Configuration, id: &str, output: &Path) -> Result<()> {
    let bytes = files::read(&c.record_directory(id)?.join("Invitation.txt"), 65536)
        .map_err(|_| Error::State)?;
    store::exact(output, &bytes)
}
pub(crate) fn run(command: Command) -> Result<Value> {
    let cancel = AtomicBool::new(false);
    match command {
        Command::ExportBackend {
            network_config,
            operator_lock,
            output,
        } => {
            let c = store::read(&network_config, 131072)?;
            let backend = backend::from_managed(
                &c,
                operator_lock,
                &cancel,
                Instant::now() + Duration::from_secs(120),
            )?;
            files::create(
                &output,
                &serde_json::to_vec_pretty(&backend).map_err(|_| Error::State)?,
            )
            .map_err(|_| Error::State)?;
            Ok(json!({"status":"BackendExported","file":output}))
        }
        Command::Init {
            backend: input,
            directory,
            address,
            name,
            maximum_invitations,
            route_seconds,
        } => {
            if address.port() <= 1024
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || address.ip().is_broadcast()
                || name.is_empty()
                || name.len() > 96
                || name.chars().any(char::is_control)
            {
                return Err(Error::Invalid);
            }
            let backend: backend::Config = store::read(&input, 131072)?;
            backend.validate()?;
            let metadata =
                backend::metadata(&backend, &cancel, Instant::now() + Duration::from_secs(120))?;
            if metadata.access_expires_ms <= now_ms()? {
                return Err(Error::Expired);
            }
            files::directory(&directory, !directory.exists()).map_err(|_| Error::State)?;
            let _initialising = store::lock(&directory.join("Initialise.lock"))?;
            let path = directory.join("Configuration.json");
            if path.exists() {
                let existing = Configuration::load(&path)?;
                if existing.address != address
                    || existing.name != name
                    || existing.maximum_invitations != maximum_invitations
                    || existing.route_seconds != route_seconds
                    || serde_json::to_vec(&existing.backend).map_err(|_| Error::State)?
                        != serde_json::to_vec(&backend).map_err(|_| Error::State)?
                {
                    return Err(Error::Bound);
                }
                return Ok(
                    json!({"status":"AdmissionPrepared","config":path,"enabled":Locked::open(&existing)?.control()?.enabled}),
                );
            }
            let (certificate_authority, certificate, private_key, certificate_sha256) =
                tls(&backend, &directory, address, &cancel)?;
            let invitations = directory.join("Invitations");
            files::directory(&invitations, !invitations.exists()).map_err(|_| Error::State)?;
            let c = Configuration {
                format: "HrcAdmissionHost/1".into(),
                name,
                directory: directory.clone(),
                address,
                certificate_authority,
                certificate,
                private_key,
                certificate_sha256,
                maximum_invitations,
                route_seconds,
                backend,
                metadata,
            };
            // The disabled control is durable before the configuration can start a listener.
            store::write(
                &directory.join("Control.json"),
                &Control {
                    configuration_sha256: c.pin()?,
                    enabled: false,
                },
            )?;
            store::write(&path, &c)?;
            Ok(
                json!({"status":"AdmissionPrepared","config":path,"enabled":false,"address":address}),
            )
        }
        Command::Serve { config } => {
            server::run(&config)?;
            Ok(json!({"status":"AdmissionStopped"}))
        }
        command => {
            let path = match &command {
                Command::Enable { config }
                | Command::Disable { config }
                | Command::Start { config }
                | Command::Stop { config }
                | Command::Status { config }
                | Command::Issue { config, .. }
                | Command::Export { config, .. }
                | Command::List { config }
                | Command::Revoke { config, .. }
                | Command::Retry { config, .. } => config,
                _ => return Err(Error::Invalid),
            }
            .clone();
            let c = Configuration::load(&path)?;
            match command {
                Command::Enable { .. } | Command::Disable { .. } => {
                    let enabled = matches!(command, Command::Enable { .. });
                    Locked::open(&c)?.enable(enabled)?;
                    Ok(json!({"status":"AdmissionConfigured","enabled":enabled}))
                }
                Command::Start { .. } => start(&c, &path, &cancel),
                Command::Stop { .. } => serde_json::to_value(
                    units::stop(&unit(&c), &cancel).map_err(|_| Error::Native)?,
                )
                .map_err(|_| Error::State),
                Command::Status { .. } => Ok(
                    json!({"enabled":Locked::open(&c)?.control()?.enabled,"unit":units::status(&unit(&c),&cancel).map_err(|_|Error::Native)?,"accessExpiresMs":c.metadata.access_expires_ms,"address":c.address}),
                ),
                Command::Issue {
                    label,
                    hours,
                    output,
                    ..
                } => {
                    if let Some(output) = &output {
                        files::directory(output.parent().ok_or(Error::Invalid)?, false)
                            .map_err(|_| Error::State)?;
                        if output.exists() {
                            return Err(Error::State);
                        }
                    }
                    let expires = now_ms()?
                        .saturating_add(u64::from(hours) * 3600000)
                        .min(c.metadata.access_expires_ms);
                    let invitation = Locked::open(&c)?.issue(&label, expires)?;
                    let path = if let Some(output) = output {
                        export(&c, &invitation.id, &output)?;
                        output
                    } else {
                        c.record_directory(&invitation.id)?.join("Invitation.txt")
                    };
                    Ok(
                        json!({"status":"InvitationIssued","id":invitation.id,"file":path,"expiresMs":invitation.expires_ms,"accessExpiresMs":invitation.access_expires_ms,"singleRecipient":true}),
                    )
                }
                Command::Export { id, output, .. } => {
                    let _store = Locked::open(&c)?;
                    export(&c, &id, &output)?;
                    Ok(json!({"status":"InvitationExported","id":id,"file":output}))
                }
                Command::List { .. } => {
                    let store = Locked::open(&c)?;
                    let rows:Vec<_>=store.records()?.into_iter().map(|r|json!({"id":r.id,"label":r.label,"phase":r.phase,"enrolled":r.enrolled,"revoked":r.revoke_requested,"expiresMs":r.expires_ms,"accessExpiresMs":r.access_expires_ms})).collect();
                    Ok(json!({"enabled":store.control()?.enabled,"invitations":rows}))
                }
                Command::Revoke { id, .. } => {
                    Locked::open(&c)?.revoke(&id)?;
                    Ok(json!({"status":"RevocationQueued","id":id,"credentialDisabled":true}))
                }
                Command::Retry { id, .. } => {
                    let store = Locked::open(&c)?;
                    let mut r = store.load(&id)?;
                    if r.phase != Phase::Blocked {
                        return Err(Error::Invalid);
                    }
                    r.phase = if r.revoke_requested {
                        Phase::Revoking
                    } else {
                        r.failed_phase.ok_or(Error::State)?
                    };
                    r.failed_phase = None;
                    store.save(&r)?;
                    Ok(json!({"status":"ExactOperationResumed","id":id}))
                }
                _ => Err(Error::Invalid),
            }
        }
    }
}
