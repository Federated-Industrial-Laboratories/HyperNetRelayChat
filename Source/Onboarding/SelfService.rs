// SPDX-License-Identifier: Apache-2.0
//! Resumable private invitations retain local identities and use normal native admission.
use super::{Error, Result, RuntimeConfig, bundle, native, runtime};
use crate::self_service::{
    self as admission, Action, Artifact, Delivery, Invitation, NetworkMetadata, Response,
    RouteDelivery,
};
use hrc::{client, protocol::canonical_decode, service::files};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

const MAXIMUM: usize = 20 * 1024 * 1024;

fn failure(error: admission::Error) -> Error {
    match error {
        admission::Error::Expired => Error::AdmissionExpired,
        admission::Error::Bound => Error::AdmissionBound,
        admission::Error::Busy => Error::Busy,
        admission::Error::Cancelled => Error::Cancelled,
        admission::Error::Deadline => Error::Deadline,
        _ => Error::Admission,
    }
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&files::read(path, MAXIMUM).map_err(|_| Error::LocalConfiguration)?)
        .map_err(|_| Error::LocalConfiguration)
}
fn replace(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::LocalConfiguration)?;
    if bytes.len() > MAXIMUM {
        return Err(Error::OutputLimit);
    }
    if path.exists() {
        files::read(path, MAXIMUM).map_err(|_| Error::LocalConfiguration)?;
    }
    let parent = path.parent().ok_or(Error::LocalConfiguration)?;
    let temporary = parent.join(format!(
        ".admission-{}",
        hrc::protocol::Id::random()
            .map_err(|_| Error::LocalConfiguration)?
            .as_hex()
    ));
    files::create(&temporary, &bytes).map_err(|_| Error::LocalConfiguration)?;
    let result = fs::rename(&temporary, path).and_then(|_| File::open(parent)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| Error::LocalConfiguration)
}
fn exact(path: &Path, artifact: &Artifact, maximum: usize) -> Result<()> {
    native::exact_file(path, &artifact.bytes(maximum).map_err(failure)?)
}
fn binding(c: &RuntimeConfig) -> serde_json::Value {
    json!({"root":c.data_directory,"network":c.network_profile,"joined":c.joined_directory,
        "companion":c.companion_directory,"profile":c.hrc_profile,"targets":c.targets_file})
}
fn exchange_repeated(
    action: Action,
    cancel: &AtomicBool,
    end: Instant,
    mut send: impl FnMut(Action) -> Result<Response>,
) -> Result<Response> {
    loop {
        native::check(cancel, end)?;
        match send(action.clone())? {
            Response::Pending { retry_after_ms, .. } => {
                let wait = Instant::now() + Duration::from_millis(retry_after_ms.clamp(100, 2000));
                while Instant::now() < wait {
                    native::check(cancel, end)?;
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Response::Refused { reason } => {
                return Err(match reason.as_str() {
                    "This invitation or access has expired or been revoked." => {
                        Error::AdmissionExpired
                    }
                    "This invitation belongs to a different recipient or request. Keep the original local profile." => {
                        Error::AdmissionBound
                    }
                    _ => Error::Admission,
                });
            }
            response => return Ok(response),
        }
    }
}

struct Workflow {
    root: PathBuf,
    invitation: Invitation,
    client: admission::client::Client,
    _lock: File,
}
impl Workflow {
    fn open(c: &RuntimeConfig) -> Result<Self> {
        let root = c.self_service.clone().ok_or(Error::LocalConfiguration)?;
        files::directory(&root, false).map_err(|_| Error::LocalConfiguration)?;
        let path = root.join("Workflow.lock");
        if !path.exists() {
            files::create(&path, &[]).map_err(|_| Error::LocalConfiguration)?;
        }
        files::read(&path, 0).map_err(|_| Error::LocalConfiguration)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::LocalConfiguration)?;
        let metadata = lock.metadata().map_err(|_| Error::LocalConfiguration)?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Error::LocalConfiguration);
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Busy);
        }
        let expected = serde_json::to_vec(&binding(c)).map_err(|_| Error::LocalConfiguration)?;
        native::exact_file(&root.join("Binding.json"), &expected)?;
        let invitation: Invitation = read(&root.join("Invitation.json"))?;
        let client_root = root.join("Authentication");
        native::directory(&client_root)?;
        let client =
            admission::client::Client::open(&client_root, invitation.clone()).map_err(failure)?;
        Ok(Self {
            root,
            invitation,
            client,
            _lock: lock,
        })
    }
    fn exchange(&mut self, action: Action, cancel: &AtomicBool, end: Instant) -> Result<Response> {
        exchange_repeated(action, cancel, end, |action| {
            self.client.exchange(action, cancel, end).map_err(failure)
        })
    }
    fn metadata(&mut self, cancel: &AtomicBool, end: Instant) -> Result<NetworkMetadata> {
        let path = self.root.join("Network.json");
        let value = if path.exists() {
            read(&path)?
        } else {
            let Response::Network { metadata } = self.exchange(
                Action::Inspect {
                    secret: self.invitation.secret.clone(),
                },
                cancel,
                end,
            )?
            else {
                return Err(Error::Admission);
            };
            metadata
        };
        validate_metadata(&self.invitation, &value)?;
        native::exact_file(
            &path,
            &serde_json::to_vec(&value).map_err(|_| Error::LocalConfiguration)?,
        )?;
        Ok(value)
    }
    fn delivery(
        &mut self,
        action: Action,
        c: &RuntimeConfig,
        metadata: &NetworkMetadata,
        cancel: &AtomicBool,
        end: Instant,
    ) -> Result<(Delivery, bool)> {
        let Response::Ready { delivery, enrolled } = self.exchange(action, cancel, end)? else {
            return Err(Error::Admission);
        };
        validate_delivery(c, metadata, &delivery)?;
        let path = self.root.join("Delivery.json");
        if path.exists() {
            let old: Delivery = read(&path)?;
            validate_successor(&old, &delivery)?;
        }
        replace(&path, &delivery)?;
        Ok((delivery, enrolled))
    }
}
fn validate_metadata(invitation: &Invitation, value: &NetworkMetadata) -> Result<()> {
    if value.network != invitation.network
        || value.incarnation != invitation.incarnation
        || value.bootstrap.sha256 != invitation.bootstrap_sha256
        || value.bootstrap_fingerprint != invitation.bootstrap_fingerprint
        || value.access_expires_ms > invitation.access_expires_ms
        || !admission::is_id(&value.application_service)
    {
        return Err(Error::BundleBinding);
    }
    value.bootstrap.bytes(1024 * 1024).map_err(failure)?;
    Ok(())
}
fn reader_config(c: &RuntimeConfig) -> RuntimeConfig {
    let mut value = RuntimeConfig::at(c.data_directory.join("Reader"));
    value.suite = c.suite.clone();
    value.core = c.core.clone();
    value.clock_directory = c.clock_directory.clone();
    value.clock_observation = c.clock_observation.clone();
    value.clock_monitor_key = c.clock_monitor_key.clone();
    value
}
fn validate_routes(
    c: &RuntimeConfig,
    metadata: &NetworkMetadata,
    routes: &[RouteDelivery],
    roles: &[&str],
) -> Result<()> {
    if routes.len() != roles.len() {
        return Err(Error::BundleBinding);
    }
    let prepared = runtime::prepared(c)?;
    for role in roles {
        let matches: Vec<_> = routes.iter().filter(|r| r.role == *role).collect();
        if matches.len() != 1 {
            return Err(Error::BundleBinding);
        }
        let value = matches[0];
        let protocol = match *role {
            "Authority" => 1,
            "Application" => 7,
            "Page" => 2,
            _ => return Err(Error::BundleBinding),
        };
        let bytes = value.artifact.bytes(1024 * 1024).map_err(failure)?;
        let route = bundle::route(&bytes, protocol)?;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::BundleBinding)?;
        let voucher: Vec<u8> =
            serde_json::from_value(json["voucher"].clone()).map_err(|_| Error::BundleBinding)?;
        let record = canonical_decode(&voucher, 65536).map_err(|_| Error::BundleBinding)?;
        let record = record.as_array().ok_or(Error::BundleBinding)?;
        if record.len() != 8
            || record[4].as_integer().and_then(|n| u64::try_from(n).ok()) != Some(value.generation)
            || record[6].as_bytes().map(hex::encode).as_deref() != Some(value.voucher_id.as_str())
            || route.network != metadata.network
            || route.incarnation != metadata.incarnation
            || route.possession != prepared.relay_key
            || route.expires_ms != value.expires_ms
            || value.expires_ms > metadata.access_expires_ms
            || !admission::is_id(&value.subject)
            || (*role != "Page" && value.subject != route.service)
            || (*role == "Application" && route.service != metadata.application_service)
        {
            return Err(Error::BundleBinding);
        }
    }
    Ok(())
}
fn request(c: &RuntimeConfig) -> Result<Artifact> {
    Artifact::from_bytes(
        &files::read(
            &c.data_directory.join("Exchange/NetworkRequest.cbor"),
            65536,
        )
        .map_err(|_| Error::LocalConfiguration)?,
    )
    .map_err(failure)
}
fn validate_delivery(
    c: &RuntimeConfig,
    metadata: &NetworkMetadata,
    value: &Delivery,
) -> Result<()> {
    if value.chat_request_sha256 != request(c)?.sha256
        || value.reader.is_some() != metadata.reader_available
        || value.access_expires_ms > metadata.access_expires_ms
        || value.route_expires_ms > value.access_expires_ms
        || value.join_expires_ms == 0
        || value.join_expires_ms > value.access_expires_ms
        || value.renewal_after_ms < value.route_expires_ms
        || value.renewal_after_ms > value.route_expires_ms.saturating_add(60_000)
    {
        return Err(Error::BundleBinding);
    }
    value
        .setup_bundle
        .bytes(bundle::MAXIMUM_BUNDLE)
        .map_err(failure)?;
    validate_routes(
        c,
        metadata,
        &value.chat_routes,
        &["Authority", "Application"],
    )?;
    let mut expiry = value
        .chat_routes
        .iter()
        .map(|r| r.expires_ms)
        .min()
        .ok_or(Error::BundleBinding)?;
    if let Some(reader) = &value.reader {
        let config = reader_config(c);
        if reader.request_sha256 != request(&config)?.sha256 {
            return Err(Error::BundleBinding);
        }
        validate_routes(&config, metadata, &reader.routes, &["Authority", "Page"])?;
        expiry = expiry.min(
            reader
                .routes
                .iter()
                .map(|r| r.expires_ms)
                .min()
                .ok_or(Error::BundleBinding)?,
        );
    }
    if expiry != value.route_expires_ms {
        return Err(Error::BundleBinding);
    }
    Ok(())
}
fn validate_successor(old: &Delivery, next: &Delivery) -> Result<()> {
    if old.setup_bundle != next.setup_bundle
        || old.chat_request_sha256 != next.chat_request_sha256
        || old.access_expires_ms != next.access_expires_ms
        || old.join_expires_ms != next.join_expires_ms
        || old.reader.is_some() != next.reader.is_some()
    {
        return Err(Error::BundleBinding);
    }
    let check = |before: &[RouteDelivery], after: &[RouteDelivery]| -> Result<()> {
        for prior in before {
            let current = after
                .iter()
                .find(|r| r.role == prior.role)
                .ok_or(Error::BundleBinding)?;
            if current.subject != prior.subject
                || current.voucher_id != prior.voucher_id
                || current.generation < prior.generation
                || current.expires_ms < prior.expires_ms
                || (current.generation == prior.generation && current != prior)
            {
                return Err(Error::BundleBinding);
            }
        }
        Ok(())
    };
    check(&old.chat_routes, &next.chat_routes)?;
    if let (Some(a), Some(b)) = (&old.reader, &next.reader) {
        if a.network_invitation != b.network_invitation || a.request_sha256 != b.request_sha256 {
            return Err(Error::BundleBinding);
        }
        check(&a.routes, &b.routes)?;
    }
    Ok(())
}
fn native_join(
    c: &RuntimeConfig,
    invitation: &Artifact,
    folder: &Path,
    join_expires_ms: u64,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let report = native::json(
        &c.suite,
        &native::strings(&[
            "network",
            "inspect",
            "--profile",
            &native::path(&c.network_profile)?,
        ]),
        cancel,
        end,
    )?;
    if report["state"] == "Joined" && report["membership"] == true {
        return Ok(());
    }
    if c.clock()
        .sample()
        .map_err(|_| Error::ClockUnavailable)?
        .upper_ms
        >= join_expires_ms
    {
        return Err(Error::AdmissionJoinExpired);
    }
    let path = folder.join("NetworkInvitation.json");
    exact(&path, invitation, 1024 * 1024)?;
    native::run(
        &c.suite,
        &native::strings(&[
            "network",
            "join",
            "--profile",
            &native::path(&c.network_profile)?,
            "--invitation",
            &native::path(&path)?,
            "--invitation-digest",
            &invitation.sha256,
            "--directory",
            &native::path(&c.joined_directory)?,
            "--clock-witness",
            &native::path(&c.clock_directory.join("ClockHealth.json"))?,
        ]),
        cancel,
        end,
    )?;
    Ok(())
}
fn retain(
    c: &RuntimeConfig,
    routes: &[RouteDelivery],
    root: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    for route in routes {
        let path = root.join(format!("{}-{}.json", route.role, route.generation));
        exact(&path, &route.artifact, 1024 * 1024)?;
        native::run(
            &c.suite,
            &native::strings(&[
                "network",
                "retain-route",
                "--profile",
                &native::path(&c.network_profile)?,
                "--route-profile",
                &native::path(&path)?,
                "--fingerprint",
                &route.artifact.sha256,
                "--subject",
                &route.subject,
            ]),
            cancel,
            end,
        )?;
    }
    Ok(())
}
fn mark(root: &Path, name: &str, value: &Delivery) -> Result<()> {
    replace(
        &root.join(name),
        &json!({"delivery":admission::digest(&serde_json::to_vec(value).map_err(|_| Error::LocalConfiguration)?),
        "renewalAfterMs":value.renewal_after_ms,"expiresMs":value.route_expires_ms}),
    )
}
fn current(root: &Path, name: &str, value: &Delivery) -> bool {
    let Ok(saved) = read::<serde_json::Value>(&root.join(name)) else {
        return false;
    };
    serde_json::to_vec(value)
        .ok()
        .is_some_and(|bytes| saved["delivery"] == admission::digest(&bytes))
}
fn stop_companion(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    if !native::socket_live(&c.companion_directory.join("Control.sock"))? {
        return Ok(());
    }
    // Refuse a live companion with different bindings before touching its configured unit.
    runtime::companion(c, cancel, end)?;
    let hash = bundle::fingerprint(native::path(&c.data_directory)?.as_bytes());
    let unit = format!("hrc-client-{}-companion", &hash[..16]);
    native::run(
        Path::new("/usr/bin/systemctl"),
        &native::strings(&["--user", "stop", &unit]),
        cancel,
        end,
    )?;
    if native::socket_live(&c.companion_directory.join("Control.sock"))? {
        return Err(Error::Busy);
    }
    Ok(())
}
fn apply_chat(
    c: &RuntimeConfig,
    flow: &Workflow,
    delivery: &Delivery,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    if current(&flow.root, "ChatApplied.json", delivery) {
        return Ok(());
    }
    stop_companion(c, cancel, end)?;
    let routes = flow.root.join("ChatRoutes");
    native::directory(&routes)?;
    retain(c, &delivery.chat_routes, &routes, cancel, end)?;
    let home = runtime::accepted(c)?.invitation()?.home;
    let retained = c
        .joined_directory
        .join("Routes")
        .join(format!("{}.json", home.service.as_hex()));
    if c.companion_directory.join("Routes").exists() {
        crate::operations::network::replace_companion_target(
            &c.companion_directory,
            &c.network_profile,
            &home.service.as_hex(),
            &home.network.network.as_hex(),
            &home.network.incarnation.as_hex(),
            &retained,
        )
        .map_err(|_| Error::Busy)?;
    }
    mark(&flow.root, "ChatApplied.json", delivery)
}
fn apply_reader(
    c: &RuntimeConfig,
    flow: &Workflow,
    delivery: &Delivery,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let Some(reader) = &delivery.reader else {
        return Ok(());
    };
    if current(&flow.root, "ReaderApplied.json", delivery) {
        return Ok(());
    }
    let config = reader_config(c);
    let folder = flow.root.join("ReaderRoutes");
    native::directory(&folder)?;
    native_join(
        &config,
        &reader.network_invitation,
        &folder,
        delivery.join_expires_ms,
        cancel,
        end,
    )?;
    retain(&config, &reader.routes, &folder, cancel, end)?;
    mark(&flow.root, "ReaderApplied.json", delivery)
}

pub(super) fn join(
    c: &mut RuntimeConfig,
    text: &str,
    file: Option<&Path>,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    if !native::socket_path_valid(&c.companion_directory.join("Control.sock")) {
        return Err(Error::CompanionSocketPath);
    }
    invitation_folder(c)?;
    c.workspace()?;
    runtime::tools(c, cancel, end)?;
    runtime::start_clock(c, cancel, end)?;
    let supplied = if let Some(path) = file {
        String::from_utf8(native::public_file(path, 65536)?).map_err(|_| Error::Admission)?
    } else {
        text.trim().to_owned()
    };
    let root = c
        .self_service
        .clone()
        .unwrap_or_else(|| c.data_directory.join("Admission"));
    native::directory(&root)?;
    if !supplied.is_empty() {
        let invitation = admission::client::parse_invitation(&supplied).map_err(failure)?;
        native::exact_file(
            &root.join("Invitation.json"),
            &serde_json::to_vec(&invitation).map_err(|_| Error::Admission)?,
        )?;
    }
    c.self_service = Some(root);
    c.save()?;
    let profile_guard = profile_lease(c)?;
    let mut flow = Workflow::open(c)?;
    let metadata = flow.metadata(cancel, end)?;
    let bootstrap = flow.root.join("Bootstrap.cbor");
    exact(&bootstrap, &metadata.bootstrap, 1024 * 1024)?;
    runtime::prepare(
        c,
        &bootstrap,
        &metadata.bootstrap_fingerprint,
        true,
        cancel,
        end,
    )?;
    let reader = if metadata.reader_available {
        let config = reader_config(c);
        config.workspace()?;
        runtime::prepare(
            &config,
            &bootstrap,
            &metadata.bootstrap_fingerprint,
            true,
            cancel,
            end,
        )?;
        let chat = runtime::prepared(c)?;
        let other = runtime::prepared(&config)?;
        if chat.device_key == other.device_key || chat.relay_key == other.relay_key {
            return Err(Error::BundleBinding);
        }
        Some(request(&config)?)
    } else {
        None
    };
    let action = Action::Redeem {
        secret: flow.invitation.secret.clone(),
        chat_request: request(c)?,
        reader_request: reader,
    };
    let (mut delivery, enrolled) = flow.delivery(action, c, &metadata, cancel, end)?;
    let setup = flow.root.join("HrcSetup.json");
    exact(&setup, &delivery.setup_bundle, bundle::MAXIMUM_BUNDLE)?;
    runtime::import(c, &setup, &delivery.setup_bundle.sha256)?;
    let original = runtime::accepted(c)?;
    let native_invitation =
        Artifact::from_bytes(&original.network_invitation.bytes()?).map_err(failure)?;
    native_join(
        c,
        &native_invitation,
        &flow.root,
        delivery.join_expires_ms,
        cancel,
        end,
    )?;
    if c.clock()
        .sample()
        .map_err(|_| Error::ClockUnavailable)?
        .lower_ms
        >= delivery.renewal_after_ms
    {
        delivery = flow.delivery(Action::Renew, c, &metadata, cancel, end)?.0;
    }
    apply_chat(c, &flow, &delivery, cancel, end)?;
    apply_reader(c, &flow, &delivery, cancel, end)?;
    let home = original.invitation()?.home;
    native::exact_file(&c.targets_file, &serde_json::to_vec(&json!([{"service":home.service.as_hex(),"protocol":"hrc/1",
        "grant":original.connect_grant,"route":c.joined_directory.join("Routes").join(format!("{}.json",home.service.as_hex())),"renewalMs":0}]))
        .map_err(|_| Error::LocalConfiguration)?)?;
    if metadata.reader_available {
        c.page_browser_profile = Some(reader_config(c).network_profile);
    }
    c.save()?;
    let registration = runtime::create_endpoint(c)?;
    if !enrolled {
        let artifact = Artifact::from_bytes(
            &files::read(&registration, 65536).map_err(|_| Error::LocalConfiguration)?,
        )
        .map_err(failure)?;
        if !flow
            .delivery(
                Action::Enrol {
                    registration: artifact,
                },
                c,
                &metadata,
                cancel,
                end,
            )?
            .1
        {
            return Err(Error::Admission);
        }
    }
    runtime::companion(c, cancel, end)?;
    drop(profile_guard);
    runtime::verify(&c.hrc_profile, cancel, end)
}

fn invitation_folder(c: &mut RuntimeConfig) -> Result<()> {
    if c.self_service.is_some() {
        return Ok(());
    }
    let path = c.data_directory.join("OnboardingRuntime.json");
    if path.try_exists().map_err(|_| Error::LocalConfiguration)? {
        let saved = RuntimeConfig::load(&path)?;
        if binding(&saved) != binding(c) {
            return Err(Error::AdmissionFolder);
        }
        if saved.self_service.is_some() {
            c.self_service = saved.self_service;
            c.page_browser_profile = saved.page_browser_profile;
            return Ok(());
        }
    }
    if c.hrc_profile
        .try_exists()
        .map_err(|_| Error::LocalConfiguration)?
        || c.network_profile
            .try_exists()
            .map_err(|_| Error::LocalConfiguration)?
    {
        return Err(Error::AdmissionFolder);
    }
    Ok(())
}

fn profile_lease(c: &RuntimeConfig) -> Result<Option<hrc::storage::Store>> {
    if !c.hrc_profile.exists() {
        return Ok(None);
    }
    let profile = client::Profile::load(&c.hrc_profile).map_err(|_| Error::LocalConfiguration)?;
    profile.store(&c.hrc_profile).map(Some).map_err(|error| {
        if matches!(error, hrc::storage::Error::Busy) {
            Error::Busy
        } else {
            Error::LocalConfiguration
        }
    })
}

pub(crate) fn renewal_due(profile: &Path) -> bool {
    let Some(parent) = profile.parent() else {
        return false;
    };
    let Ok(c) = RuntimeConfig::load(&parent.join("OnboardingRuntime.json")) else {
        return false;
    };
    let Some(root) = &c.self_service else {
        return false;
    };
    let Ok(now) = c.clock().sample() else {
        return false;
    };
    let Ok(applied) = read::<serde_json::Value>(&root.join("ChatApplied.json")) else {
        return false;
    };
    c.hrc_profile == profile
        && applied["renewalAfterMs"]
            .as_u64()
            .is_some_and(|until| now.lower_ms >= until)
}
pub(super) fn renew_existing(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    if c.self_service.is_none() {
        return Ok(());
    }
    let _profile_guard = profile_lease(c)?;
    let mut flow = Workflow::open(c)?;
    let metadata = flow.metadata(cancel, end)?;
    let mut delivery: Delivery = read(&flow.root.join("Delivery.json"))?;
    validate_delivery(c, &metadata, &delivery)?;
    let now = c.clock().sample().map_err(|_| Error::ClockUnavailable)?;
    if now.upper_ms >= delivery.access_expires_ms {
        return Err(Error::AdmissionExpired);
    }
    if now.lower_ms >= delivery.renewal_after_ms {
        stop_companion(c, cancel, end)?;
        delivery = flow.delivery(Action::Renew, c, &metadata, cancel, end)?.0;
    }
    apply_chat(c, &flow, &delivery, cancel, end)
}
pub(crate) fn prepare_reader(c: &RuntimeConfig, cancel: &AtomicBool) -> Result<()> {
    if c.self_service.is_none() {
        return Ok(());
    }
    // An explicitly selected external reader remains independently managed.
    if c.page_browser_profile.as_ref() != Some(&reader_config(c).network_profile) {
        return Ok(());
    }
    let end = Instant::now() + Duration::from_secs(120);
    let mut flow = Workflow::open(c)?;
    let metadata = flow.metadata(cancel, end)?;
    let mut delivery: Delivery = read(&flow.root.join("Delivery.json"))?;
    validate_delivery(c, &metadata, &delivery)?;
    let now = c.clock().sample().map_err(|_| Error::ClockUnavailable)?;
    if now.upper_ms >= delivery.access_expires_ms {
        return Err(Error::AdmissionExpired);
    }
    if now.lower_ms >= delivery.renewal_after_ms {
        delivery = flow.delivery(Action::Renew, c, &metadata, cancel, end)?.0;
    }
    apply_reader(c, &flow, &delivery, cancel, end)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Onboarding/SelfService.rs"]
mod tests;
