// SPDX-License-Identifier: Apache-2.0
//! Explicit local runtime configuration and resumable native onboarding operations.
use super::{
    Error, Result,
    bundle::{self, Bundle},
    native,
};
use hrc::{client, clock, service::files};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

/// Explicit local observer ownership; setup bundles cannot supply executable configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateChrony {
    pub executable: PathBuf,
    pub configuration: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub format: String,
    pub data_directory: PathBuf,
    pub suite: PathBuf,
    pub core: PathBuf,
    pub network_profile: PathBuf,
    pub joined_directory: PathBuf,
    pub companion_directory: PathBuf,
    pub targets_file: PathBuf,
    pub clock_directory: PathBuf,
    pub clock_observation: PathBuf,
    pub clock_monitor_key: String,
    pub chronyc: PathBuf,
    pub chrony_socket: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_chrony: Option<PrivateChrony>,
    pub hrc_profile: PathBuf,
    pub recovery_key: PathBuf,
    pub registration_file: PathBuf,
}
impl RuntimeConfig {
    pub fn at(data_directory: PathBuf) -> Self {
        let root = &data_directory;
        Self {
            format: "HrcOnboardingRuntime/1".into(),
            suite: native::discover("HyperNetSuite"),
            core: native::discover("HyperNet"),
            network_profile: root.join("Network/Profile.json"),
            joined_directory: root.join("Network/Connected"),
            companion_directory: root.join("Companion"),
            targets_file: root.join("Network/Targets.json"),
            clock_directory: root.join("Clock"),
            clock_observation: root.join("Clock/Public/ClockHealth.cbor"),
            clock_monitor_key: String::new(),
            chronyc: native::discover("chronyc"),
            chrony_socket: PathBuf::from("/run/chrony/chronyd.sock"),
            private_chrony: None,
            hrc_profile: root.join("Profile"),
            recovery_key: root.join("Recovery/Account.key"),
            registration_file: root.join("Exchange/HrcRegistration.cbor"),
            data_directory,
        }
    }
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(
            &files::read(path, 65536).map_err(|_| Error::LocalConfiguration)?,
        )
        .map_err(|_| Error::LocalConfiguration)?;
        value.paths()?;
        Ok(value)
    }
    pub fn save(&self) -> Result<()> {
        self.paths()?;
        native::replace_file(
            &self.data_directory.join("OnboardingRuntime.json"),
            &serde_json::to_vec_pretty(self).map_err(|_| Error::LocalConfiguration)?,
        )
    }
    fn paths(&self) -> Result<()> {
        if self.format != "HrcOnboardingRuntime/1"
            || self.recovery_key.starts_with(&self.hrc_profile)
        {
            return Err(Error::LocalConfiguration);
        }
        for path in [
            &self.data_directory,
            &self.network_profile,
            &self.joined_directory,
            &self.companion_directory,
            &self.targets_file,
            &self.clock_directory,
            &self.clock_observation,
            &self.hrc_profile,
            &self.recovery_key,
            &self.registration_file,
        ] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err(Error::LocalConfiguration);
            }
        }
        if let Some(observer) = &self.private_chrony {
            for path in [&observer.executable, &observer.configuration] {
                if !path.is_absolute()
                    || path
                        .components()
                        .any(|p| matches!(p, std::path::Component::ParentDir))
                {
                    return Err(Error::LocalConfiguration);
                }
            }
        }
        Ok(())
    }
    pub fn clock(&self) -> clock::Config {
        clock::Config {
            observation: self.clock_observation.clone(),
            monitor_key: self.clock_monitor_key.clone(),
        }
    }
    fn workspace(&self) -> Result<()> {
        self.paths()?;
        native::directory(&self.data_directory)?;
        for p in [
            &self.network_profile,
            &self.targets_file,
            &self.recovery_key,
            &self.registration_file,
        ] {
            native::directory(p.parent().ok_or(Error::LocalConfiguration)?)?;
        }
        native::directory(&self.data_directory.join("Setup"))
    }
}

#[derive(Clone)]
pub(super) enum Task {
    Browse(PathBuf),
    Existing {
        profile: PathBuf,
        offline: bool,
    },
    Preflight,
    StartClock,
    Prepare {
        bootstrap: PathBuf,
        fingerprint: String,
        organisational: bool,
    },
    Import {
        path: PathBuf,
        fingerprint: String,
    },
    Connect,
    CreateEndpoint,
    Verify,
}
pub(super) struct Completed {
    pub config: RuntimeConfig,
    pub notice: &'static str,
    pub export: Option<PathBuf>,
    pub open: Option<super::wizard::Selection>,
    pub listing: Option<(PathBuf, Vec<(PathBuf, bool)>)>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepared {
    bootstrap_sha256: String,
    device_key: String,
    relay_key: String,
    network: String,
    incarnation: String,
}
fn prepared(c: &RuntimeConfig) -> Result<Prepared> {
    files::json(&c.data_directory.join("PreparedNetwork.json"))
        .map_err(|_| Error::LocalConfiguration)
}
fn accepted(c: &RuntimeConfig) -> Result<Bundle> {
    let path = c.data_directory.join("AcceptedSetup.json");
    let bytes =
        files::read(&path, bundle::MAXIMUM_BUNDLE).map_err(|_| Error::LocalConfiguration)?;
    Bundle::load(&path, &bundle::fingerprint(&bytes))
}
fn args(parts: &[&str]) -> Vec<String> {
    native::strings(parts)
}
fn tools(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    for (path, name) in [(&c.suite, "HyperNetSuite"), (&c.core, "HyperNet")] {
        let out = native::run(path, &args(&["--version"]), cancel, end)?;
        if !String::from_utf8_lossy(&out).starts_with(name) {
            return Err(Error::RuntimeMissing);
        }
    }
    Ok(())
}
fn unit(
    c: &RuntimeConfig,
    purpose: &str,
    program: &Path,
    arguments: Vec<String>,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let hash = bundle::fingerprint(native::path(&c.data_directory)?.as_bytes());
    let name = format!("hrc-client-{}-{purpose}", &hash[..16]);
    native::executable(program)?;
    match native::run(
        Path::new("/usr/bin/systemctl"),
        &args(&["--user", "is-active", "--quiet", &name]),
        cancel,
        end,
    ) {
        Ok(_) => return Ok(()),
        Err(Error::NativeRefused) => {}
        Err(error) => return Err(error),
    }
    let mut command = args(&[
        "--user",
        "--collect",
        "--quiet",
        "--property=Restart=no",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
    ]);
    command.push(format!("--unit={name}"));
    command.push("--".into());
    command.push(native::path(program)?);
    command.extend(arguments);
    native::run(Path::new("/usr/bin/systemd-run"), &command, cancel, end)?;
    Ok(())
}

fn chrony_available(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<bool> {
    native::check(cancel, end)?;
    if native::private_socket(&c.chrony_socket).is_err() {
        return Ok(false);
    }
    match native::run(
        &c.chronyc,
        &args(&[
            "-n",
            "-c",
            "-h",
            &native::path(&c.chrony_socket)?,
            "authdata",
        ]),
        cancel,
        end.min(Instant::now() + Duration::from_secs(2)),
    ) {
        Ok(_) => Ok(true),
        Err(Error::NativeRefused | Error::Deadline) => {
            native::check(cancel, end)?;
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn ensure_chrony(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    if chrony_available(c, cancel, end)? {
        return Ok(());
    }
    let observer = c.private_chrony.as_ref().ok_or(Error::ClockPrerequisite)?;
    native::executable(&observer.executable).map_err(|_| Error::ClockPrerequisite)?;
    // A private owner file, never an operator-bundle command or system configuration edit.
    files::read(&observer.configuration, 65536).map_err(|_| Error::ClockPrerequisite)?;
    unit(
        c,
        "chrony",
        &observer.executable,
        args(&[
            "-U",
            "-x",
            "-d",
            "-u",
            &native::current_user()?,
            "-f",
            &native::path(&observer.configuration)?,
        ]),
        cancel,
        end,
    )?;
    let wait_end = end.min(Instant::now() + Duration::from_secs(8));
    loop {
        native::check(cancel, wait_end)?;
        if chrony_available(c, cancel, wait_end)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Recover only a private, internally consistent existing signer, including an
/// interrupted initialise-export. No new identity is generated on this path.
pub(super) fn recover_clock_identity(c: &mut RuntimeConfig) -> Result<()> {
    use zeroize::{Zeroize, Zeroizing};
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ClockConfig {
        chronyc: PathBuf,
        socket: PathBuf,
        export_directory: PathBuf,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Identity {
        secret_key: String,
        public_key: String,
    }
    let config: ClockConfig = files::json(&c.clock_directory.join("ClockConfig.json"))
        .map_err(|_| Error::ClockUnavailable)?;
    if config.chronyc != c.chronyc
        || config.socket != c.chrony_socket
        || config.export_directory != c.clock_directory.join("Public")
        || c.clock_observation != config.export_directory.join("ClockHealth.cbor")
    {
        return Err(Error::ClockUnavailable);
    }
    let bytes = Zeroizing::new(
        files::read(&c.clock_directory.join("ClockSigner.json"), 4096)
            .map_err(|_| Error::ClockUnavailable)?,
    );
    let mut identity: Identity =
        serde_json::from_slice(&bytes).map_err(|_| Error::ClockUnavailable)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    let decoded = hex::decode_to_slice(&identity.secret_key, &mut *secret);
    identity.secret_key.zeroize();
    decoded.map_err(|_| Error::ClockUnavailable)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let public = hex::encode(key.verifying_key().to_bytes());
    if public != identity.public_key
        || (!c.clock_monitor_key.is_empty() && c.clock_monitor_key != public)
    {
        return Err(Error::ClockUnavailable);
    }
    c.clock_monitor_key = public;
    c.save()
}

fn start_clock(c: &mut RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    if c.clock().sample().is_ok() {
        return Ok(());
    }
    native::executable(&c.chronyc).map_err(|_| Error::ClockPrerequisite)?;
    ensure_chrony(c, cancel, end)?;
    // Native observation validates authdata and source provenance without changing system time.
    let probe = c.data_directory.join("ClockProbe");
    native::directory(&probe)?;
    let probe_end = end.min(Instant::now() + Duration::from_secs(8));
    loop {
        native::check(cancel, probe_end)?;
        match native::run(
            &c.suite,
            &args(&[
                "network",
                "clock",
                "observe",
                "--directory",
                &native::path(&probe)?,
                "--chronyc",
                &native::path(&c.chronyc)?,
                "--socket",
                &native::path(&c.chrony_socket)?,
            ]),
            cancel,
            probe_end,
        ) {
            Ok(_) => break,
            // A just-started private observer may answer before its NTS sources are ready.
            Err(Error::NativeRefused) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(error),
        }
    }
    if !c.clock_directory.exists() {
        native::run(
            &c.core,
            &args(&[
                "runtime",
                "provision",
                "clock",
                "--directory",
                &native::path(&c.clock_directory)?,
                "--export-directory",
                &native::path(&c.clock_directory.join("Public"))?,
                "--chronyc",
                &native::path(&c.chronyc)?,
                "--socket",
                &native::path(&c.chrony_socket)?,
            ]),
            cancel,
            end,
        )?;
    }
    if !c.clock_directory.join("ClockSigner.json").exists() {
        native::run(
            &c.core,
            &args(&[
                "authority-clock",
                "initialise-export",
                "--directory",
                &native::path(&c.clock_directory)?,
            ]),
            cancel,
            end,
        )?;
    }
    recover_clock_identity(c)?;
    unit(
        c,
        "clock",
        &c.core,
        args(&[
            "authority-clock",
            "monitor",
            "--directory",
            &native::path(&c.clock_directory)?,
        ]),
        cancel,
        end,
    )?;
    let wait_end = end.min(Instant::now() + Duration::from_secs(8));
    loop {
        native::check(cancel, wait_end)?;
        if c.clock().sample().is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn prepare(
    c: &RuntimeConfig,
    bootstrap: &Path,
    fingerprint: &str,
    organisational: bool,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<PathBuf> {
    if !bundle::is_digest(fingerprint) {
        return Err(Error::BundleBinding);
    }
    let bytes = native::public_file(bootstrap, 1024 * 1024)?;
    let saved = c.data_directory.join("Setup/Bootstrap.cbor");
    native::exact_file(&saved, &bytes)?;
    if !c.network_profile.exists() {
        native::run(
            &c.suite,
            &args(&[
                "network",
                "prepare",
                "--bootstrap",
                &native::path(&saved)?,
                "--fingerprint",
                fingerprint,
                "--minimum-route",
                if organisational {
                    "Organisational"
                } else {
                    "Independent"
                },
                "--output",
                &native::path(&c.network_profile)?,
            ]),
            cancel,
            end,
        )?;
    }
    // Reuse only the exact accepted bootstrap, including after interrupted preparation.
    let inspected = native::json(
        &c.suite,
        &args(&[
            "network",
            "inspect",
            "--profile",
            &native::path(&c.network_profile)?,
        ]),
        cancel,
        end,
    )?;
    if inspected["fingerprint"] != fingerprint {
        return Err(Error::BundleBinding);
    }
    let request = c.data_directory.join("Exchange/NetworkRequest.cbor");
    if !request.exists() {
        native::run(
            &c.suite,
            &args(&[
                "network",
                "request",
                "--profile",
                &native::path(&c.network_profile)?,
                "--output",
                &native::path(&request)?,
            ]),
            cancel,
            end,
        )?;
    }
    let public = native::json(
        &c.suite,
        &args(&[
            "network",
            "inspect-request",
            "--request",
            &native::path(&request)?,
        ]),
        cancel,
        end,
    )?;
    let device = public["devicePublicKey"]
        .as_str()
        .filter(|s| bundle::is_digest(s))
        .ok_or(Error::NativeRefused)?;
    let relay = public["relayPublicKey"]
        .as_str()
        .filter(|s| bundle::is_digest(s))
        .ok_or(Error::NativeRefused)?;
    if inspected["devicePublicKey"] != device || inspected["relayPublicKey"] != relay {
        return Err(Error::BundleBinding);
    }
    let prepared = Prepared {
        bootstrap_sha256: bundle::fingerprint(&bytes),
        device_key: device.into(),
        relay_key: relay.into(),
        network: public["network"]
            .as_str()
            .ok_or(Error::NativeRefused)?
            .into(),
        incarnation: public["incarnation"]
            .as_str()
            .ok_or(Error::NativeRefused)?
            .into(),
    };
    native::exact_file(
        &c.data_directory.join("PreparedNetwork.json"),
        &serde_json::to_vec(&prepared).map_err(|_| Error::LocalConfiguration)?,
    )?;
    Ok(request)
}
fn import(c: &RuntimeConfig, path: &Path, fingerprint: &str) -> Result<()> {
    let bundle = Bundle::load(path, fingerprint)?;
    let prepared = prepared(c)?;
    let route = bundle::route(&bundle.application_route.bytes()?, 7)?;
    if prepared.bootstrap_sha256 != bundle.bootstrap.digest()
        || prepared.relay_key != route.possession
        || prepared.network != route.network
        || prepared.incarnation != route.incarnation
        || prepared.device_key != bundle.invitation()?.principal.as_hex()
    {
        return Err(Error::BundleBinding);
    }
    bundle.materialize(&c.data_directory.join("Setup"))?;
    native::exact_file(
        &c.data_directory.join("AcceptedSetup.json"),
        &native::public_file(path, bundle::MAXIMUM_BUNDLE)?,
    )
}
fn companion(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    let expected = prepared(c)?;
    let bundle = accepted(c)?;
    let home = bundle.invitation()?.home;
    ensure_companion(c, &expected.device_key, home, cancel, end)
}
fn ensure_companion(
    c: &RuntimeConfig,
    principal: &str,
    home: hrc::protocol::ServiceId,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let socket = c.companion_directory.join("Control.sock");
    if native::socket_live(&socket)? {
        let status = native::json(
            &c.suite,
            &args(&[
                "streams",
                "status",
                "--directory",
                &native::path(&c.companion_directory)?,
            ]),
            cancel,
            end,
        )?;
        if status["principal"] != principal
            || status["network"] != home.network.network.as_hex()
            || status["incarnation"] != home.network.incarnation.as_hex()
            || !status["targets"].as_array().is_some_and(|targets| {
                targets
                    .iter()
                    .any(|t| t["service"] == home.service.as_hex() && t["protocol"] == "hrc/1")
            })
        {
            return Err(Error::CompanionBinding);
        }
        return Ok(());
    }
    unit(
        c,
        "companion",
        &c.suite,
        args(&[
            "network",
            "connect",
            "--profile",
            &native::path(&c.network_profile)?,
            "--",
            "streams",
            "agent",
            "--ipc-directory",
            &native::path(&c.companion_directory)?,
            "--targets",
            &native::path(&c.targets_file)?,
        ]),
        cancel,
        end,
    )?;
    let wait_end = end.min(Instant::now() + Duration::from_secs(8));
    while !native::socket_live(&socket)? {
        native::check(cancel, wait_end)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    // Inspect a newly started companion using the same binding checks as a reused one.
    ensure_companion(c, principal, home, cancel, end)
}

/// Start only explicitly configured local user services; an externally managed
/// profile needs no configuration file and remains usable without this launcher.
pub fn prepare_existing(profile: &Path, offline: bool, cancel: &AtomicBool) -> Result<()> {
    prepare_existing_before(
        profile,
        offline,
        cancel,
        Instant::now() + Duration::from_secs(30),
    )
}
fn prepare_existing_before(
    profile: &Path,
    offline: bool,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    native::check(cancel, end)?;
    let loaded = client::Profile::load(profile).map_err(|_| Error::LocalConfiguration)?;
    if offline {
        return Ok(());
    }
    let path = profile
        .parent()
        .ok_or(Error::LocalConfiguration)?
        .join("OnboardingRuntime.json");
    if !path.try_exists().map_err(|_| Error::LocalConfiguration)? {
        return Ok(());
    }
    let mut config = RuntimeConfig::load(&path)?;
    if config.hrc_profile != profile
        || config.companion_directory != loaded.companion
        || config.clock_observation != loaded.clock.observation
        || config.clock_monitor_key != loaded.clock.monitor_key
    {
        return Err(Error::LocalConfiguration);
    }
    start_clock(&mut config, cancel, end)?;
    ensure_companion(
        &config,
        &loaded.registration.transport_principal.as_hex(),
        loaded.server.home,
        cancel,
        end,
    )
}
fn connect(c: &RuntimeConfig, cancel: &AtomicBool, end: Instant) -> Result<()> {
    let bundle = accepted(c)?;
    let now = c.clock().sample().map_err(|_| Error::ClockUnavailable)?;
    let setup = c.data_directory.join("Setup");
    for (artifact, protocol) in [(&bundle.authority_route, 1), (&bundle.application_route, 7)] {
        let route = bundle::route(&artifact.bytes()?, protocol)?;
        if now.upper_ms >= route.expires_ms || route.connections == 0 {
            return Err(Error::BundleBinding);
        }
    }
    native::run(
        &c.suite,
        &args(&[
            "network",
            "join",
            "--profile",
            &native::path(&c.network_profile)?,
            "--invitation",
            &native::path(&setup.join("NetworkInvitation.json"))?,
            "--invitation-digest",
            bundle.network_invitation.digest(),
            "--directory",
            &native::path(&c.joined_directory)?,
            "--clock-witness",
            &native::path(&c.clock_directory.join("ClockHealth.json"))?,
        ]),
        cancel,
        end,
    )?;
    for (name, artifact, protocol) in [
        ("AuthorityRoute.json", &bundle.authority_route, 1),
        ("ApplicationRoute.json", &bundle.application_route, 7),
    ] {
        let route = bundle::route(&artifact.bytes()?, protocol)?;
        native::run(
            &c.suite,
            &args(&[
                "network",
                "retain-route",
                "--profile",
                &native::path(&c.network_profile)?,
                "--route-profile",
                &native::path(&setup.join(name))?,
                "--fingerprint",
                artifact.digest(),
                "--subject",
                &route.service,
            ]),
            cancel,
            end,
        )?;
    }
    let home = bundle.invitation()?.home;
    let targets = json!([{"service":home.service.as_hex(),"protocol":"hrc/1","grant":bundle.connect_grant,
        "route":c.joined_directory.join("Routes").join(format!("{}.json",home.service.as_hex())),"renewalMs":bundle.renewal_ms}]);
    native::exact_file(
        &c.targets_file,
        &serde_json::to_vec(&targets).map_err(|_| Error::LocalConfiguration)?,
    )?;
    companion(c, cancel, end)
}
fn create_endpoint(c: &RuntimeConfig) -> Result<PathBuf> {
    let expected = accepted(c)?.invitation()?;
    if c.hrc_profile.exists() {
        let profile =
            client::Profile::load(&c.hrc_profile).map_err(|_| Error::LocalConfiguration)?;
        if profile.registration.invitation != expected.id
            || profile.server.home != expected.home
            || profile.server.signing_key != expected.service_key
            || profile.registration.transport_principal != expected.principal
            || profile.companion != c.companion_directory
            || profile.clock.observation != c.clock_observation
            || profile.clock.monitor_key != c.clock_monitor_key
        {
            return Err(Error::BundleBinding);
        }
        files::read(&c.registration_file, 65536).map_err(|_| Error::LocalConfiguration)?;
    } else {
        client::setup::create(
            &c.hrc_profile,
            &c.data_directory.join("Setup/HrcInvitation.json"),
            c.companion_directory.clone(),
            c.clock(),
            &c.recovery_key,
            &c.registration_file,
        )
        .map_err(|_| Error::LocalConfiguration)?;
    }
    Ok(c.registration_file.clone())
}
fn verify(profile: &Path, cancel: &AtomicBool, end: Instant) -> Result<()> {
    let value = client::Profile::load(profile).map_err(|_| Error::LocalConfiguration)?;
    value.clock.sample().map_err(|_| Error::ClockUnavailable)?;
    let executable = std::env::current_exe().map_err(|_| Error::RuntimeMissing)?;
    let result = native::json(
        &executable,
        &args(&["profile", "session", "--profile", &native::path(profile)?]),
        cancel,
        end,
    )
    .map_err(|e| {
        if matches!(e, Error::Cancelled | Error::Deadline) {
            e
        } else {
            Error::ActivationPending
        }
    })?;
    if result["status"] != "Authenticated" {
        return Err(Error::ActivationPending);
    }
    Ok(())
}
pub(super) fn perform(
    task: Task,
    mut config: RuntimeConfig,
    cancel: &AtomicBool,
) -> Result<Completed> {
    // One fixed operation budget; component commands cannot restart it.
    let end = Instant::now() + Duration::from_secs(120);
    native::check(cancel, end)?;
    let mut export = None;
    let mut open = None;
    let mut listing = None;
    let notice = match task {
        Task::Browse(path) => {
            let path = path.canonicalize().map_err(|_| Error::LocalConfiguration)?;
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&path)
                .map_err(|_| Error::LocalConfiguration)?
                .take(256)
            {
                native::check(cancel, end)?;
                let entry = entry.map_err(|_| Error::LocalConfiguration)?;
                let kind = entry.file_type().map_err(|_| Error::LocalConfiguration)?;
                if kind.is_dir() || kind.is_file() || kind.is_socket() {
                    entries.push((entry.path(), kind.is_dir()));
                }
            }
            entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            listing = Some((path, entries));
            "Choose a local file or folder"
        }
        Task::Existing { profile, offline } => {
            prepare_existing_before(&profile, offline, cancel, end)?;
            if !offline {
                verify(&profile, cancel, end)?;
            }
            open = Some(super::wizard::Selection { profile, offline });
            "Profile ready"
        }
        Task::Preflight => {
            config.workspace()?;
            tools(&config, cancel, end)?;
            config.save()?;
            if config.clock().sample().is_ok() {
                "Runtime and local clock ready"
            } else {
                "Runtime ready. Start or select a local clock."
            }
        }
        Task::StartClock => {
            config.workspace()?;
            tools(&config, cancel, end)?;
            start_clock(&mut config, cancel, end)?;
            config.save()?;
            "Local signed clock ready"
        }
        Task::Prepare {
            bootstrap,
            fingerprint,
            organisational,
        } => {
            config.workspace()?;
            tools(&config, cancel, end)?;
            export = Some(prepare(
                &config,
                &bootstrap,
                &fingerprint,
                organisational,
                cancel,
                end,
            )?);
            config.save()?;
            "Send this public request to your network operator"
        }
        Task::Import { path, fingerprint } => {
            config.workspace()?;
            import(&config, &path, &fingerprint)?;
            config.save()?;
            "Setup bundle accepted for this device"
        }
        Task::Connect => {
            config.workspace()?;
            tools(&config, cancel, end)?;
            connect(&config, cancel, end)?;
            "Network joined and companion ready"
        }
        Task::CreateEndpoint => {
            export = Some(create_endpoint(&config)?);
            "Send this signed registration to your service operator"
        }
        Task::Verify => {
            verify(&config.hrc_profile, cancel, end)?;
            open = Some(super::wizard::Selection {
                profile: config.hrc_profile.clone(),
                offline: false,
            });
            "Authenticated. Ready for chat."
        }
    };
    native::check(cancel, end)?;
    Ok(Completed {
        config,
        notice,
        export,
        open,
        listing,
    })
}
