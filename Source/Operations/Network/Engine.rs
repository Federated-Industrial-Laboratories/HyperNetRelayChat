// SPDX-License-Identifier: Apache-2.0
//! Exact configuration review, bounded native calls and a single durable setup journal.
use super::{Configuration, Error, Preview, Requirement, Result, Status};
use crate::operations::native;
use hrc::service::files;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) fn random() -> Result<String> {
    hrc::protocol::Id::random()
        .map(|v| v.as_hex())
        .map_err(|_| Error::State)
}
pub(super) fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
pub(super) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .map_err(|_| Error::State)
}
pub(super) fn text(path: &Path) -> Result<String> {
    native::path(path).map_err(|_| Error::Configuration("path"))
}
pub(super) fn bytes(args: &[&str]) -> Vec<String> {
    args.iter().map(|v| v.to_string()).collect()
}
pub(super) fn string(v: &Value, key: &str) -> Result<String> {
    v[key].as_str().map(str::to_owned).ok_or(Error::State)
}
pub(super) fn number(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().ok_or(Error::State)
}
pub(super) fn read(path: &Path) -> Result<Value> {
    serde_json::from_slice(&files::read(path, 1_048_576).map_err(|_| Error::State)?)
        .map_err(|_| Error::State)
}
pub(super) fn public_read(path: &Path) -> Result<Value> {
    serde_json::from_slice(&native::public_file(path, 1_048_576).map_err(|_| Error::State)?)
        .map_err(|_| Error::State)
}
pub(super) fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).map_err(|_| Error::State)?;
    if data.len() > 1_048_576 {
        return Err(Error::State);
    }
    let parent = path.parent().ok_or(Error::State)?;
    files::directory(parent, false).map_err(|_| Error::State)?;
    if path.exists() {
        files::read(path, 1_048_576).map_err(|_| Error::State)?;
    }
    let temporary = parent.join(format!(".operation-{}", random()?));
    files::create(&temporary, &data).map_err(|_| Error::State)?;
    fs::rename(&temporary, path)
        .and_then(|_| File::open(parent)?.sync_all())
        .map_err(|_| Error::State)
}
pub(super) fn check(cancel: &AtomicBool, end: Instant) -> Result<()> {
    if cancel.load(Ordering::Acquire) {
        return Err(Error::Cancelled);
    }
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    Ok(())
}
pub(super) fn invoke(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
    phase: &str,
) -> Result<Value> {
    let out = raw(program, args, cancel, end, phase)?;
    serde_json::from_slice(&out).map_err(|_| Error::Native(phase.into()))
}
pub(super) fn raw(
    program: &Path,
    args: &[String],
    cancel: &AtomicBool,
    end: Instant,
    phase: &str,
) -> Result<Vec<u8>> {
    check(cancel, end)?;
    let program = program
        .canonicalize()
        .map_err(|_| Error::Native(phase.into()))?;
    let result = native::run(&program, args, cancel, end);
    check(cancel, end)?;
    result.map_err(|_| Error::Native(phase.into()))
}
pub(super) fn config_digest(c: &Configuration) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({"format":"HrcHostingReview/1","configuration":c,"core":crate::operations::packages::Product::Core.version(),"suite":crate::operations::packages::Product::Suite.version(),"publisher":crate::operations::packages::PUBLISHER})).map_err(|_| Error::State)?))
}
pub fn preview(c: &Configuration, cancel: &AtomicBool) -> Result<Preview> {
    c.validate()?;
    let end = Instant::now() + Duration::from_secs(180);
    let mut requirements = Vec::new();
    for (component, path, action) in [
        (
            "Podman",
            "/usr/bin/podman",
            "Install rootless Podman and configure subordinate UID/GID mappings.",
        ),
        (
            "slirp4netns",
            "/usr/bin/slirp4netns",
            "Install the distribution slirp4netns package.",
        ),
        (
            "OpenSSL",
            "/usr/bin/openssl",
            "Install the distribution OpenSSL package.",
        ),
        (
            "Python",
            "/usr/bin/python3",
            "Install Python 3.11 or later for signed package verification.",
        ),
        (
            "OpenSSH",
            "/usr/bin/ssh-keygen",
            "Install OpenSSH client tools for release signature verification.",
        ),
        (
            "systemd user manager",
            "/usr/bin/systemd-run",
            "Enable a working systemd user session.",
        ),
    ] {
        requirements.push(Requirement {
            component: component.into(),
            ready: Path::new(path)
                .canonicalize()
                .is_ok_and(|p| native::executable(&p).is_ok()),
            action: action.into(),
        });
    }
    let landlock = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            1u32,
        )
    };
    requirements.push(Requirement { component: "Landlock ABI 6".into(), ready: landlock >= 6, action: "Use a Linux kernel with Landlock ABI 6 or later; hosting confinement cannot be disabled.".into() });
    requirements.push(Requirement { component: "Chrony command socket".into(), ready: native::private_socket(&c.chrony_socket).is_ok() && native::executable(&c.chronyc).is_ok(), action: "Select a readable chrony command socket with authenticated NTS sources. No clock or policy changes are automatic.".into() });
    let user_ready = raw(
        Path::new("/usr/bin/systemctl"),
        &bytes(&["--user", "show", "--property=Version", "--value"]),
        cancel,
        end,
        "user manager",
    )
    .is_ok();
    requirements.push(Requirement {
        component: "User services".into(),
        ready: user_ready,
        action: "Start a systemd user session before creating this host.".into(),
    });
    let core = crate::operations::packages::verify_installed(
        crate::operations::packages::Product::Core,
        &c.core,
        &c.publisher_key,
        cancel,
        end,
    )
    .map_err(|_| Error::Package)?;
    let suite = crate::operations::packages::verify_installed(
        crate::operations::packages::Product::Suite,
        &c.suite,
        &c.publisher_key,
        cancel,
        end,
    )
    .map_err(|_| Error::Package)?;
    let ready = requirements.iter().all(|v| v.ready);
    let review_digest = digest(
        &serde_json::to_vec(&json!({"configuration":config_digest(c)?,"core":core,"suite":suite}))
            .map_err(|_| Error::State)?,
    );
    Ok(Preview {
        digest: review_digest,
        configuration: c.clone(),
        requirements,
        ready,
        authority_replicas: 4,
        host_failure_independence: false,
        privacy: "Organisational: one operator can correlate relay and destination activity".into(),
        memory_admission_bytes: c.resources.memory_bytes_per_role * 7,
        storage_admission_bytes: c.resources.state_bytes_per_role * 7,
        core_package: core,
        suite_package: suite,
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Journal {
    pub format: String,
    pub configuration_digest: String,
    pub image: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub phase: String,
    pub ids: BTreeMap<String, String>,
    pub results: BTreeMap<String, Value>,
    pub artifacts: BTreeMap<String, String>,
    pub completed: bool,
}
pub(super) struct Host<'a> {
    pub c: &'a Configuration,
    pub cancel: &'a AtomicBool,
    pub end: Instant,
    pub state: Journal,
    _lock: File,
}
impl<'a> Host<'a> {
    pub fn open(
        c: &'a Configuration,
        cancel: &'a AtomicBool,
        create: Option<&Preview>,
    ) -> Result<Self> {
        c.validate()?;
        let root_exists = c.root.exists();
        if !root_exists && create.is_none() {
            return Err(Error::State);
        }
        crate::operations::private_directory(&c.root).map_err(|_| Error::State)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(c.root.join("Operation.lock"))
            .map_err(|_| Error::State)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Busy);
        }
        let path = c.root.join("Hosting.json");
        let state = if path.exists() {
            let value: Journal = serde_json::from_value(read(&path)?).map_err(|_| Error::State)?;
            if value.format != "HrcHosting/1" || value.configuration_digest != config_digest(c)? {
                return Err(Error::State);
            }
            value
        } else {
            let p = create.ok_or(Error::State)?;
            if root_exists && fs::read_dir(&c.root).map_err(|_| Error::State)?.count() != 1 {
                return Err(Error::State);
            }
            let created_ms = now()? / 1000 * 1000;
            Journal {
                format: "HrcHosting/1".into(),
                configuration_digest: config_digest(c)?,
                image: string(&p.core_package["metadata"], "imageId")?,
                created_ms,
                expires_ms: created_ms + u64::from(c.lifetime_hours) * 3_600_000,
                phase: "Preparing".into(),
                ids: BTreeMap::new(),
                results: BTreeMap::new(),
                artifacts: BTreeMap::new(),
                completed: false,
            }
        };
        let host = Self {
            c,
            cancel,
            end: Instant::now() + Duration::from_secs(1200),
            state,
            _lock: lock,
        };
        host.verify_artifacts()?;
        host.save()?;
        Ok(host)
    }
    pub fn save(&self) -> Result<()> {
        write(&self.c.root.join("Hosting.json"), &self.state)
    }
    pub fn phase(&mut self, phase: &str) -> Result<()> {
        self.state.phase = phase.into();
        self.save()
    }
    pub fn id(&mut self, name: &str) -> Result<String> {
        if let Some(value) = self.state.ids.get(name) {
            return Ok(value.clone());
        }
        let value = random()?;
        self.state.ids.insert(name.into(), value.clone());
        self.save()?;
        Ok(value)
    }
    pub fn p(&self, name: &str) -> PathBuf {
        self.c.root.join(name)
    }
    pub fn dir(&self, name: &str) -> Result<PathBuf> {
        let path = self.p(name);
        native::directory(&path).map_err(|_| Error::State)?;
        Ok(path)
    }
    pub fn core(&self, args: &[String]) -> Result<Value> {
        let result = invoke(&self.c.core, args, self.cancel, self.end, &self.state.phase)?;
        if result["ok"] == false {
            return Err(Error::Native(self.state.phase.clone()));
        }
        Ok(result)
    }
    pub fn suite(&self, args: &[String]) -> Result<Value> {
        invoke(
            &self.c.suite,
            args,
            self.cancel,
            self.end,
            &self.state.phase,
        )
    }
    pub fn remember(&mut self, name: &str, value: Value) -> Result<Value> {
        self.state.results.insert(name.into(), value.clone());
        self.save()?;
        Ok(value)
    }
    pub fn remembered(&self, name: &str) -> Option<Value> {
        self.state.results.get(name).cloned()
    }
    pub fn artifact(&mut self, path: &Path) -> Result<()> {
        if !path.starts_with(&self.c.root) && !path.starts_with(&self.c.recovery_directory) {
            return Err(Error::State);
        }
        let data = native::public_file(path, 1_048_576).map_err(|_| Error::State)?;
        let hash = digest(&data);
        let key = text(path)?;
        if self
            .state
            .artifacts
            .get(&key)
            .is_some_and(|old| old != &hash)
        {
            return Err(Error::State);
        }
        self.state.artifacts.insert(key, hash);
        self.save()
    }
    pub fn verify_artifacts(&self) -> Result<()> {
        for (path, hash) in &self.state.artifacts {
            let path = Path::new(path);
            if (!path.starts_with(&self.c.root) && !path.starts_with(&self.c.recovery_directory))
                || digest(&native::public_file(path, 1_048_576).map_err(|_| Error::State)?) != *hash
            {
                return Err(Error::State);
            }
        }
        Ok(())
    }
    pub fn immutable_json(&mut self, path: &Path, value: &Value) -> Result<()> {
        let data = serde_json::to_vec_pretty(value).map_err(|_| Error::State)?;
        native::exact_file(path, &data).map_err(|_| Error::State)?;
        self.artifact(path)
    }
    pub fn bootstrap(&self) -> Result<Value> {
        self.remembered("bootstrap").ok_or(Error::State)
    }
    pub fn trust(&self) -> Result<Vec<String>> {
        Ok(bytes(&[
            "--bootstrap",
            &text(&self.p("Network/Bootstrap.cbor"))?,
            "--bootstrap-digest",
            &string(&self.bootstrap()?, "fingerprint")?,
        ]))
    }
    pub fn root_grant(&self) -> Result<String> {
        string(
            &self.bootstrap()?["genesisGovernance"]["rootGrants"][0]["record"],
            "id",
        )
    }
    pub fn monitor(&self) -> Result<String> {
        string(
            self.state.results.get("clock").ok_or(Error::State)?,
            "publicKey",
        )
    }
    pub fn hrc(&self, args: &[String]) -> Result<Value> {
        invoke(
            &std::env::current_exe().map_err(|_| Error::State)?,
            args,
            self.cancel,
            self.end,
            &self.state.phase,
        )
    }
    pub fn unit_name(&self, purpose: &str) -> String {
        if purpose == "hrc"
            && let Some(service) = self.state.ids.get("application")
        {
            return format!("hrc-managed-home-{service}");
        }
        format!(
            "hrc-host-{}-{purpose}.service",
            &digest(self.c.root.as_os_str().as_encoded_bytes())[..16]
        )
    }
    pub fn unit(&self, purpose: &str, executable: &Path, args: &[String]) -> Result<()> {
        let name = self.unit_name(purpose);
        let active = raw(
            Path::new("/usr/bin/systemctl"),
            &bytes(&["--user", "is-active", &name]),
            self.cancel,
            self.end,
            purpose,
        );
        if active.as_ref().is_ok_and(|v| v == b"active\n") {
            return Ok(());
        }
        let mut command = bytes(&[
            "--user",
            "--collect",
            "--quiet",
            "--unit",
            &name,
            "--property=Type=exec",
            "--property=Restart=no",
            "--property=UMask=0077",
            "--property=LogRateLimitIntervalSec=30s",
            "--property=LogRateLimitBurst=30",
        ]);
        // Podman's native subordinate-ID helpers need their normal privileges; Core confines each workload.
        if purpose == "hrc" || purpose == "client" || purpose == "clock" {
            command.push("--property=NoNewPrivileges=yes".into());
        }
        command.extend(bytes(&["--", &text(executable)?]));
        command.extend(args.iter().cloned());
        raw(
            Path::new("/usr/bin/systemd-run"),
            &command,
            self.cancel,
            self.end,
            purpose,
        )?;
        Ok(())
    }
    pub fn stop_unit(&self, purpose: &str) -> Result<()> {
        raw(
            Path::new("/usr/bin/systemctl"),
            &bytes(&["--user", "stop", &self.unit_name(purpose)]),
            self.cancel,
            self.end,
            purpose,
        )?;
        Ok(())
    }
    pub fn wait(&self, mut probe: impl FnMut() -> Result<()>, seconds: u64) -> Result<()> {
        let end = self.end.min(Instant::now() + Duration::from_secs(seconds));
        loop {
            check(self.cancel, end)?;
            if probe().is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}
/// Read only the bounded public progress field while another operation owns its mutation lock.
pub fn progress(c: &Configuration) -> Result<String> {
    let value = read(&c.root.join("Hosting.json"))?;
    if value["configurationDigest"] != config_digest(c)? {
        return Err(Error::State);
    }
    let phase = string(&value, "phase")?;
    if phase.len() > 128 || phase.chars().any(char::is_control) {
        return Err(Error::State);
    }
    Ok(phase)
}
pub fn apply(c: &Configuration, reviewed_digest: &str, cancel: &AtomicBool) -> Result<Status> {
    let reviewed = preview(c, cancel)?;
    if reviewed.digest != reviewed_digest {
        return Err(Error::PreviewChanged);
    }
    if !reviewed.ready {
        return Err(Error::Prerequisite("complete the host prerequisite checks"));
    }
    let mut host = Host::open(c, cancel, Some(&reviewed))?;
    super::bootstrap::prepare(&mut host)?;
    super::bootstrap::activate(&mut host)?;
    super::services::prepare(&mut host)?;
    super::services::activate(&mut host)?;
    super::clients::create_owner(&mut host)?;
    super::lifecycle::start_host(&mut host)?;
    let observed = super::lifecycle::observe(&mut host)?;
    if !observed.quorum_verified || !observed.client_authenticated {
        return Err(Error::NotReady);
    }
    host.state.completed = true;
    host.phase("Ready")?;
    Ok(Status {
        phase: "Ready".into(),
        ..observed
    })
}
