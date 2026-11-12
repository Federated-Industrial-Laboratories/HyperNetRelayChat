// SPDX-License-Identifier: Apache-2.0
//! Rootless fixed-argument native execution with retained mapped-UID operator outputs.
use super::*;
use hrc::service::files;

pub(super) struct Native<'a> {
    pub config: &'a Config,
    pub cancel: &'a AtomicBool,
    pub end: Instant,
}
impl<'a> Native<'a> {
    pub fn new(config: &'a Config, cancel: &'a AtomicBool, end: Instant) -> Self {
        Self {
            config,
            cancel,
            end,
        }
    }
    pub fn raw(&self, executable: &Path, arguments: &[String]) -> Result<Vec<u8>> {
        process::check(self.cancel, self.end).map_err(|_| Error::Cancelled)?;
        process::run(executable, arguments, self.cancel, self.end).map_err(|_| Error::Native)
    }
    pub fn suite(&self, arguments: &[String]) -> Result<Value> {
        serde_json::from_slice(&self.raw(&self.config.suite, arguments)?).map_err(|_| Error::Native)
    }
    fn podman(&self, arguments: &[String]) -> Result<Vec<u8>> {
        self.raw(Path::new("/usr/bin/podman"), arguments)
    }
    pub fn trust(&self) -> Result<Vec<String>> {
        Ok(args(&[
            "--bootstrap",
            &text(&self.config.bootstrap)?,
            "--bootstrap-digest",
            &digest(
                &process::public_file(&self.config.bootstrap, 1_048_576)
                    .map_err(|_| Error::State)?,
            ),
        ]))
    }
    pub fn online(&self) -> Result<Vec<String>> {
        let mut arguments = self.trust()?;
        arguments.extend(args(&[
            "--directory",
            "/Operator/Floor",
            "--clock-witness",
            "/Clock/ClockHealth.cbor",
            "--key",
            "/Operator/Identity.json",
            "--socket",
            "/Control/Control.sock",
        ]));
        Ok(arguments)
    }
    pub fn bootstrap(&self) -> Result<Value> {
        let value = self.suite(&args(&[
            "network",
            "inspect-bootstrap",
            "--bootstrap",
            &text(&self.config.bootstrap)?,
        ]))?;
        value.get("trust").cloned().ok_or(Error::State)
    }
    pub fn prepare(&self) -> Result<()> {
        let root = &self.config.operator_directory;
        // Existing native operator floors are reused in place, never initialized or copied.
        let status = self.podman(&args(&[
            "unshare",
            "/usr/bin/stat",
            "-c",
            "%u:%a",
            &text(root)?,
        ]))?;
        if status != b"1001:700\n" {
            return Err(Error::State);
        }
        self.podman(&args(&[
            "unshare",
            "/usr/bin/test",
            "-d",
            &text(&root.join("Floor"))?,
        ]))?;
        self.podman(&args(&[
            "unshare",
            "/usr/bin/cmp",
            "--",
            &text(&self.config.operator_key)?,
            &text(&root.join("Identity.json"))?,
        ]))?;
        self.podman(&args(&[
            "unshare",
            "/usr/bin/cmp",
            "--",
            &text(&self.config.suite)?,
            &text(&root.join("HyperNetSuite"))?,
        ]))?;
        Ok(())
    }
    fn output_name(path: &Path) -> Result<String> {
        Ok(format!(
            "{}-{}",
            &digest(text(path)?.as_bytes())[..16],
            path.file_name()
                .and_then(|v| v.to_str())
                .ok_or(Error::State)?
        ))
    }
    pub fn recover_output(&self, destination: &Path) -> Result<bool> {
        let source = self
            .config
            .operator_directory
            .join("Output")
            .join(Self::output_name(destination)?);
        if self
            .podman(&args(&["unshare", "/usr/bin/test", "-f", &text(&source)?]))
            .is_err()
        {
            return Ok(false);
        }
        if destination.exists() {
            return Ok(true);
        }
        files::directory(destination.parent().ok_or(Error::State)?, false)
            .map_err(|_| Error::State)?;
        self.podman(&args(&[
            "unshare",
            "/usr/bin/cp",
            "--",
            &text(&source)?,
            &text(destination)?,
        ]))?;
        self.podman(&args(&[
            "unshare",
            "/usr/bin/chown",
            "0:0",
            &text(destination)?,
        ]))?;
        process::public_file(destination, 1_048_576).map_err(|_| Error::State)?;
        Ok(true)
    }
    pub fn operator(&self, arguments: &[String], output: Option<&Path>) -> Result<Value> {
        self.prepare()?;
        let allowed = match arguments.first().map(String::as_str) {
            Some("authority-inspection") => matches!(
                arguments.get(1).map(String::as_str),
                Some("context" | "delegate-grant" | "invite-member" | "revoke-grant")
            ),
            Some("routes") => matches!(
                arguments.get(1).map(String::as_str),
                Some("issue" | "invite")
            ),
            _ => false,
        };
        if !allowed {
            return Err(Error::State);
        }
        let root = &self.config.operator_directory;
        let mut converted = Vec::new();
        for (index, argument) in arguments.iter().enumerate() {
            let path = Path::new(argument);
            if [
                "/Operator/Floor",
                "/Operator/Identity.json",
                "/Clock/ClockHealth.cbor",
                "/Control/Control.sock",
            ]
            .contains(&argument.as_str())
            {
                converted.push(argument.clone());
            } else if index > 0 && arguments[index - 1] == "--output" {
                if output != Some(path) {
                    return Err(Error::State);
                }
                converted.push(format!("/Operator/Output/{}", Self::output_name(path)?));
            } else if path.is_absolute() {
                let bytes = process::public_file(path, 1_048_576).map_err(|_| Error::State)?;
                let name = format!(
                    "{}-{}",
                    digest(&bytes),
                    path.file_name()
                        .and_then(|v| v.to_str())
                        .ok_or(Error::State)?
                );
                let target = root.join("Inputs").join(&name);
                self.podman(&args(&[
                    "unshare",
                    "/usr/bin/cp",
                    "--",
                    argument,
                    &text(&target)?,
                ]))?;
                self.podman(&args(&[
                    "unshare",
                    "/usr/bin/chown",
                    "1001:1001",
                    &text(&target)?,
                ]))?;
                converted.push(format!("/Operator/Inputs/{name}"));
            } else {
                converted.push(argument.clone());
            }
        }
        let clock: Value = serde_json::from_slice(
            &process::public_file(&self.config.clock_metadata, 16384).map_err(|_| Error::State)?,
        )
        .map_err(|_| Error::State)?;
        let monitor = string(&clock, "publicKey")?;
        if !is_id(&monitor) {
            return Err(Error::State);
        }
        converted.extend(args(&[
            "--clock-monitor-key",
            &monitor,
            "--host-kernel-boot",
            &string(&clock, "kernelBoot")?,
        ]));
        let mut command = args(&[
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--userns=nomap",
            "--user=1000:1000",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--pids-limit=64",
            "--memory=268435456",
            "--cpus=1",
            "--volume",
            &format!("{}:/Operator:rw", text(root)?),
            "--volume",
            &format!("{}:/Clock:ro", text(&self.config.clock_directory)?),
            "--volume",
            &format!(
                "{}:/Control:ro",
                text(&self.config.authority_control_directory)?
            ),
            "--entrypoint=/Operator/HyperNetSuite",
            &self.config.image,
        ]);
        command.extend(converted);
        let result: Value =
            serde_json::from_slice(&self.podman(&command)?).map_err(|_| Error::Native)?;
        if let Some(output) = output
            && !self.recover_output(output)?
        {
            return Err(Error::Native);
        }
        Ok(result)
    }
    pub fn home<T>(
        &self,
        work: &Path,
        operation: impl FnOnce(&Path, bool) -> Result<T>,
    ) -> Result<T> {
        state::directory(work)?;
        let config = crate::operations::home::Configuration::load(&self.config.home_config)
            .map_err(|_| Error::State)?;
        let descriptor = hrc::service::Config::load(&config.directory).map_err(|_| Error::State)?;
        if descriptor.descriptor.home.service.as_hex() != self.config.application.service {
            return Err(Error::State);
        }
        let active = crate::operations::home::status(&config, self.cancel)
            .map_err(|_| Error::Native)?
            .active;
        // The running Home owns its store. A failed live request never stops or opens it.
        operation(&config.directory, active)
    }
}
