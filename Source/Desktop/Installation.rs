// SPDX-License-Identifier: Apache-2.0
//! Per-user installation and operator bundle export use fixed native entry points.
use super::{APPLICATION_ID, settings};
use crate::onboarding;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn owned_directory(path: &Path) -> Result<(), &'static str> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(path)
        .map_err(|_| "InstallationDirectoryUnavailable")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "InstallationDirectoryUnavailable")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o002 != 0
    {
        return Err("InstallationDirectoryUnsafe");
    }
    Ok(())
}
fn replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), &'static str> {
    let directory = path.parent().ok_or("InstallationDirectoryUnavailable")?;
    owned_directory(directory)?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1)
    {
        return Err("InstallationDestinationUnsafe");
    }
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).map_err(|_| "InstallationUnavailable")?;
    let temporary = directory.join(format!(".hrc-install-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_: std::io::Error| "InstallationWriteFailed")
}

// Desktop entries have both string escaping and command-line escaping; no shell is used.
fn exec_path(path: &Path) -> Result<String, &'static str> {
    let value = path.to_str().ok_or("UnsupportedInstallationPath")?;
    if value.chars().any(|c| c.is_control() || c == '=') {
        return Err("UnsupportedInstallationPath");
    }
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                quoted.push_str("\\\\");
                quoted.push(character);
            }
            '%' => quoted.push_str("%%"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}
fn desktop_entry(binary: &Path) -> Result<String, &'static str> {
    let executable = exec_path(binary)?;
    Ok(format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=HyperNet Relay Chat\nGenericName=HyperNet Chat\nComment=Conversations on HyperNet\nExec={executable} gui\nIcon={APPLICATION_ID}\nTerminal=false\nCategories=Network;InstantMessaging;\nStartupNotify=true\nStartupWMClass={APPLICATION_ID}\nActions=Setup;Offline;\n\n[Desktop Action Setup]\nName=Profiles and setup\nExec={executable} gui --setup\n\n[Desktop Action Offline]\nName=Open offline\nExec={executable} gui --offline\n"
    ))
}
pub(super) fn is_installed() -> bool {
    settings::user_directory("XDG_DATA_HOME", ".local/share").is_ok_and(|root| {
        root.join("applications")
            .join(format!("{APPLICATION_ID}.desktop"))
            .is_file()
    })
}
pub fn install() -> Result<serde_json::Value, &'static str> {
    let root = settings::user_directory("XDG_DATA_HOME", ".local/share")?;
    let application = root.join("HyperNetRelayChat");
    for directory in [
        &application,
        &application.join("Application"),
        &application.join("Application/Bin"),
    ] {
        owned_directory(directory)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| "InstallationWriteFailed")?;
    }
    let binary = root.join("HyperNetRelayChat/Application/Bin/hrc");
    let desktop = root
        .join("applications")
        .join(format!("{APPLICATION_ID}.desktop"));
    let entry = desktop_entry(&binary)?;
    let source = std::env::current_exe().map_err(|_| "ExecutableUnavailable")?;
    let bytes = fs::read(source).map_err(|_| "ExecutableUnavailable")?;
    if bytes.len() > 512 * 1024 * 1024 || !bytes.starts_with(b"\x7fELF") {
        return Err("InvalidExecutable");
    }
    replace(&binary, &bytes, 0o755)?;
    let icon = root
        .join("icons/hicolor/scalable/apps")
        .join(format!("{APPLICATION_ID}.svg"));
    replace(
        &icon,
        include_bytes!("../../Packaging/HyperNetRelayChat.svg"),
        0o644,
    )?;
    replace(&desktop, entry.as_bytes(), 0o644)?;
    Ok(serde_json::json!({"status":"Installed", "launcher":desktop, "executable":binary}))
}

#[derive(clap::Args)]
pub struct BundleOptions {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    network_invitation: PathBuf,
    #[arg(long)]
    authority_route: PathBuf,
    #[arg(long)]
    application_route: PathBuf,
    #[arg(long)]
    hrc_invitation: PathBuf,
    /// Certified Connect grant: ID:generation:digest.
    #[arg(long)]
    connect_grant: String,
    #[arg(long)]
    renewal_ms: u64,
    /// New file in a private operator export directory.
    #[arg(long)]
    output: PathBuf,
}
pub fn bundle(options: BundleOptions) -> Result<serde_json::Value, &'static str> {
    let (bytes, digest) = onboarding::build_bundle(onboarding::BundleInputs {
        bootstrap: options.bootstrap,
        network_invitation: options.network_invitation,
        authority_route: options.authority_route,
        application_route: options.application_route,
        hrc_invitation: options.hrc_invitation,
        connect_grant: options.connect_grant,
        renewal_ms: options.renewal_ms,
    })
    .map_err(|_| "InvalidSetupBundle")?;
    hrc::service::files::create(&options.output, &bytes).map_err(|_| "BundleExportUnavailable")?;
    Ok(
        serde_json::json!({"status":"BundleExported", "path":options.output, "sha256":digest, "bytes":bytes.len()}),
    )
}

#[cfg(test)]
#[path = "../../Tests/Unit/DesktopInstallation.rs"]
mod tests;
