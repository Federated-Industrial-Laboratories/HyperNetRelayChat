// SPDX-License-Identifier: Apache-2.0
//! Bootstrap Suite through the existing signed importer, then use its coordinated installer.
use super::{
    Result, failure, native,
    packages::{self, Configuration, Product},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preview {
    pub release: PathBuf,
    pub installation: PathBuf,
    pub digest: String,
    pub core: Value,
    pub suite: Value,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tools {
    pub core: PathBuf,
    pub suite: PathBuf,
}
pub fn directory() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_STATE_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".local/state")))
        .ok_or("The local state directory is unavailable.")?;
    if !root.is_absolute() {
        return Err("Choose an absolute local state directory.".into());
    }
    Ok(root.join("HyperNetSuite/Installation"))
}
pub fn supplied_directory() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let packages = executable.parent()?.parent()?.join("Packages");
    (packages.join("Core").is_dir() && packages.join("Suite").is_dir()).then_some(packages)
}
fn label(product: Product) -> &'static str {
    match product {
        Product::Core => "Core",
        Product::Suite => "Suite",
    }
}
fn prefix(root: &Path, product: Product, archive: &str) -> Result<PathBuf> {
    if archive.len() != 64
        || !archive
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("The retained native archive identity is invalid.".into());
    }
    Ok(root
        .join("Products")
        .join(label(product))
        .join("Installed")
        .join(format!(
            "{}-{}-{archive}",
            product.name(),
            product.version()
        )))
}
fn trust(root: &Path, product: Product) -> PathBuf {
    root.join("Products").join(label(product)).join("Trust")
}
fn archive_hash(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(failure)?;
    let metadata = file.metadata().map_err(failure)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 536870912 {
        return Err("Choose the coordinated release's regular signed package archives.".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer).map_err(failure)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > 536870912 {
            return Err("The native package grew beyond its limit.".into());
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}
fn product_preview(
    release: &Path,
    root: &Path,
    product: Product,
    cancel: &AtomicBool,
) -> Result<Value> {
    let config = Configuration {
        product,
        downloads: release.join(label(product)),
    };
    let archive = config.downloads.join(format!(
        "{}-{}-linux-x86_64.tar",
        product.name(),
        product.version()
    ));
    let destination = prefix(root, product, &archive_hash(&archive)?)?;
    packages::preview_at(&config, &destination, &trust(root, product), cancel)
}
pub fn preview(release: &Path, cancel: &AtomicBool) -> Result<Preview> {
    let release = release.canonicalize().map_err(|_| {
        "Choose the Packages folder supplied with the coordinated release.".to_owned()
    })?;
    let installation = directory()?;
    let core = product_preview(&release, &installation, Product::Core, cancel)?;
    let suite = product_preview(&release, &installation, Product::Suite, cancel)?;
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(
            &json!({"release":release,"installation":installation,"core":core,"suite":suite}),
        )
        .map_err(failure)?,
    ));
    Ok(Preview {
        release,
        installation,
        digest,
        core,
        suite,
    })
}
fn checked_path(value: &Value, name: &str) -> Result<PathBuf> {
    value[name]
        .as_str()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| "Native installation returned an invalid path.".into())
}
fn selected_executable(root: &Path, result: &Value, product: Product) -> Result<PathBuf> {
    let name = match product {
        Product::Core => "core",
        Product::Suite => "suite",
    };
    let archive = result["packages"][name]["archiveSha256"]
        .as_str()
        .ok_or("Native package identity is missing.")?;
    let expected = prefix(root, product, archive)?
        .join("Bin")
        .join(product.name());
    let actual = checked_path(result, &format!("{name}Executable"))?;
    if actual != expected {
        return Err("The native installation returned another package location.".into());
    }
    Ok(actual)
}
fn publisher(root: &Path, result: &Value) -> Result<PathBuf> {
    let target = result["packages"]["suite"]["targetDigest"]
        .as_str()
        .ok_or("The retained native target is missing.")?;
    if target.len() != 64
        || !target
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("The retained native target is invalid.".into());
    }
    Ok(root
        .join("Products/Suite/Targets")
        .join(target)
        .join("Publisher.pub"))
}
fn run(
    suite: &Path,
    operation: &str,
    root: &Path,
    release: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<Value> {
    let mut args = native::strings(&[
        "native-installation",
        operation,
        "--directory",
        &native::path(root).map_err(failure)?,
        "--json",
    ]);
    if let Some(release) = release {
        args.extend(native::strings(&[
            "--release-directory",
            &native::path(release).map_err(failure)?,
        ]));
    }
    let result = native::json(
        suite,
        &args,
        cancel,
        Instant::now() + Duration::from_secs(if release.is_some() { 1800 } else { 60 }),
    )
    .map_err(failure)?;
    if result["format"] != "HyperNetNativeInstallation/1" || result["status"] != "Ready" {
        return Err(
            "The coordinated native installation is incomplete. Retain its state and retry.".into(),
        );
    }
    Ok(result)
}
pub fn inspect(cancel: &AtomicBool) -> Result<Tools> {
    let root = directory()?;
    let retained: Value = super::read_json(&root.join("Installation.json"))?;
    let suite = selected_executable(&root, &retained, Product::Suite)?;
    // The local manifest only locates a candidate. Verify it with the existing
    // pinned publisher before executing even its read-only inspection command.
    packages::verify_installed(
        Product::Suite,
        &suite,
        &publisher(&root, &retained)?,
        cancel,
        Instant::now() + Duration::from_secs(60),
    )?;
    let result = run(&suite, "inspect", &root, None, cancel)?;
    let checked_suite = selected_executable(&root, &result, Product::Suite)?;
    if checked_suite != suite {
        return Err("The installed native selection changed. Verify packages again.".into());
    }
    Ok(Tools {
        core: selected_executable(&root, &result, Product::Core)?,
        suite,
    })
}
fn register_desktop(suite: &Path, cancel: &AtomicBool) -> Result<()> {
    const RETRY: &str = "The native tools remain installed, but desktop link registration did not complete. Retry Install native tools to repair the links without replacing saved identities.";
    let result = native::json(
        suite,
        &native::strings(&["join", "install"]),
        cancel,
        Instant::now() + Duration::from_secs(30),
    )
    .map_err(|_| RETRY.to_owned())?;
    if result["status"] != "DesktopInstalled" {
        return Err(RETRY.into());
    }
    Ok(())
}
pub fn install(review: &Preview, cancel: &AtomicBool) -> Result<Tools> {
    let current = preview(&review.release, cancel)?;
    if current.digest != review.digest || current.installation != review.installation {
        return Err("The selected package files changed. Review them again.".into());
    }
    let suite_prefix = checked_path(&current.suite, "destination")?;
    let config = Configuration {
        product: Product::Suite,
        downloads: current.release.join("Suite"),
    };
    packages::install_at(
        &config,
        current.suite["digest"]
            .as_str()
            .ok_or("The signed Suite review is incomplete.")?,
        &suite_prefix,
        &trust(&current.installation, Product::Suite),
        cancel,
    )?;
    let suite = suite_prefix.join("Bin/HyperNetSuite");
    let result = run(
        &suite,
        "install",
        &current.installation,
        Some(&current.release),
        cancel,
    )?;
    if selected_executable(&current.installation, &result, Product::Suite)? != suite
        || selected_executable(&current.installation, &result, Product::Core)?
            != checked_path(&current.core, "destination")?.join("Bin/HyperNet")
    {
        return Err("The native package result differs from the reviewed selection.".into());
    }
    let tools = inspect(cancel)?;
    // Register only the exact installed Suite after its package inspection succeeds.
    // A desktop failure preserves the admitted packages for the same install retry.
    register_desktop(&tools.suite, cancel)?;
    Ok(tools)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Operations/Bootstrap.rs"]
mod tests;
