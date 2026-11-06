// SPDX-License-Identifier: Apache-2.0
//! Per-user native package installation reuses the pinned upstream signature and rollback checks.
use super::{Result, failure, native, private_directory, root};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
pub(crate) const PUBLISHER: &str =
    "6529f9e574e73409ec578c9e9a66e683fef6ae885704d22d75538781b4b43b1e";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum Product {
    Core,
    Suite,
}
impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Self::Core => "HyperNet",
            Self::Suite => "HyperNetSuite",
        }
    }
    pub fn version(self) -> &'static str {
        match self {
            Self::Core => "0.10.3",
            Self::Suite => "0.10.2",
        }
    }
    fn contract(self) -> &'static str {
        match self {
            Self::Core => "HyperNet080Authority2",
            Self::Suite => "HyperNet080Client1",
        }
    }
    fn helpers(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Self::Core => (
                include_bytes!("Network/Package/Core/Bundle.py"),
                include_bytes!("Network/Package/Core/PackageTrust.py"),
            ),
            Self::Suite => (
                include_bytes!("Network/Package/Suite/Bundle.py"),
                include_bytes!("Network/Package/Suite/PackageTrust.py"),
            ),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub product: Product,
    pub downloads: PathBuf,
}
impl Configuration {
    fn base(&self) -> String {
        format!(
            "{}-{}-linux-x86_64",
            self.product.name(),
            self.product.version()
        )
    }
    fn file(&self, suffix: &str) -> PathBuf {
        self.downloads.join(format!("{}{suffix}", self.base()))
    }
    pub fn prefix(&self) -> PathBuf {
        root().join("Native").join(format!(
            "{}-{}",
            self.product.name(),
            self.product.version()
        ))
    }
    pub fn executable(&self) -> PathBuf {
        self.prefix().join("Bin").join(self.product.name())
    }
    pub fn publisher(&self) -> PathBuf {
        self.downloads.join("Publisher.pub")
    }
    fn trust(&self) -> PathBuf {
        root()
            .join("Native")
            .join(format!("{}-Trust", self.product.name()))
    }
}
struct Helpers {
    directory: PathBuf,
    python: PathBuf,
    end: Instant,
}
impl Drop for Helpers {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Helpers {
    fn new(product: Product) -> Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "HrcNativePackage-{}",
            hrc::protocol::Id::random().map_err(failure)?
        ));
        native::directory(&directory).map_err(failure)?;
        let value = Self {
            directory,
            python: Path::new("/usr/bin/python3")
                .canonicalize()
                .map_err(|_| "Install the distribution Python 3 package.".to_owned())?,
            end: Instant::now() + Duration::from_secs(180),
        };
        let (bundle, trust) = product.helpers();
        native::exact_file(&value.directory.join("Bundle.py"), bundle).map_err(failure)?;
        native::exact_file(&value.directory.join("PackageTrust.py"), trust).map_err(failure)?;
        Ok(value)
    }
    fn run(&self, args: &[String], cancel: &AtomicBool) -> Result<Value> {
        let mut argv = native::strings(&[
            "-I",
            "-S",
            "-c",
            "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')",
            &native::path(&self.directory).map_err(failure)?,
            &native::path(&self.directory.join("Bundle.py")).map_err(failure)?,
        ]);
        argv.extend_from_slice(args);
        serde_json::from_slice(&native::run(&self.python,&argv,cancel,self.end).map_err(|_|"The signed native package was refused. Check the exact archive, signatures, publisher key, target policy and platform requirements.".to_owned())?).map_err(failure)
    }
}
fn input_digest(config: &Configuration) -> Result<String> {
    let key = native::public_file(&config.publisher(), 8192).map_err(failure)?;
    let fields = std::str::from_utf8(&key)
        .map_err(failure)?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 2
        || fields[0] != "ssh-ed25519"
        || hex::encode(Sha256::digest(
            format!("{} {}\n", fields[0], fields[1]).as_bytes(),
        )) != PUBLISHER
    {
        return Err("The publisher key does not match the pinned HyperNet release key.".into());
    }
    let mut digest = Sha256::new();
    digest.update(serde_json::to_vec(config).map_err(failure)?);
    digest.update(native::path(&config.prefix()).map_err(failure)?.as_bytes());
    digest.update(native::path(&config.trust()).map_err(failure)?.as_bytes());
    digest.update(key);
    for suffix in [".tar", ".tar.sig", ".target.json", ".target.json.sig"] {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(config.file(suffix))
            .map_err(|_| format!("The download folder needs {}{suffix}.", config.base()))?;
        let metadata = file.metadata().map_err(failure)?;
        let maximum = if suffix == ".tar" { 536870912 } else { 32768 };
        if !metadata.is_file() || metadata.len() > maximum {
            return Err("Native package input exceeds its regular-file size limit.".into());
        }
        digest.update(metadata.len().to_le_bytes());
        let mut bytes = [0; 65536];
        let mut size = 0u64;
        loop {
            let count = file.read(&mut bytes).map_err(failure)?;
            if count == 0 {
                break;
            }
            size += count as u64;
            if size > maximum {
                return Err("Native package input grew beyond its limit.".into());
            }
            digest.update(&bytes[..count]);
        }
    }
    Ok(hex::encode(digest.finalize()))
}
fn verification(config: &Configuration, helper: &Helpers, cancel: &AtomicBool) -> Result<Value> {
    let manifest = helper.run(
        &native::strings(&[
            "Verify",
            "--archive",
            &native::path(&config.file(".tar")).map_err(failure)?,
            "--signature",
            &native::path(&config.file(".tar.sig")).map_err(failure)?,
            "--public-key",
            &native::path(&config.publisher()).map_err(failure)?,
        ]),
        cancel,
    )?;
    if manifest["product"] != config.product.name()
        || manifest["version"] != config.product.version()
    {
        return Err("Choose the exact supported Core or Suite release.".into());
    }
    Ok(manifest)
}
pub fn preview(config: &Configuration, cancel: &AtomicBool) -> Result<Value> {
    let digest = input_digest(config)?;
    let helper = Helpers::new(config.product)?;
    let manifest = verification(config, &helper, cancel)?;
    Ok(
        json!({"status":"VerifiedArchive","product":config.product.name(),"version":config.product.version(),"digest":digest,"destination":config.prefix(),"hostRuntime":manifest["metadata"]["hostRuntime"],"systemPackagesChanged":false}),
    )
}
pub fn install(config: &Configuration, digest: &str, cancel: &AtomicBool) -> Result<Value> {
    if input_digest(config)? != digest {
        return Err("The selected package files changed. Review them again.".into());
    }
    let helper = Helpers::new(config.product)?;
    let expected = verification(config, &helper, cancel)?;
    private_directory(&root().join("Native"))?;
    let key = native::path(&config.publisher()).map_err(failure)?;
    let trust = native::path(&config.trust()).map_err(failure)?;
    if !config.trust().exists() {
        helper.run(
            &native::strings(&[
                "TrustInit",
                "--trust-directory",
                &trust,
                "--public-key",
                &key,
                "--root-pin",
                PUBLISHER,
                "--root-generation",
                "1",
                "--version-floor",
                config.product.version(),
                "--state-contract",
                config.product.contract(),
            ]),
            cancel,
        )?;
    }
    if !config.prefix().exists() {
        helper.run(
            &native::strings(&[
                "Install",
                "--archive",
                &native::path(&config.file(".tar")).map_err(failure)?,
                "--signature",
                &native::path(&config.file(".tar.sig")).map_err(failure)?,
                "--public-key",
                &key,
                "--prefix",
                &native::path(&config.prefix()).map_err(failure)?,
                "--trust-directory",
                &trust,
                "--policy",
                &native::path(&config.file(".target.json")).map_err(failure)?,
                "--policy-signature",
                &native::path(&config.file(".target.json.sig")).map_err(failure)?,
            ]),
            cancel,
        )?;
    }
    let actual = helper.run(
        &native::strings(&[
            "VerifyInstalled",
            "--prefix",
            &native::path(&config.prefix()).map_err(failure)?,
            "--public-key",
            &key,
        ]),
        cancel,
    )?;
    if actual != expected {
        return Err("The existing installation is different. It was preserved.".into());
    }
    helper.run(
        &native::strings(&[
            "AdmitInstalled",
            "--prefix",
            &native::path(&config.prefix()).map_err(failure)?,
            "--public-key",
            &key,
            "--trust-directory",
            &trust,
            "--policy",
            &native::path(&config.file(".target.json")).map_err(failure)?,
            "--policy-signature",
            &native::path(&config.file(".target.json.sig")).map_err(failure)?,
        ]),
        cancel,
    )?;
    let retained_key = root().join("Native/Publisher.pub");
    native::exact_file(
        &retained_key,
        &native::public_file(&config.publisher(), 8192).map_err(failure)?,
    )
    .map_err(failure)?;
    Ok(
        json!({"status":"Installed","product":config.product.name(),"version":config.product.version(),"executable":config.executable(),"publisher":retained_key}),
    )
}
pub(crate) fn verify_installed(
    product: Product,
    executable: &Path,
    key: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Value> {
    native::executable(executable).map_err(failure)?;
    let prefix = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("Select a signed native installation.")?;
    if prefix.join("Bin").join(product.name()) != executable {
        return Err("Select the native executable inside its signed installation.".into());
    }
    let data = native::public_file(key, 8192).map_err(failure)?;
    let fields = std::str::from_utf8(&data)
        .map_err(failure)?
        .split_whitespace()
        .collect::<Vec<_>>();
    if fields.len() < 2
        || fields[0] != "ssh-ed25519"
        || hex::encode(Sha256::digest(
            format!("{} {}\n", fields[0], fields[1]).as_bytes(),
        )) != PUBLISHER
    {
        return Err("The publisher key does not match the pinned HyperNet release key.".into());
    }
    let mut helper = Helpers::new(product)?;
    helper.end = end;
    let value = helper.run(
        &native::strings(&[
            "VerifyInstalled",
            "--prefix",
            &native::path(prefix).map_err(failure)?,
            "--public-key",
            &native::path(key).map_err(failure)?,
        ]),
        cancel,
    )?;
    if value["product"] != product.name() || value["version"] != product.version() {
        return Err("The installation differs from the supported native release.".into());
    }
    Ok(value)
}
#[derive(clap::Subcommand)]
pub enum Command {
    Preview {
        #[arg(long, value_enum)]
        product: Product,
        #[arg(long)]
        downloads: PathBuf,
    },
    Install {
        #[arg(long, value_enum)]
        product: Product,
        #[arg(long)]
        downloads: PathBuf,
        #[arg(long)]
        digest: String,
    },
}
pub fn run(command: Command, cancel: &AtomicBool) -> Result<Value> {
    match command {
        Command::Preview { product, downloads } => {
            preview(&Configuration { product, downloads }, cancel)
        }
        Command::Install {
            product,
            downloads,
            digest,
        } => install(&Configuration { product, downloads }, &digest, cancel),
    }
}
