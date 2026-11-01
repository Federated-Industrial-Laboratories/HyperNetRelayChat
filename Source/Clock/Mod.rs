// SPDX-License-Identifier: Apache-2.0
//! Read-only verification of the pinned HyperNet host clock export.
use crate::protocol::{canonical_decode, canonical_encode};
use ciborium::Value;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub const ERROR_BOUND_MS: u64 = 250;
#[derive(Debug, thiserror::Error)]
#[error("a current pinned HyperNet clock observation is unavailable")]
pub struct Unavailable;
pub type Result<T> = std::result::Result<T, Unavailable>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub observation: PathBuf,
    pub monitor_key: String,
}

/// Conservative UTC bounds, taken at one current boot-clock observation.
#[derive(Clone, Copy, Debug)]
pub struct TimeBounds {
    pub lower_ms: u64,
    pub upper_ms: u64,
    pub boot_ms: u64,
    sample_wall_ms: u64,
    sample_boot_ms: u64,
    valid_until_boot_ms: u64,
    maximum_error_ms: u64,
}
impl TimeBounds {
    #[cfg(test)]
    pub(crate) fn test_now() -> Self {
        let wall = wall_ms().unwrap();
        let boot = boot_ms().unwrap();
        checked_time(wall, boot, boot + 1000, 0, wall, boot).unwrap()
    }
    /// Recheck this original signed observation immediately at an operation boundary.
    pub fn refresh(&self) -> Result<Self> {
        checked_time(
            self.sample_wall_ms,
            self.sample_boot_ms,
            self.valid_until_boot_ms,
            self.maximum_error_ms,
            wall_ms()?,
            boot_ms()?,
        )
    }
    pub fn permits(&self, not_before_ms: u64, expires_ms: u64) -> bool {
        self.lower_ms >= not_before_ms && self.upper_ms < expires_ms
    }
    pub fn after_floor(&self, retained_lower_ms: u64) -> Result<()> {
        if self.lower_ms < retained_lower_ms {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }
}

pub fn boot_ms() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // The output is writable and CLOCK_BOOTTIME includes suspend.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return Err(Unavailable);
    }
    (time.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|n| n.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or(Unavailable)
}
fn wall_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Unavailable)
}
fn host_boot() -> Result<String> {
    let offsets = fs::read_to_string("/proc/self/timens_offsets").map_err(|_| Unavailable)?;
    if offsets.len() > 256
        || offsets.split_whitespace().collect::<Vec<_>>()
            != ["monotonic", "0", "0", "boottime", "0", "0"]
    {
        return Err(Unavailable);
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| Unavailable)?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(Unavailable);
    }
    Ok(boot.to_owned())
}
fn array(value: &Value, size: usize) -> Result<&[Value]> {
    let v = value.as_array().ok_or(Unavailable)?;
    if v.len() != size {
        return Err(Unavailable);
    }
    Ok(v)
}
fn uint(value: &Value) -> Result<u64> {
    value
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(Unavailable)
}
fn bytes(value: &Value) -> Result<&[u8]> {
    value.as_bytes().map(Vec::as_slice).ok_or(Unavailable)
}
fn text(value: &Value) -> Result<&str> {
    value.as_text().ok_or(Unavailable)
}

impl Config {
    /// Never changes the host clock or refreshes an expired observation itself.
    pub fn sample(&self) -> Result<TimeBounds> {
        if !self.observation.is_absolute()
            || self.observation.canonicalize().map_err(|_| Unavailable)? != self.observation
        {
            return Err(Unavailable);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.observation)
            .map_err(|_| Unavailable)?;
        let meta = file.metadata().map_err(|_| Unavailable)?;
        if !meta.is_file() || meta.len() > 4096 || meta.nlink() > 1 {
            return Err(Unavailable);
        }
        let mut content = Vec::new();
        file.take(4097)
            .read_to_end(&mut content)
            .map_err(|_| Unavailable)?;
        let key = crate::protocol::Id::from_hex(&self.monitor_key).map_err(|_| Unavailable)?;
        let boot = host_boot()?;
        verify(&content, *key.as_bytes(), &boot, wall_ms()?, boot_ms()?)
    }
}

fn verify(
    content: &[u8],
    key: [u8; 32],
    host_boot: &str,
    wall: u64,
    boot: u64,
) -> Result<TimeBounds> {
    let value = canonical_decode(content, 4096).map_err(|_| Unavailable)?;
    let envelope = array(&value, 4)?;
    if uint(&envelope[0])? != 0 || uint(&envelope[1])? != 1 {
        return Err(Unavailable);
    }
    let payload = bytes(&envelope[2])?;
    let signatures = array(&envelope[3], 1)?;
    let signature = array(&signatures[0], 2)?;
    if bytes(&signature[0])? != key {
        return Err(Unavailable);
    }
    let signature = Signature::from_slice(bytes(&signature[1])?).map_err(|_| Unavailable)?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| Unavailable)?;
    if verifying.is_weak() || key == [0; 32] {
        return Err(Unavailable);
    }
    // HyperNet TrustWire's published signature domain, length and signer binding.
    let mut message = b"HyperNet/RecordSignature/1\0".to_vec();
    message.extend((payload.len() as u32).to_be_bytes());
    message.extend(payload);
    message.extend(key);
    verifying
        .verify_strict(&message, &signature)
        .map_err(|_| Unavailable)?;
    let value = canonical_decode(payload, 4096).map_err(|_| Unavailable)?;
    if canonical_encode(&value, 4096).map_err(|_| Unavailable)? != payload {
        return Err(Unavailable);
    }
    let fields = array(&value, 8)?;
    if uint(&fields[0])? != 44 || uint(&fields[1])? != 1 || text(&fields[2])? != host_boot {
        return Err(Unavailable);
    }
    let source: IpAddr = text(&fields[7])?.parse().map_err(|_| Unavailable)?;
    if source.is_unspecified() || source.is_loopback() || source.to_string() != text(&fields[7])? {
        return Err(Unavailable);
    }
    let sample_wall = uint(&fields[3])?;
    let sample_boot = uint(&fields[4])?;
    let expiry = uint(&fields[5])?;
    let error = uint(&fields[6])?;
    checked_time(sample_wall, sample_boot, expiry, error, wall, boot)
}
fn checked_time(
    sample_wall: u64,
    sample_boot: u64,
    expiry: u64,
    error: u64,
    wall: u64,
    boot: u64,
) -> Result<TimeBounds> {
    let elapsed = boot.checked_sub(sample_boot).ok_or(Unavailable)?;
    let predicted = sample_wall.checked_add(elapsed).ok_or(Unavailable)?;
    if sample_boot.checked_add(1000) != Some(expiry)
        || boot >= expiry
        || error
            .checked_add(wall.abs_diff(predicted))
            .is_none_or(|e| e > ERROR_BOUND_MS)
    {
        return Err(Unavailable);
    }
    Ok(TimeBounds {
        lower_ms: wall.checked_sub(ERROR_BOUND_MS).ok_or(Unavailable)?,
        upper_ms: wall.checked_add(ERROR_BOUND_MS).ok_or(Unavailable)?,
        boot_ms: boot,
        sample_wall_ms: sample_wall,
        sample_boot_ms: sample_boot,
        valid_until_boot_ms: expiry,
        maximum_error_ms: error,
    })
}

#[cfg(test)]
#[path = "../../Tests/Clock/Clock.rs"]
mod tests;
