//! Bounded owner-private Unix IPC. Payload bytes use the same deadline-aware I/O.
use super::{Error, Result};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::{
    fmt, fs, io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::Path,
    time::Duration,
};

pub(super) const MAX_FRAME: usize = 16_384;
pub(super) const MAX_PAYLOAD: usize = 65_536;

pub(super) fn boot_ms() -> Result<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_BOOTTIME includes suspend; the output pointer is valid and writable.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } != 0 || t.tv_sec < 0 {
        return Err(Error::Clock);
    }
    (t.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|n| n.checked_add(t.tv_nsec as u64 / 1_000_000))
        .ok_or(Error::Clock)
}

pub(super) fn timeout_ms(timeout: Duration, maximum: u64, minimum: u64) -> Result<u64> {
    let n = u64::try_from(timeout.as_millis()).map_err(|_| Error::InvalidInput)?;
    if !(minimum..=maximum).contains(&n) || timeout != Duration::from_millis(n) {
        return Err(Error::InvalidInput);
    }
    Ok(n)
}

pub(super) fn deadline(timeout: Duration, maximum: u64, minimum: u64) -> Result<u64> {
    boot_ms()?
        .checked_add(timeout_ms(timeout, maximum, minimum)?)
        .ok_or(Error::Clock)
}

pub(super) fn unshifted_boot() -> Result<String> {
    let offsets = fs::read_to_string("/proc/self/timens_offsets").map_err(|_| Error::Clock)?;
    let fields: Vec<_> = offsets.split_whitespace().collect();
    if fields != ["monotonic", "0", "0", "boottime", "0", "0"] {
        return Err(Error::Clock);
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| Error::Clock)?;
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
        return Err(Error::Clock);
    }
    Ok(boot.to_owned())
}

fn private(path: &Path, directory: bool) -> Result<(u64, u64)> {
    let m = fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    // geteuid has no preconditions and does not expose private state.
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.file_type().is_dir()
        } else {
            !m.file_type().is_socket()
        }
    {
        return Err(Error::Ownership);
    }
    Ok((m.dev(), m.ino()))
}

pub(super) fn canonical(path: &Path) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| Error::Unavailable)? != path {
        return Err(Error::Path);
    }
    private(path, true)?;
    Ok(())
}

pub(super) fn connect(directory: &Path, end: u64) -> Result<UnixStream> {
    canonical(directory)?;
    let before_dir = private(directory, true)?;
    let path = directory.join("Control.sock");
    let before_socket = private(&path, false)?;
    let bytes = path.as_os_str().as_bytes();
    // sockaddr_un is plain C storage; zero initialization also terminates its path.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(Error::Path);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (out, byte) in address.sun_path.iter_mut().zip(bytes) {
        *out = *byte as libc::c_char;
    }
    // The descriptor is owned immediately and always closed on failure.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(Error::Unavailable);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let socket = UnixStream::from(fd);
    let len = (mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    // address has a complete initialized pathname and the matching sockaddr length.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            len,
        )
    } != 0
    {
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EINPROGRESS) => wait(&socket, libc::POLLOUT, end)?,
            // A full Unix accept queue must not turn into an unbounded blocking connect.
            Some(libc::EAGAIN) => return Err(Error::Busy),
            _ => return Err(Error::Unavailable),
        }
        if socket
            .take_error()
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Unavailable);
        }
    }
    // SO_PEERCRED is populated by the kernel; both pointers have the exact sizes.
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != mem::size_of::<libc::ucred>()
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err(Error::Ownership);
    }
    canonical(directory)?;
    if private(directory, true)? != before_dir || private(&path, false)? != before_socket {
        return Err(Error::Changed);
    }
    if boot_ms()? >= end {
        return Err(Error::Timeout);
    }
    Ok(socket)
}

pub(super) fn wait(socket: &UnixStream, events: i16, end: u64) -> Result<()> {
    loop {
        let now = boot_ms()?;
        if now >= end {
            return Err(Error::Timeout);
        }
        let mut p = libc::pollfd {
            fd: socket.as_raw_fd(),
            events,
            revents: 0,
        };
        // Slice the wait so a host suspend cannot extend a boot-time deadline.
        let n = unsafe { libc::poll(&mut p, 1, (end - now).min(50) as i32) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Unavailable);
        }
        if boot_ms()? >= end {
            return Err(Error::Timeout);
        }
        if n > 0 {
            if p.revents & libc::POLLNVAL != 0 {
                return Err(Error::Closed);
            }
            // HUP still allows reading bytes already queued before EOF.
            return Ok(());
        }
    }
}

pub(super) fn send(socket: &UnixStream, bytes: &[u8], end: u64) -> Result<()> {
    send_checked(socket, bytes, end, || true)
}

pub(super) fn send_checked(
    socket: &UnixStream,
    mut bytes: &[u8],
    end: u64,
    valid: impl Fn() -> bool,
) -> Result<()> {
    while !bytes.is_empty() {
        if !valid() {
            return Err(Error::NotActive);
        }
        if boot_ms()? >= end {
            return Err(Error::Timeout);
        }
        // MSG_NOSIGNAL prevents a disconnected peer from raising process SIGPIPE.
        let n = unsafe {
            libc::send(
                socket.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n > 0 {
            bytes = &bytes[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(Error::Closed);
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::WouldBlock => wait(socket, libc::POLLOUT, end)?,
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => {
                return Err(Error::Closed);
            }
            _ => return Err(Error::Unavailable),
        }
    }
    if boot_ms()? >= end {
        return Err(Error::Timeout);
    }
    Ok(())
}

pub(super) fn exact(socket: &UnixStream, mut bytes: &mut [u8], end: u64) -> Result<()> {
    while !bytes.is_empty() {
        if boot_ms()? >= end {
            return Err(Error::Timeout);
        }
        // The output slice is valid for precisely its reported length.
        let n = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n > 0 {
            bytes = &mut bytes[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(Error::Closed);
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::WouldBlock => wait(socket, libc::POLLIN, end)?,
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::ConnectionReset => return Err(Error::Closed),
            _ => return Err(Error::Unavailable),
        }
    }
    if boot_ms()? >= end {
        return Err(Error::Timeout);
    }
    Ok(())
}

pub(super) fn request(directory: &Path, value: Value, end: u64) -> Result<(Value, UnixStream)> {
    let body = serde_json::to_vec(&value).map_err(|_| Error::Protocol)?;
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(Error::Frame);
    }
    let socket = connect(directory, end)?;
    send(&socket, &(body.len() as u32).to_be_bytes(), end)?;
    send(&socket, &body, end)?;
    let mut size = [0; 4];
    exact(&socket, &mut size, end)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(Error::Frame);
    }
    let mut body = vec![0; size];
    exact(&socket, &mut body, end)?;
    let value = parse(&body)?;
    if value.get("version").and_then(Value::as_u64) != Some(2) {
        return Err(Error::UnsupportedVersion);
    }
    match value.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok((value, socket)),
        Some(false) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Refusal {
                version: u64,
                ok: bool,
                error: Detail,
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Detail {
                code: String,
                message: String,
            }
            let refusal: Refusal = serde_json::from_value(value).map_err(|_| Error::Protocol)?;
            if refusal.version != 2
                || refusal.ok
                || refusal.error.code.is_empty()
                || refusal.error.code.len() > 64
                || refusal.error.message.len() > MAX_FRAME
            {
                return Err(Error::Protocol);
            }
            Err(match refusal.error.code.as_str() {
                "Capacity" => Error::Capacity,
                "Timeout" => Error::Timeout,
                "Closed" => Error::Closed,
                _ => Error::Refused,
            })
        }
        None => Err(Error::Protocol),
    }
}

/// Reject repeated keys at every nesting level before mapping wire values to types.
pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = Unique::deserialize(&mut decoder)
        .map_err(|_| Error::Protocol)?
        .0;
    decoder.end().map_err(|_| Error::Protocol)?;
    Ok(result)
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<Unique>()? {
                    out.push(v.0);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                    if out.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        decoder.deserialize_any(Strict)
    }
}
