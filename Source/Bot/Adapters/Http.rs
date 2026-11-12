// SPDX-License-Identifier: Apache-2.0
//! Bounded loopback HTTP owns curl cancellation, pipe limits and the shared request deadline.
use super::{Error, INPUT_BYTES, LocalModel, RESPONSE_BYTES, Result};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

pub(super) fn json(
    model: &LocalModel,
    path: &str,
    body: Option<Value>,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Option<Value>> {
    let body = body
        .map(|value| serde_json::to_vec(&value).map_err(|_| Error::ModelResponse))
        .transpose()?;
    request(
        &model.curl,
        model.endpoint,
        path,
        body.as_deref(),
        stop,
        deadline,
    )?
    .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| Error::ModelResponse))
    .transpose()
}
struct Request(Child);
impl Drop for Request {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn nonblocking(fd: &impl AsRawFd) -> Result<()> {
    let fd = fd.as_raw_fd();
    // These descriptors remain owned by the request throughout both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::ModelUnavailable);
    }
    Ok(())
}
pub(super) fn request(
    curl: &Path,
    endpoint: SocketAddr,
    path: &str,
    body: Option<&[u8]>,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Option<Vec<u8>>> {
    if stop.load(Ordering::Acquire) {
        return Ok(None);
    }
    if Instant::now() >= deadline {
        return Err(Error::ModelTimeout);
    }
    if !endpoint.ip().is_loopback()
        || endpoint.port() == 0
        || !matches!(
            path,
            "/props"
                | "/apply-template"
                | "/tokenize"
                | "/v1/chat/completions"
                | "/api/show"
                | "/api/chat"
        )
    {
        return Err(Error::Configuration);
    }
    if body.is_some_and(|v| v.len() > INPUT_BYTES) {
        return Err(Error::ModelResponse);
    }
    let mut command = Command::new(curl);
    command.args([
        "--disable",
        "--silent",
        "--fail",
        "--proxy",
        "",
        "--noproxy",
        "*",
        "--proto",
        "=http",
        "--no-location",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "2",
        "--max-filesize",
        "262144",
        "--header",
        "Content-Type: application/json",
        "--write-out",
        "\n%{http_code}",
    ]);
    command.args([
        "--max-time",
        &format!(
            "{:.3}",
            deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64()
                .max(0.001)
        ),
    ]);
    if body.is_some() {
        command.args(["--data-binary", "@-"]);
    }
    // Endpoints are fixed adapter paths; caller-controlled URLs and redirects cannot escape loopback.
    let mut child = Request(
        command
            .arg("--url")
            .arg(format!("http://{endpoint}{path}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::ModelUnavailable)?,
    );
    let input = child.0.stdin.take().ok_or(Error::ModelUnavailable)?;
    let mut output = child.0.stdout.take().ok_or(Error::ModelUnavailable)?;
    nonblocking(&input)?;
    nonblocking(&output)?;
    let mut input = body.map(|_| input);
    let body = body.unwrap_or_default();
    let mut written = 0;
    let mut bytes = Vec::new();
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(Error::ModelTimeout);
        }
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&body[written..]) {
                Ok(0) if written < body.len() => return Err(Error::ModelUnavailable),
                Ok(count) => written += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Error::ModelUnavailable),
            }
            if written == body.len() {
                input = None;
            }
        }
        let mut buffer = [0u8; 4096];
        let mut eof = false;
        // A busy writer gets at most64KiB before cancellation/deadline is checked again.
        for _ in 0..16 {
            match output.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => {
                    if bytes.len() + count > RESPONSE_BYTES + 4 {
                        return Err(Error::ModelResponse);
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::ModelUnavailable),
            }
        }
        if let Some(status) = child.0.try_wait().map_err(|_| Error::ModelUnavailable)? {
            if !status.success() {
                return Err(if status.code() == Some(28) {
                    Error::ModelTimeout
                } else {
                    Error::ModelUnavailable
                });
            }
            if eof {
                if !bytes.ends_with(b"\n200") {
                    return Err(Error::ModelUnavailable);
                }
                bytes.truncate(bytes.len() - 4);
                return Ok(Some(bytes));
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}
