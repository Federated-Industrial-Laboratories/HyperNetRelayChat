// SPDX-License-Identifier: Apache-2.0
//! A bounded local inference request produces text only; model output never becomes an operation.
use super::{Error, Result};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const INPUT_BYTES: usize = 8192;
const OUTPUT_BYTES: usize = 4096;
const RESPONSE_BYTES: usize = 65536;
const DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize)]
pub struct LocalModel {
    /// Absolute path of the locally installed curl executable.
    pub curl: PathBuf,
    pub endpoint: SocketAddr,
    pub model: String,
    pub prefix: String,
    /// Trigger without a prefix; all model modes require exactly one configured room.
    pub all_human_messages: bool,
}
impl LocalModel {
    pub(super) fn validate(&self) -> Result<()> {
        if !self.curl.is_absolute()
            || !self.curl.is_file()
            || !self.endpoint.ip().is_loopback()
            || self.endpoint.port() == 0
            || self.model.is_empty()
            || self.model.len() > 128
            || self.model.chars().any(char::is_control)
            || self.prefix.is_empty()
            || self.prefix.len() > 32
            || !self.prefix.starts_with('!')
            || self.prefix == "!help"
            || self
                .prefix
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub(super) fn prompt<'a>(&self, text: &'a str) -> Option<&'a str> {
        let text = text.trim();
        if let Some(rest) = text.strip_prefix(&self.prefix)
            && rest.chars().next().is_some_and(char::is_whitespace)
            && !rest.trim().is_empty()
        {
            return Some(rest.trim());
        }
        (self.all_human_messages && !text.is_empty() && !text.starts_with('!')).then_some(text)
    }
    pub(super) fn generate(&self, prompt: &str, stop: &AtomicBool) -> Result<Option<String>> {
        self.validate()?;
        if stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        if prompt.len() > INPUT_BYTES || crate::text::message(prompt).is_err() {
            return Err(Error::Configuration);
        }
        let body = serde_json::to_vec(&json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a local chat assistant in HyperNet Relay Chat. Reply to the user's message clearly and concisely, using plain text. You have no tools, cannot perform actions, and receive only this message, not earlier conversation. Do not claim to have performed actions. Keep replies under 1000 characters. Do not include reasoning or thinking blocks."},
                {"role": "user", "content": prompt}
            ],
            "stream": false,
            "max_tokens": 512,
            "temperature": 0.6,
            "chat_template_kwargs": {"enable_thinking": false}
        }))
        .map_err(|_| Error::Configuration)?;
        let bytes = request(&self.curl, self.endpoint, &body, stop, DEADLINE)?;
        bytes.map(|bytes| response(&bytes)).transpose()
    }
}

fn response(bytes: &[u8]) -> Result<String> {
    if bytes.len() > RESPONSE_BYTES {
        return Err(Error::ModelResponse);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::ModelResponse)?;
    let choices = value["choices"].as_array().ok_or(Error::ModelResponse)?;
    if choices.len() != 1 || choices[0]["finish_reason"] != "stop" {
        return Err(Error::ModelResponse);
    }
    let message = &choices[0]["message"];
    if message["role"] != "assistant"
        || !message["function_call"].is_null()
        || (!message["tool_calls"].is_null()
            && message["tool_calls"]
                .as_array()
                .is_none_or(|calls| !calls.is_empty()))
    {
        return Err(Error::ModelResponse);
    }
    let text = message["content"]
        .as_str()
        .ok_or(Error::ModelResponse)?
        .trim();
    if text.len() > OUTPUT_BYTES || crate::text::message(text).is_err() {
        return Err(Error::ModelResponse);
    }
    Ok(text.to_owned())
}

struct Request(Child);
impl Drop for Request {
    fn drop(&mut self) {
        // Also covers cancellation, invalid output and I/O errors, without leaving an orphan.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn nonblocking(fd: &impl AsRawFd) -> Result<()> {
    let fd = fd.as_raw_fd();
    // The descriptor is an owned child pipe and stays live throughout both calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::ModelUnavailable);
    }
    Ok(())
}

fn request(
    curl: &Path,
    endpoint: SocketAddr,
    body: &[u8],
    stop: &AtomicBool,
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    // No inherited curl configuration, proxies, redirects, hostname resolution, or external URL.
    let mut child = Request(
        Command::new(curl)
            .args([
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
                "--max-time",
                "60",
                "--max-filesize",
                "65536",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                "--url",
            ])
            .arg(format!("http://{endpoint}/v1/chat/completions"))
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
    let mut input = Some(input);
    let mut written = 0;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(Error::ModelTimeout);
        }
        if let Some(pipe) = input.as_mut() {
            match pipe.write(&body[written..]) {
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
        // At most 64 KiB per iteration, so a busy writer cannot delay cancellation.
        for _ in 0..16 {
            match output.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => {
                    if bytes.len() + count > RESPONSE_BYTES {
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
                if status.code() == Some(28) {
                    return Err(Error::ModelTimeout);
                }
                return Err(Error::ModelUnavailable);
            }
            if eof {
                return Ok(Some(bytes));
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
#[path = "../../Tests/Bot/Model.rs"]
mod tests;
