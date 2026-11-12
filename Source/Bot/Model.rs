// SPDX-License-Identifier: Apache-2.0
//! Local model configuration and bounded conversation packing; adapters produce text only.
#[path = "Adapters/Http.rs"]
mod http;
#[path = "Adapters/LlamaCpp.rs"]
mod llama_cpp;
#[path = "Adapters/Ollama.rs"]
mod ollama;
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

const INPUT_BYTES: usize = 128 * 1024;
const OUTPUT_BYTES: usize = 8192;
const RESPONSE_BYTES: usize = 256 * 1024;
const MAX_MESSAGES: usize = 66;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "camelCase")]
pub enum Adapter {
    #[default]
    LlamaCpp,
    Ollama,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}
fn default_context() -> u32 {
    4096
}
fn default_output() -> u32 {
    512
}

pub fn default_request_seconds() -> u32 {
    60
}
pub fn default_reply_characters() -> u32 {
    1000
}
fn default_request(value: &u32) -> bool {
    *value == default_request_seconds()
}
fn default_characters(value: &u32) -> bool {
    *value == default_reply_characters()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalModel {
    /// Absolute path of the locally installed curl executable.
    pub curl: PathBuf,
    pub endpoint: SocketAddr,
    pub model: String,
    pub prefix: String,
    /// Trigger without a prefix; all model modes require exactly one configured room.
    pub all_human_messages: bool,
    #[serde(default)]
    pub adapter: Adapter,
    #[serde(default = "default_context")]
    pub context_tokens: u32,
    #[serde(default = "default_output")]
    pub output_tokens: u32,
    /// One complete reply attempt, including optional memory compaction, within the 5-minute history certificate.
    #[serde(
        default = "default_request_seconds",
        skip_serializing_if = "default_request"
    )]
    pub request_seconds: u32,
    #[serde(
        default = "default_reply_characters",
        skip_serializing_if = "default_characters"
    )]
    pub reply_characters: u32,
}
impl LocalModel {
    pub fn validate(&self) -> Result<()> {
        if !self.curl.is_absolute()
            || !self.curl.is_file()
            || !self.endpoint.ip().is_loopback()
            || self.endpoint.port() == 0
            || self.model.is_empty()
            || self.model.len() > 128
            || self.model.chars().any(char::is_control)
            || self.model.to_ascii_lowercase().contains(":cloud")
            || self.model.to_ascii_lowercase().ends_with("-cloud")
            || self.prefix.is_empty()
            || self.prefix.len() > 32
            || !self.prefix.starts_with('!')
            || self.prefix == "!help"
            || self
                .prefix
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || !(2048..=131072).contains(&self.context_tokens)
            || !(128..=8192).contains(&self.output_tokens)
            || !(10..=240).contains(&self.request_seconds)
            || !(128..=2000).contains(&self.reply_characters)
            || self.output_tokens.saturating_add(1024) >= self.context_tokens
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Test the configured local backend without disclosing conversation content.
    pub fn probe(&self, stop: &AtomicBool) -> Result<bool> {
        self.probe_for(stop, Duration::from_secs(u64::from(self.request_seconds)))
    }
    /// A synthetic readiness check has no room certificate or conversation content.
    pub fn probe_for(&self, stop: &AtomicBool, timeout: Duration) -> Result<bool> {
        if timeout.is_zero() || timeout > Duration::from_secs(3600) {
            return Err(Error::Configuration);
        }
        self.generate_until(
            &[
                ChatMessage {
                    role: Role::System,
                    content:
                        "This is a local inference availability check. Reply briefly in plain text."
                            .into(),
                },
                ChatMessage {
                    role: Role::User,
                    content: "Reply with Ready.".into(),
                },
            ],
            stop,
            Instant::now() + timeout,
        )
        .map(|reply| reply.is_some())
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
    /// Preliminary content budget. llama.cpp subsequently verifies actual template tokens;
    /// Ollama's byte budget is deliberately conservative and is not a tokenizer count.
    pub(crate) fn input_budget_bytes(&self) -> usize {
        let available = self
            .context_tokens
            .saturating_sub(self.output_tokens)
            .saturating_sub(1024) as usize;
        match self.adapter {
            Adapter::LlamaCpp => available.saturating_mul(4).min(INPUT_BYTES / 2),
            Adapter::Ollama => available.min(INPUT_BYTES / 2),
        }
    }
    #[cfg(test)]
    pub(super) fn generate(
        &self,
        messages: &[ChatMessage],
        stop: &AtomicBool,
    ) -> Result<Option<String>> {
        self.validate()?;
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(None);
        }
        self.generate_until(
            messages,
            stop,
            Instant::now() + Duration::from_secs(u64::from(self.request_seconds)),
        )
    }
    pub(super) fn generate_until(
        &self,
        messages: &[ChatMessage],
        stop: &AtomicBool,
        deadline: Instant,
    ) -> Result<Option<String>> {
        self.validate()?;
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(None);
        }
        if messages.first().is_none_or(|m| m.role != Role::System) {
            return Err(Error::ModelResponse);
        }
        let mut messages = messages.to_vec();
        messages[0].content.push_str(&format!("\nReply in at most {} characters. The chat message limit is 2000 characters and 8192 UTF-8 bytes.", self.reply_characters));
        let messages = fit_messages(&messages, self.input_budget_bytes())?;
        let generated = match self.adapter {
            Adapter::LlamaCpp => llama_cpp::generate(self, messages, stop, deadline),
            Adapter::Ollama => ollama::generate(self, messages, stop, deadline),
        }?;
        if generated.as_ref().is_some_and(|reply| {
            unicode_segmentation::UnicodeSegmentation::graphemes(reply.as_str(), true).count()
                > self.reply_characters as usize
        }) {
            return Err(Error::ModelReplyLimit);
        }
        Ok(generated)
    }
}

fn fit_messages(messages: &[ChatMessage], budget: usize) -> Result<Vec<ChatMessage>> {
    if !(2..=MAX_MESSAGES).contains(&messages.len())
        || messages.first().is_none_or(|m| m.role != Role::System)
        || messages.last().is_none_or(|m| m.role != Role::User)
        || messages[1..].iter().any(|m| m.role == Role::System)
        || messages.iter().any(|m| {
            m.content.is_empty()
                || m.content
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        })
        || messages.iter().map(|m| m.content.len()).sum::<usize>() > INPUT_BYTES
    {
        return Err(Error::ModelResponse);
    }
    let mut fitted = messages.to_vec();
    // Include a per-turn allowance in addition to the provider's fixed template reserve.
    while fitted.iter().map(|m| m.content.len() + 32).sum::<usize>() > budget {
        if !drop_oldest(&mut fitted) {
            return Err(Error::ModelContext);
        }
    }
    Ok(fitted)
}
fn drop_oldest(messages: &mut Vec<ChatMessage>) -> bool {
    if messages.len() <= 2 {
        return false;
    }
    messages.remove(1);
    // Do not leave an orphaned assistant answer as the oldest historical turn.
    while messages.len() > 2 && messages[1].role == Role::Assistant {
        messages.remove(1);
    }
    true
}
fn text_response(message: &Value) -> Result<String> {
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
    if text.len() > OUTPUT_BYTES
        || unicode_segmentation::UnicodeSegmentation::graphemes(text, true).count() > 2000
    {
        return Err(Error::ModelReplyLimit);
    }
    if crate::text::message(text).is_err() {
        return Err(Error::ModelResponse);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
#[path = "../../Tests/Bot/Model.rs"]
mod tests;
