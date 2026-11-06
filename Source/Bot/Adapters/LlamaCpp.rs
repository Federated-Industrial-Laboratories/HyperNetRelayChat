// SPDX-License-Identifier: Apache-2.0
//! llama.cpp prompt fitting uses its active context and tokenizer before chat generation.
use super::{ChatMessage, Error, LocalModel, Result, drop_oldest, http, text_response};
use serde_json::{Value, json};
use std::{sync::atomic::AtomicBool, time::Instant};

pub(super) fn generate(
    model: &LocalModel,
    mut messages: Vec<ChatMessage>,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Option<String>> {
    let Some(props) = http::json(model, "/props", None, stop, deadline)? else {
        return Ok(None);
    };
    let available = props["default_generation_settings"]["n_ctx"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(Error::ModelResponse)?;
    let context = available.min(u64::from(model.context_tokens));
    let budget = context
        .checked_sub(u64::from(model.output_tokens) + 128)
        .ok_or(Error::ModelResponse)?;
    loop {
        let Some(rendered) = http::json(
            model,
            "/apply-template",
            Some(
                json!({"messages":messages, "add_generation_prompt":true, "chat_template_kwargs":{"enable_thinking":false}}),
            ),
            stop,
            deadline,
        )?
        else {
            return Ok(None);
        };
        let prompt = rendered["prompt"].as_str().ok_or(Error::ModelResponse)?;
        let Some(tokens) = http::json(
            model,
            "/tokenize",
            Some(json!({"content":prompt, "add_special":false, "parse_special":true})),
            stop,
            deadline,
        )?
        else {
            return Ok(None);
        };
        let tokens = tokens["tokens"].as_array().ok_or(Error::ModelResponse)?;
        if tokens.iter().any(|token| token.as_u64().is_none()) {
            return Err(Error::ModelResponse);
        }
        if tokens.len() as u64 <= budget {
            break;
        }
        if !drop_oldest(&mut messages) {
            return Err(Error::ModelResponse);
        }
    }
    let Some(value) = http::json(
        model,
        "/v1/chat/completions",
        Some(json!({
            "model":model.model, "messages":messages, "stream":false,
            "max_tokens":model.output_tokens, "temperature":0.6,
            "chat_template_kwargs":{"enable_thinking":false}
        })),
        stop,
        deadline,
    )?
    else {
        return Ok(None);
    };
    response(&value).map(Some)
}
pub(super) fn response(value: &Value) -> Result<String> {
    let choices = value["choices"].as_array().ok_or(Error::ModelResponse)?;
    if choices.len() != 1 || choices[0]["finish_reason"] != "stop" {
        return Err(Error::ModelResponse);
    }
    text_response(&choices[0]["message"])
}
