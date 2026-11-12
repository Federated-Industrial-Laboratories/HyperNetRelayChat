// SPDX-License-Identifier: Apache-2.0
//! Native Ollama chat accepts only locally described models and explicit bounded context.
use super::{ChatMessage, Error, LocalModel, Result, http, text_response};
use serde_json::{Value, json};
use std::{sync::atomic::AtomicBool, time::Instant};

fn local(value: &Value) -> bool {
    ["remote_model", "remote_host"]
        .iter()
        .all(|name| value[*name].is_null() || value[*name].as_str() == Some(""))
}
pub(super) fn generate(
    model: &LocalModel,
    messages: Vec<ChatMessage>,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Option<String>> {
    // Only the model name is disclosed before this check. Ollama also must run with cloud disabled.
    let Some(info) = http::json(
        model,
        "/api/show",
        Some(json!({"model":model.model, "verbose":false})),
        stop,
        deadline,
    )?
    else {
        return Ok(None);
    };
    if !local(&info)
        || info["model_info"]
            .as_object()
            .is_none_or(|info| info.is_empty())
    {
        return Err(Error::ModelUnavailable);
    }
    let Some(value) = http::json(
        model,
        "/api/chat",
        Some(json!({
            "model":model.model, "messages":messages, "stream":false, "think":false,
            "options":{"num_ctx":model.context_tokens, "num_predict":model.output_tokens, "temperature":0.6},
            "keep_alive":"5m"
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
    if local(value) && value["done"] == true && value["done_reason"] == "length" {
        return Err(Error::ModelIncomplete);
    }
    if !local(value) || value["done"] != true || value["done_reason"] != "stop" {
        return Err(Error::ModelResponse);
    }
    text_response(&value["message"])
}
