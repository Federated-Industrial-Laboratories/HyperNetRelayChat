// SPDX-License-Identifier: Apache-2.0
//! Provider wire contracts, prompt bounds, local routing and cancellation are observable boundaries.
use super::*;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
};

fn model() -> LocalModel {
    LocalModel {
        curl: std::env::var_os("HRC_TEST_CURL")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/usr/bin/curl".into()),
        endpoint: "127.0.0.1:8080".parse().unwrap(),
        model: "Qwen".into(),
        prefix: "!qwen".into(),
        all_human_messages: false,
        adapter: Adapter::LlamaCpp,
        context_tokens: 4096,
        output_tokens: 512,
        request_seconds: 60,
        reply_characters: 1000,
    }
}
fn message(role: Role, content: &str) -> ChatMessage {
    ChatMessage {
        role,
        content: content.into(),
    }
}
fn conversation() -> Vec<ChatMessage> {
    vec![
        message(Role::System, "Answer from the supplied conversation."),
        message(Role::User, "My project is named Cedar."),
        message(Role::Assistant, "Understood."),
        message(Role::User, "What is my project called?"),
    ]
}

#[test]
fn only_explicit_loopback_models_and_complete_prefixes_are_accepted() {
    let mut config = model();
    for endpoint in ["192.0.2.1:8080", "0.0.0.0:8080", "[::]:8080", "127.0.0.1:0"] {
        config.endpoint = endpoint.parse().unwrap();
        assert!(matches!(config.validate(), Err(Error::Configuration)));
    }
    for endpoint in ["127.0.0.1:8080", "[::1]:8080"] {
        config.endpoint = endpoint.parse().unwrap();
        config.validate().unwrap();
    }
    assert_eq!(config.prompt(" !qwen hello "), Some("hello"));
    for text in ["!qwen", "!qwen ", "!qwenish hello", "hello", "!help"] {
        assert_eq!(config.prompt(text), None);
    }
    config.all_human_messages = true;
    assert_eq!(config.prompt(" hello "), Some("hello"));
    assert_eq!(config.prompt("!other command"), None);
    config.prefix = "!help".into();
    assert!(config.validate().is_err());
    config.prefix = "!qwen".into();
    for name in ["qwen:cloud", "qwen-CLOUD"] {
        config.model = name.into();
        assert!(config.validate().is_err());
    }
    config.model = "Qwen".into();
    config.context_tokens = 2048;
    config.output_tokens = 2048;
    assert!(config.validate().is_err());
}

#[test]
fn conversation_packing_preserves_instructions_and_latest_question() {
    let mut messages = conversation();
    messages[1].content = "Old Unicode context: 🪵 ".repeat(100);
    let fitted = fit_messages(&messages, 256).unwrap();
    assert_eq!(fitted, vec![messages[0].clone(), messages[3].clone()]);
    assert!(fit_messages(&messages, 8).is_err());
    let mut injected = conversation();
    injected[1].role = Role::System;
    assert!(fit_messages(&injected, 4096).is_err());
    let mut too_many = vec![message(Role::User, "x"); MAX_MESSAGES + 1];
    too_many[0].role = Role::System;
    assert!(fit_messages(&too_many, 65536).is_err());
    assert!(
        fit_messages(
            &[
                message(Role::System, "system"),
                message(Role::Assistant, "not a question")
            ],
            4096
        )
        .is_err()
    );
}

#[test]
fn providers_require_complete_bounded_text_and_reject_tools_or_remote_results() {
    let mut value = json!({"choices":[{"finish_reason":"stop", "message":{"role":"assistant","content":"Hello."}}]});
    assert_eq!(llama_cpp::response(&value).unwrap(), "Hello.");
    value["choices"][0]["message"]["content"] = json!("x".repeat(OUTPUT_BYTES + 1));
    assert!(llama_cpp::response(&value).is_err());
    value["choices"][0]["message"]["content"] = json!("\u{1b}[31m");
    assert!(llama_cpp::response(&value).is_err());
    value["choices"][0]["message"]["content"] = json!("Hello.");
    value["choices"][0]["message"]["tool_calls"] = json!([{"name":"send"}]);
    assert!(llama_cpp::response(&value).is_err());
    value["choices"][0]["message"]["tool_calls"] = Value::Null;
    value["choices"][0]["finish_reason"] = json!("length");
    assert!(llama_cpp::response(&value).is_err());
    let mut value =
        json!({"done":true,"done_reason":"stop","message":{"role":"assistant","content":"Hello."}});
    assert_eq!(ollama::response(&value).unwrap(), "Hello.");
    value["remote_host"] = json!("https://provider.invalid");
    assert!(ollama::response(&value).is_err());
    value["remote_host"] = Value::Null;
    value["done"] = json!(false);
    assert!(ollama::response(&value).is_err());
    value["done"] = json!(true);
    value["done_reason"] = json!("length");
    assert!(ollama::response(&value).is_err());
}

fn read_request(stream: &mut TcpStream) -> (String, Value) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0);
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() < INPUT_BYTES + 8192);
        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                let path = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                let body = if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap()
                };
                return (path, body);
            }
        }
    }
}
fn respond(stream: &mut TcpStream, value: &Value) {
    let body = serde_json::to_vec(value).unwrap();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
}
fn server(
    serve: impl FnOnce(TcpListener) + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    (endpoint, thread::spawn(move || serve(listener)))
}

#[test]
fn llama_uses_actual_server_context_and_preserves_multiturn_wire_roles() {
    let captured = Arc::new(Mutex::new(None));
    let saved = captured.clone();
    let (endpoint, worker) = server(move |listener| {
        for path in [
            "/props",
            "/apply-template",
            "/tokenize",
            "/v1/chat/completions",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let (actual, body) = read_request(&mut stream);
            assert_eq!(actual, path);
            let reply = match path {
                "/props" => json!({"default_generation_settings":{"n_ctx":4096}}),
                "/apply-template" => {
                    assert_eq!(body["messages"][1]["content"], "My project is named Cedar.");
                    assert_eq!(body["chat_template_kwargs"]["enable_thinking"], false);
                    json!({"prompt":"Rendered conversation"})
                }
                "/tokenize" => {
                    assert_eq!(body["content"], "Rendered conversation");
                    json!({"tokens":[1,2,3]})
                }
                _ => {
                    *saved.lock().unwrap() = Some(body);
                    json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Cedar."}}]})
                }
            };
            respond(&mut stream, &reply);
        }
    });
    let mut config = model();
    config.endpoint = endpoint;
    assert_eq!(
        config
            .generate(&conversation(), &AtomicBool::new(false))
            .unwrap(),
        Some("Cedar.".into())
    );
    worker.join().unwrap();
    let guard = captured.lock().unwrap();
    let request = guard.as_ref().unwrap();
    assert_eq!(request["messages"][2]["role"], "assistant");
    assert_eq!(
        request["messages"][3]["content"],
        "What is my project called?"
    );
    assert_eq!(request["max_tokens"], 512);
    assert_eq!(request["stream"], false);
}

#[test]
fn llama_trims_history_using_tokenizer_and_refuses_an_unfit_final_question() {
    let (endpoint, worker) = server(move |listener| {
        for (index, path) in [
            "/props",
            "/apply-template",
            "/tokenize",
            "/apply-template",
            "/tokenize",
            "/v1/chat/completions",
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().unwrap();
            let (actual, body) = read_request(&mut stream);
            assert_eq!(actual, path);
            let reply = match path {
                "/props" => json!({"default_generation_settings":{"n_ctx":2048}}),
                "/apply-template" => {
                    assert_eq!(
                        body["messages"].as_array().unwrap().len(),
                        if index == 1 { 4 } else { 2 }
                    );
                    json!({"prompt":"rendered"})
                }
                "/tokenize" if index == 2 => json!({"tokens":vec![1;1800]}),
                "/tokenize" => json!({"tokens":[1,2]}),
                _ => {
                    json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"Ready."}}]})
                }
            };
            respond(&mut stream, &reply);
        }
    });
    let mut config = model();
    config.endpoint = endpoint;
    assert_eq!(
        config
            .generate(&conversation(), &AtomicBool::new(false))
            .unwrap(),
        Some("Ready.".into())
    );
    worker.join().unwrap();
    assert!(
        fit_messages(
            &[
                message(Role::System, "System"),
                message(Role::User, &"x".repeat(INPUT_BYTES))
            ],
            4096
        )
        .is_err()
    );
}

#[test]
fn ollama_uses_native_chat_and_checks_local_metadata_before_disclosing_context() {
    let (endpoint, worker) = server(move |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/show");
        assert_eq!(body, json!({"model":"Qwen","verbose":false}));
        respond(
            &mut stream,
            &json!({"model_info":{"general.architecture":"qwen3"}}),
        );
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/chat");
        assert_eq!(body["messages"][1]["content"], "My project is named Cedar.");
        assert_eq!(body["options"]["num_ctx"], 4096);
        assert_eq!(body["options"]["num_predict"], 512);
        assert_eq!(body["think"], false);
        assert_eq!(body["stream"], false);
        respond(
            &mut stream,
            &json!({"done":true,"done_reason":"stop","message":{"role":"assistant","content":"Cedar."}}),
        );
    });
    let mut config = model();
    config.adapter = Adapter::Ollama;
    config.endpoint = endpoint;
    assert_eq!(
        config
            .generate(&conversation(), &AtomicBool::new(false))
            .unwrap(),
        Some("Cedar.".into())
    );
    worker.join().unwrap();
    let (endpoint, worker) = server(move |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/show");
        assert!(body.get("messages").is_none());
        respond(
            &mut stream,
            &json!({"remote_host":"https://remote.invalid","remote_model":"qwen","model_info":{}}),
        );
    });
    config.endpoint = endpoint;
    assert!(matches!(
        config.generate(&conversation(), &AtomicBool::new(false)),
        Err(Error::ModelUnavailable)
    ));
    worker.join().unwrap();
}

fn request(endpoint: SocketAddr, stop: &AtomicBool, timeout: Duration) -> Result<Option<Vec<u8>>> {
    http::request(
        &model().curl,
        endpoint,
        "/v1/chat/completions",
        Some(b"{}"),
        stop,
        Instant::now() + timeout,
    )
}
#[test]
fn curl_bounds_output_rejects_redirects_and_cancels_under_one_deadline() {
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        respond(&mut stream, &json!({}));
    });
    assert_eq!(
        request(endpoint, &AtomicBool::new(false), Duration::from_secs(2)).unwrap(),
        Some(b"{}".to_vec())
    );
    worker.join().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let (endpoint, worker) = server(move |listener| {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        signal.store(true, Ordering::Release);
        thread::sleep(Duration::from_millis(150));
    });
    let start = Instant::now();
    assert!(
        request(endpoint, &stop, Duration::from_secs(2))
            .unwrap()
            .is_none()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        thread::sleep(Duration::from_millis(200));
    });
    assert!(matches!(
        request(
            endpoint,
            &AtomicBool::new(false),
            Duration::from_millis(100)
        ),
        Err(Error::ModelTimeout)
    ));
    worker.join().unwrap();
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        let _ = stream.write_all(&vec![b'x'; RESPONSE_BYTES + 1]);
    });
    assert!(matches!(
        request(endpoint, &AtomicBool::new(false), Duration::from_secs(2)),
        Err(Error::ModelResponse | Error::ModelUnavailable)
    ));
    worker.join().unwrap();
    let (endpoint, worker) = server(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.1/\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
    });
    assert!(matches!(
        request(endpoint, &AtomicBool::new(false), Duration::from_secs(2)),
        Err(Error::ModelUnavailable)
    ));
    worker.join().unwrap();
}

#[test]
fn configured_limits_preserve_old_defaults_and_refuse_certificate_overrun() {
    let config = model();
    let mut value = serde_json::to_value(&config).unwrap();
    assert!(value.get("request_seconds").is_none());
    assert!(value.get("reply_characters").is_none());
    let restored: LocalModel = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(restored.request_seconds, 60);
    assert_eq!(restored.reply_characters, 1000);
    value["request_seconds"] = json!(241);
    assert!(
        serde_json::from_value::<LocalModel>(value)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut config = model();
    config.context_tokens = 16384;
    config.output_tokens = 4096;
    config.request_seconds = 240;
    config.reply_characters = 2000;
    config.validate().unwrap();
    config.reply_characters = 2001;
    assert!(config.validate().is_err());
}
#[test]
fn truncated_reply_and_oversize_text_have_distinct_recoverable_diagnostics() {
    let value = json!({"choices":[{"finish_reason":"length","message":{"role":"assistant","content":"partial"}}]});
    assert!(matches!(
        llama_cpp::response(&value),
        Err(Error::ModelIncomplete)
    ));
    let value = json!({"done":true,"done_reason":"length","message":{"role":"assistant","content":"partial"}});
    assert!(matches!(
        ollama::response(&value),
        Err(Error::ModelIncomplete)
    ));
    assert!(matches!(
        text_response(&json!({"role":"assistant","content":"a".repeat(2001)})),
        Err(Error::ModelReplyLimit)
    ));
}
