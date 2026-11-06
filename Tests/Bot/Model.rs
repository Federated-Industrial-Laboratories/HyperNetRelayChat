// SPDX-License-Identifier: Apache-2.0
//! Local inference boundaries reject disclosure, excessive output, and unattended process work.
use super::*;
use std::{net::TcpListener, sync::Arc};

fn model() -> LocalModel {
    LocalModel {
        curl: std::env::var_os("HRC_TEST_CURL")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/usr/bin/curl".into()),
        endpoint: "127.0.0.1:8080".parse().unwrap(),
        model: "Qwen".into(),
        prefix: "!qwen".into(),
        all_human_messages: false,
    }
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
}

#[test]
fn model_output_must_be_one_complete_bounded_text_reply() {
    let mut result = json!({"choices":[{
        "finish_reason":"stop", "message":{"role":"assistant", "content":"Hello."}
    }]});
    let read = |value: &Value| response(&serde_json::to_vec(value).unwrap());
    assert_eq!(read(&result).unwrap(), "Hello.");
    result["choices"][0]["message"]["content"] = Value::String("x".repeat(OUTPUT_BYTES + 1));
    assert!(matches!(read(&result), Err(Error::ModelResponse)));
    result["choices"][0]["message"]["content"] = json!("\u{1b}[31m");
    assert!(read(&result).is_err());
    result["choices"][0]["message"]["content"] = json!("Hello.");
    result["choices"][0]["message"]["tool_calls"] = json!([{"name":"send"}]);
    assert!(read(&result).is_err());
    result["choices"][0]["message"]["tool_calls"] = Value::Null;
    result["choices"][0]["finish_reason"] = json!("length");
    assert!(read(&result).is_err());
    assert!(response(b"not JSON").is_err());
    assert!(response(&vec![b' '; RESPONSE_BYTES + 1]).is_err());
}

fn request(
    endpoint: SocketAddr,
    body: &[u8],
    stop: &AtomicBool,
    timeout: Duration,
) -> Result<Option<Vec<u8>>> {
    super::request(&model().curl, endpoint, body, stop, timeout)
}

fn server(
    serve: impl FnOnce(std::net::TcpStream) + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        while !bytes.ends_with(b"\r\n\r\n{}") {
            let count = stream.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&buffer[..count]);
            assert!(bytes.len() < 4096);
        }
        assert!(bytes.starts_with(b"POST /v1/chat/completions HTTP/1.1\r\n"));
        serve(stream);
    });
    (address, worker)
}

#[test]
fn curl_request_is_bounded_and_cancellation_reaps_the_child() {
    let (endpoint, worker) = server(|mut stream| {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
    });
    assert_eq!(
        request(
            endpoint,
            b"{}",
            &AtomicBool::new(false),
            Duration::from_secs(2)
        )
        .unwrap(),
        Some(b"{}".to_vec())
    );
    worker.join().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let (endpoint, worker) = server(move |_stream| {
        server_stop.store(true, Ordering::Release);
        thread::sleep(Duration::from_millis(150));
    });
    let start = Instant::now();
    assert!(
        request(endpoint, b"{}", &stop, Duration::from_secs(2))
            .unwrap()
            .is_none()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    worker.join().unwrap();

    let (endpoint, worker) = server(|_stream| thread::sleep(Duration::from_millis(200)));
    assert!(matches!(
        request(
            endpoint,
            b"{}",
            &AtomicBool::new(false),
            Duration::from_millis(100)
        ),
        Err(Error::ModelTimeout)
    ));
    worker.join().unwrap();

    let (endpoint, worker) = server(|mut stream| {
        stream.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        let _ = stream.write_all(&vec![b'x'; RESPONSE_BYTES + 1]);
    });
    assert!(matches!(
        request(
            endpoint,
            b"{}",
            &AtomicBool::new(false),
            Duration::from_secs(2)
        ),
        Err(Error::ModelResponse | Error::ModelUnavailable)
    ));
    worker.join().unwrap();
}
