// SPDX-License-Identifier: Apache-2.0
//! Qualify the external API against two provisioned profiles and a real native Home.
use clap::Parser;
use hrc::{client::Client, integration, messaging, protocol::*};
use serde_json::{Value as Json, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    person: PathBuf,
    #[arg(long)]
    agent: PathBuf,
    #[arg(long)]
    room: RoomId,
    #[arg(long)]
    work: PathBuf,
    #[arg(long, default_value_t = 180)]
    maximum_seconds: u64,
}
struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<integration::Result<()>>>,
}
impl Server {
    fn start(config: &Path) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let config = config.to_owned();
        Self {
            stop,
            worker: Some(thread::spawn(move || {
                integration::serve(&config, false, stopped)
            })),
        }
    }
    fn stop(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "API thread failed")??;
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn request(socket: &Path, key: &Path, method: &str, params: Json, end: Instant) -> Result<Json> {
    loop {
        let response = integration::request(socket, key, method, params.clone());
        match response {
            Ok(v) if v.get("result").is_some() => return Ok(v["result"].clone()),
            Ok(v) if v["error"]["data"]["retryable"] != true => {
                return Err(format!("{method}: {}", v["error"]["message"]).into());
            }
            _ => (),
        }
        if Instant::now() >= end {
            return Err(format!("{method}: deadline").into());
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn main() -> Result<()> {
    let a = Arguments::parse();
    if !(30..=300).contains(&a.maximum_seconds) {
        return Err("maximum-seconds must be 30..300".into());
    }
    let end = Instant::now() + Duration::from_secs(a.maximum_seconds);
    let config = integration::initialise(&a.agent, &a.work)?;
    let key = a.work.join("Client.json");
    let credential = integration::issue(
        &config,
        integration::Scope {
            rooms: vec![a.room],
            initiate: false,
            history: false,
            agent_replies: false,
        },
        &key,
    )?;
    let socket = a.work.join("Api.sock");
    let mut server = Server::start(&config);
    let status = request(&socket, &key, "api.describe", json!({}), end)?;
    assert_eq!(status["apiVersion"], integration::API_VERSION);
    let mut person = Client::open(&a.person)?;
    request(
        &socket,
        &key,
        "events.open",
        json!({"consumer":"qualification","room":a.room}),
        end,
    )?;
    let text = format!("external API {}", Id::random()?);
    let sent = person.send_message(
        a.room,
        &messaging::Send {
            text,
            mentions: vec![],
            parent: None,
            causation: None,
        },
        None,
        false,
    )?;
    assert!(matches!(sent.outcome, Outcome::Committed { .. }));
    let (batch, trigger) = loop {
        let batch = request(
            &socket,
            &key,
            "events.next",
            json!({"consumer":"qualification"}),
            end,
        )?;
        if let Some(event) = batch["events"]
            .as_array()
            .ok_or("events missing")?
            .iter()
            .find(|e| e["operationId"] == serde_json::to_value(sent.operation_id).unwrap())
        {
            assert_eq!(batch["historical"], false);
            break (batch.clone(), event["event"].clone());
        }
        request(
            &socket,
            &key,
            "events.ack",
            json!({"consumer":"qualification","batch":batch["id"]}),
            end,
        )?;
        if Instant::now() >= end {
            return Err("new event missing".into());
        }
        thread::sleep(Duration::from_millis(100));
    };
    let reply = format!("external response {}", Id::random()?);
    let status = request(&socket, &key, "status", json!({}), end)?;
    let parameters = json!({"clientRequestId":status["nextClientRequestId"],"room":a.room,"consumer":"qualification","batch":batch["id"],"trigger":trigger,"text":reply});
    let original = request(&socket, &key, "messages.reply", parameters.clone(), end)?;
    // Simulate loss of the application acknowledgement after publication.
    server.stop()?;
    server = Server::start(&config);
    let retained = request(
        &socket,
        &key,
        "events.next",
        json!({"consumer":"qualification"}),
        end,
    )?;
    assert_eq!(retained, batch);
    let terminal = loop {
        let value = request(&socket, &key, "messages.reply", parameters.clone(), end)?;
        assert_eq!(value["operation"], original["operation"]);
        if value["status"] == "terminal" {
            break value;
        }
        if Instant::now() >= end {
            return Err("reply outcome unresolved".into());
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(terminal["outcome"]["status"], "committed", "{terminal}");
    let mut changed = parameters.clone();
    changed["text"] = json!("different content");
    let conflict = integration::request(&socket, &key, "messages.reply", changed)?;
    assert_eq!(conflict["error"]["message"], "RequestConflict");
    request(
        &socket,
        &key,
        "events.ack",
        json!({"consumer":"qualification","batch":batch["id"]}),
        end,
    )?;
    request(
        &socket,
        &key,
        "events.ack",
        json!({"consumer":"qualification","batch":batch["id"]}),
        end,
    )?;
    request(&socket, &key, "pause", json!({}), end)?;
    let paused = integration::request(
        &socket,
        &key,
        "events.next",
        json!({"consumer":"qualification"}),
    )?;
    assert_eq!(paused["error"]["message"], "IntegrationDenied");
    integration::revoke(&config, credential)?;
    let revoked = integration::request(&socket, &key, "status", json!({}))?;
    assert_eq!(revoked["error"]["message"], "IntegrationDenied");
    server.stop()?;
    let history = person.history_tail(a.room, 32, None)?;
    let effects = history
        .events
        .iter()
        .filter(|e| serde_json::to_value(e.operation_id).unwrap() == terminal["operation"])
        .count();
    assert_eq!(effects, 1, "exactly one independently attributed reply");
    println!(
        "{}",
        json!({"status":"Passed","apiVersion":integration::API_VERSION,"replyEffects":effects,"restartRedelivery":true,"revocation":true})
    );
    Ok(())
}
