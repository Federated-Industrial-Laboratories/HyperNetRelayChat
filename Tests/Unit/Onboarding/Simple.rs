// SPDX-License-Identifier: Apache-2.0
//! Exercise fixed process handoffs, persistent desire, and exact Agent consent binding.
use super::{Error, native, simple, simple_agents};
use hrc::{home::admission as a, protocol::*, service::files};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
struct Fixture {
    root: PathBuf,
    profile: PathBuf,
    binding: simple::Binding,
}
impl Fixture {
    fn new() -> Self {
        // The executable validator intentionally refuses shared /tmp parents.
        let root = std::env::var_os("HRC_SIMPLE_FIXTURE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"))
            .join(format!("simple-check-{}", Id::random().unwrap()));
        files::directory(&root, true).unwrap();
        let profile = root.join("Profile");
        files::directory(&profile, true).unwrap();
        let runtime = root.join("Runtime.json");
        files::create(&runtime, b"{}").unwrap();
        let suite = root.join("Suite");
        files::create(
            &suite,
            br##"#!/usr/bin/python3
import json, pathlib, sys
root=pathlib.Path(__file__).parent
args=sys.argv[1:]
with (root/'Calls.jsonl').open('a') as log: log.write(json.dumps(args)+'\n')
if args[:2]==['join','status']:
    print((root/'Status.json').read_text())
elif args[:2]==['join','desire']:
    state=json.loads((root/'Status.json').read_text())
    state['desiredOnline']='--online' in args
    (root/'Status.json').write_text(json.dumps(state))
    print('{}')
elif args[:3]==['join','agent','prepare']:
    request=json.load(sys.stdin)
    assert request['operator'] == json.loads((root/'Proposal.json').read_text())['operator']
    print((root/'Prepared.json').read_text())
elif args[:3]==['join','agent','pending']:
    print((root/'Pending.json').read_text())
elif args[:2]==['join','pages']:
    location=json.load(sys.stdin)['location']
    assert location.startswith('hypernet://')
    assert location not in args
    print('{"status":"Opened"}')
else: sys.exit(2)
"##,
        )
        .unwrap();
        fs::set_permissions(&suite, fs::Permissions::from_mode(0o700)).unwrap();
        let binding = simple::Binding {
            version: 1,
            name: Some("Example server".into()),
            initial_nickname: Some("Test member".into()),
            directory: root.clone(),
            suite,
            runtime_configuration: runtime,
            page_profile: Some(root.join("Reader.json")),
        };
        files::create_json(&profile.join("SimpleServer.json"), &binding).unwrap();
        files::create_json(&root.join("Status.json"),&json!({"status":"SavedServer","desiredOnline":false,"runtimeReady":true,"runtimeOwned":true,"hrcProfile":profile,"pageProfile":binding.page_profile})).unwrap();
        Self {
            root,
            profile,
            binding,
        }
    }
    fn calls(&self) -> Vec<Vec<String>> {
        fs::read_to_string(self.root.join("Calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
fn saved_server_desire_persists_and_wrong_profile_cannot_change_it() {
    let f = Fixture::new();
    let cancel = AtomicBool::new(false);
    assert!(simple::saved_offline(&f.profile, &cancel).unwrap());
    simple::prepare(&f.binding, &f.profile, false, &cancel, end()).unwrap();
    assert!(!simple::saved_offline(&f.profile, &cancel).unwrap());
    simple::prepare(&f.binding, &f.profile, true, &cancel, end()).unwrap();
    assert!(simple::saved_offline(&f.profile, &cancel).unwrap());
    let count = f
        .calls()
        .iter()
        .filter(|args| args.get(1).is_some_and(|v| v == "desire"))
        .count();
    assert_eq!(count, 2);
    assert_eq!(
        simple::prepare(&f.binding, &f.root.join("Different"), false, &cancel, end()),
        Err(Error::CompanionBinding)
    );
    assert_eq!(
        f.calls()
            .iter()
            .filter(|args| args.get(1).is_some_and(|v| v == "desire"))
            .count(),
        count
    );
    assert!(simple::saved_offline(&f.profile, &cancel).unwrap());
    assert!(f.calls().iter().all(|args| args[1] != "session")); // Reuse existing owner, never stop it.
    let location = format!(
        "hypernet://{}/{}/Docs/{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    );
    simple::pages(&f.binding, Some(&location), &cancel).unwrap();
}
#[test]
fn simple_server_marker_rejects_public_permissions_and_relative_bindings() {
    let f = Fixture::new();
    let marker = f.profile.join("SimpleServer.json");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(simple::load(&f.profile).is_err());
    fs::remove_file(&marker).unwrap();
    let mut binding = f.binding.clone();
    binding.directory = "relative".into();
    files::create_json(&marker, &binding).unwrap();
    assert!(simple::load(&f.profile).is_err());
}
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn proposal() -> (simple_agents::Proposal, a::Prepare) {
    let network = NetworkId {
        network: id(1),
        incarnation: id(2),
    };
    let home = ServiceId {
        network,
        service: id(2),
    };
    let operator = AccountId {
        origin: network,
        local: id(3),
    };
    let room = RoomId { home, local: id(4) };
    let proposal = simple_agents::Proposal {
        operator,
        rooms: vec![room],
        allow_initiate: false,
        allow_agent_replies: false,
        successor: false,
    };
    let request = a::Prepare {
        claim_id: id(5),
        native_principal: id(6),
        identity: a::Identity {
            account: AccountId {
                origin: network,
                local: id(7),
            },
            endpoint: id(8),
            endpoint_key: id(9),
            recovery_key: id(10),
        },
        classification: a::Classification::Agent { operator },
        rooms: vec![room],
        allow_initiate: false,
        allow_agent_replies: false,
        successor: false,
        operator_consent: None,
    };
    (proposal, request)
}
#[test]
fn agent_helper_rejects_scope_class_and_receipt_substitution_and_resumes_exact_pending() {
    let f = Fixture::new();
    let cancel = AtomicBool::new(false);
    let (proposal, request) = proposal();
    files::create_json(&f.root.join("Proposal.json"), &proposal).unwrap();
    let prepared = |request: &a::Prepare| json!({"status":"ConsentRequired","agentDirectory":f.root,"runtimeConfiguration":f.binding.runtime_configuration,"request":request});
    files::create_json(&f.root.join("Prepared.json"), &prepared(&request)).unwrap();
    let pending = simple_agents::prepare(&f.binding, &proposal, &cancel).unwrap();
    let value = ciborium::Value::serialized(&request).unwrap();
    let mut receipt = a::ConsentReceipt {
        claim_id: request.claim_id,
        request_digest: digest(&canonical_encode(&value, CRYPTO_FRAME_BYTES).unwrap()),
        expires_ms: 1000,
        operator_consent: a::Artifact::new(&[1]),
    };
    assert!(pending.matches_consent(&receipt));
    receipt.request_digest = id(11);
    assert!(!pending.matches_consent(&receipt));
    assert!(simple_agents::complete(&f.binding.suite, &pending, &receipt, &cancel).is_err());
    let saved = json!({"agentDirectory":f.root,"runtimeConfiguration":f.binding.runtime_configuration,"request":request});
    files::create_json(
        &f.root.join("Pending.json"),
        &json!({"status":"PendingAgents","agents":[saved]}),
    )
    .unwrap();
    assert_eq!(
        simple_agents::pending(&f.binding, proposal.operator, &cancel).unwrap()[0].request,
        request
    );
    let mut changed = request.clone();
    changed.allow_initiate = true;
    native::replace_file(
        &f.root.join("Prepared.json"),
        &serde_json::to_vec(&prepared(&changed)).unwrap(),
    )
    .unwrap();
    assert!(simple_agents::prepare(&f.binding, &proposal, &cancel).is_err());
    changed = request;
    changed.classification = a::Classification::Person;
    native::replace_file(
        &f.root.join("Prepared.json"),
        &serde_json::to_vec(&prepared(&changed)).unwrap(),
    )
    .unwrap();
    assert!(simple_agents::prepare(&f.binding, &proposal, &cancel).is_err());
}
#[test]
fn stdin_json_drains_full_pipes_limits_output_and_cancels_blocked_input() {
    let python = PathBuf::from("/usr/bin/python3").canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let private = "private-invitation".repeat(3000);
    let response:serde_json::Value=native::input_json(&python,&native::strings(&["-c","import sys,json; sys.stderr.write('x'*60000); sys.stderr.flush(); print(json.dumps({'length':len(json.load(sys.stdin)['location'])}))"]),&json!({"location":private}),&cancel,Some(end())).unwrap();
    assert_eq!(response["length"], private.len());
    let result: std::result::Result<serde_json::Value, _> = native::input_json(
        &python,
        &native::strings(&[
            "-c",
            "import sys; sys.stdout.write('x'*65537); sys.stdout.flush()",
        ]),
        &json!({}),
        &cancel,
        Some(end()),
    );
    assert_eq!(result, Err(Error::OutputLimit));
    let started = Instant::now();
    let result: std::result::Result<serde_json::Value, _> = native::input_json(
        &python,
        &native::strings(&[
            "-c",
            "import time,signal; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)",
        ]),
        &json!({"location":private}),
        &cancel,
        Some(Instant::now() + Duration::from_millis(100)),
    );
    assert_eq!(result, Err(Error::Deadline));
    assert!(started.elapsed() < Duration::from_secs(4));
    let result: std::result::Result<serde_json::Value, _> =
        native::input_json(&python, &[], &json!({}), &AtomicBool::new(true), None);
    assert_eq!(result, Err(Error::Cancelled));
}
