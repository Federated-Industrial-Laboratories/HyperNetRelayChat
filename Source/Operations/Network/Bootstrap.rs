// SPDX-License-Identifier: Apache-2.0
//! Native clock, role identities, accepted governance and four authority replicas.
use super::{Error, Result, engine::*};
use crate::operations::native;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{fs, path::Path};
use zeroize::Zeroizing;

pub(super) fn identity(host: &mut Host<'_>, name: &str, path: &Path) -> Result<String> {
    if !path.exists() {
        host.suite(&bytes(&["keygen", "--output", &text(path)?]))?;
    }
    // A completed native key creation can precede an interrupted journal write. Validate the pair.
    let raw = Zeroizing::new(hrc::service::files::read(path, 8192).map_err(|_| Error::State)?);
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Key {
        public_key: String,
        secret_key: String,
    }
    let mut key: Key = serde_json::from_slice(&raw).map_err(|_| Error::State)?;
    let seed = Zeroizing::new(hex::decode(&key.secret_key).map_err(|_| Error::State)?);
    use zeroize::Zeroize;
    key.secret_key.zeroize();
    let signer = SigningKey::from_bytes(seed.as_slice().try_into().map_err(|_| Error::State)?);
    if hex::encode(signer.verifying_key().to_bytes()) != key.public_key {
        return Err(Error::State);
    }
    host.artifact(path)?;
    host.remember(name, json!({"publicKey":key.public_key}))?;
    Ok(key.public_key)
}
pub(super) fn clock(host: &mut Host<'_>) -> Result<()> {
    host.phase("Clock")?;
    let folder = host.p("Clock");
    if !folder.exists() {
        host.core(&bytes(&[
            "runtime",
            "provision",
            "clock",
            "--directory",
            &text(&folder)?,
            "--export-directory",
            &text(&folder.join("Public"))?,
            "--chronyc",
            &text(&host.c.chronyc)?,
            "--socket",
            &text(&host.c.chrony_socket)?,
        ]))?;
    }
    if !folder.join("ClockSigner.json").exists() {
        host.core(&bytes(&[
            "authority-clock",
            "initialise-export",
            "--directory",
            &text(&folder)?,
        ]))?;
    }
    let key = identity(host, "clock-key", &folder.join("ClockSigner.json"))?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::State)?
        .trim()
        .to_owned();
    host.remember("clock", json!({"publicKey":key,"kernelBoot":boot}))?;
    host.unit(
        "clock",
        &host.c.core,
        &bytes(&["authority-clock", "monitor", "--directory", &text(&folder)?]),
    )?;
    host.wait(
        || {
            let health = raw(
                &host.c.core,
                &bytes(&[
                    "authority-clock",
                    "verify-export",
                    "--observation",
                    &text(&folder.join("Public/ClockHealth.cbor"))?,
                    "--monitor-key",
                    &key,
                    "--kernel-boot",
                    &boot,
                ]),
                host.cancel,
                host.end,
                "Clock verification",
            )?;
            if health == b"ClockHealthy\n" {
                Ok(())
            } else {
                Err(Error::NotReady)
            }
        },
        30,
    )
}
pub(super) fn prepare(host: &mut Host<'_>) -> Result<()> {
    for name in ["Keys", "Peers", "Network", "Services", "Client", "Exchange"] {
        host.dir(name)?;
    }
    crate::operations::private_directory(&host.c.recovery_directory).map_err(|_| Error::State)?;
    clock(host)?;
    host.phase("Identities")?;
    let issuer = host.c.recovery_directory.join("Issuer");
    if !issuer.exists() {
        host.core(&bytes(&[
            "runtime",
            "provision",
            "issuer",
            "--directory",
            &text(&issuer)?,
            "--days",
            &host.c.governance_days.to_string(),
        ]))?;
    }
    let issuer_cert =
        native::public_file(&issuer.join("Authority.pem"), 16384).map_err(|_| Error::State)?;
    let issuer_pin = digest(&issuer_cert);
    host.artifact(&issuer.join("Authority.pem"))?;
    for (name, port) in [
        ("Voter1", host.c.authority_first_port),
        ("Voter2", host.c.authority_first_port + 1),
        ("Voter3", host.c.authority_first_port + 2),
        ("Voter4", host.c.authority_first_port + 3),
        ("Relay", host.c.relay_port),
        ("AuthorityEndpoint", host.c.relay_port),
        ("ApplicationEndpoint", host.c.relay_port),
    ] {
        let folder = host.p(&format!("Keys/{name}"));
        if !folder.exists() {
            host.core(&bytes(&[
                "runtime",
                "provision",
                "identity",
                "--directory",
                &text(&folder)?,
                "--address",
                &host.c.advertised_address.to_string(),
                "--port",
                &port.to_string(),
            ]))?;
        }
        let request = public_read(&folder.join("TransportRequest.json"))?;
        if request["address"] != host.c.advertised_address.to_string() || request["port"] != port {
            return Err(Error::State);
        }
        host.artifact(&folder.join("TransportRequest.json"))?;
        let public = identity(
            host,
            &format!("identity/{name}"),
            &folder.join("Identity.json"),
        )?;
        if request["identity"].as_str() != Some(&public) {
            return Err(Error::State);
        }
        let peer = host.p(&format!("Peers/{name}.json"));
        if !peer.exists() {
            let request_pin = digest(
                &native::public_file(&folder.join("TransportRequest.json"), 16384)
                    .map_err(|_| Error::State)?,
            );
            host.core(&bytes(&[
                "runtime",
                "provision",
                "issue",
                "--directory",
                &text(&issuer)?,
                "--issuer-digest",
                &issuer_pin,
                "--request",
                &text(&folder.join("TransportRequest.json"))?,
                "--request-digest",
                &request_pin,
                "--days",
                "365",
                "--output",
                &text(&peer)?,
            ]))?;
        }
        host.artifact(&peer)?;
        host.remember(&format!("role/{name}"), request)?;
    }
    for name in [
        "Administrator",
        "RelayOperator",
        "AuthorityOperator",
        "ApplicationOperator",
        "ServiceOwner",
        "Receiver",
    ] {
        let path = host.p(&format!("Keys/{name}.json"));
        identity(host, name, &path)?;
    }
    let recovery_path = host.c.recovery_directory.join("Governance.json");
    let recovery = identity(host, "Recovery", &recovery_path)?;
    host.phase("Governance acceptance")?;
    let mut voters = Vec::new();
    let mut transports = serde_json::Map::new();
    for n in 1..=4 {
        let role = host
            .remembered(&format!("role/Voter{n}"))
            .ok_or(Error::State)?;
        let voter = string(&role, "identity")?;
        transports.insert(voter.clone(), role["transport"].clone());
        voters.push(voter);
    }
    voters.sort();
    let relay_id = host.id("relay")?;
    let authority_id = host.id("authority")?;
    host.id("application")?;
    let domain = host.id("domain")?;
    let owner = host.id("recovery-owner")?;
    let until = host.state.created_ms + u64::from(host.c.governance_days) * 86_400_000;
    let spec = json!({"voters":voters,"authorityTransports":transports,"clockMonitors":[host.monitor()?],
        "administrator":host.state.results["Administrator"]["publicKey"],"administratorActions":[0,6,9,10,11,12,13,21,25,26,27,28,29,30],
        "enrolment":"InvitationOnly","publicReading":false,"minimumRoute":"Organisational","publicationModes":["HostReadable","Sealed"],"defaultPublicationMode":"HostReadable",
        "limits":[host.c.resources.connection_bytes,1024,host.c.resources.relay_connections,32],
        "recovery":{"custody":"OwnerSingle","keys":[{"principal":owner,"publicKey":recovery}],"acceptedKeys":[recovery],"immutableShared":false},
        "route":{"relayService":relay_id,"relayOrigin":format!("https://{}:{}/",host.c.advertised_address,host.c.relay_port),"relayTransportKey":host.state.results["role/Relay"]["transport"],"relayDomain":domain,
        "admissionService":authority_id,"admissionOrigin":format!("https://{}:{}/",host.c.advertised_address,host.c.relay_port),"admissionTransportKey":host.state.results["role/AuthorityEndpoint"]["transport"],"admissionDomain":domain,"assurance":"Organisational","notBeforeMs":host.state.created_ms.saturating_sub(60_000),"expiresMs":until}});
    let spec_path = host.p("Network/Governance.json");
    host.immutable_json(&spec_path, &spec)?;
    let draft = host.p("Network/Draft.cbor");
    if !draft.exists() {
        host.suite(&bytes(&[
            "network",
            "draft",
            "--spec",
            &text(&spec_path)?,
            "--output",
            &text(&draft)?,
        ]))?;
    }
    let inspected = host.suite(&bytes(&[
        "network",
        "inspect-bootstrap",
        "--bootstrap",
        &text(&draft)?,
    ]))?;
    host.artifact(&draft)?;
    let acceptance = host.p("Network/Acceptance.cbor");
    if !acceptance.exists() {
        host.suite(&bytes(&[
            "network",
            "recovery-accept",
            "--draft",
            &text(&draft)?,
            "--fingerprint",
            &string(&inspected["trust"], "fingerprint")?,
            "--identity",
            &text(&host.c.recovery_directory.join("Governance.json"))?,
            "--output",
            &text(&acceptance)?,
        ]))?;
    }
    let bootstrap = host.p("Network/Bootstrap.cbor");
    if !bootstrap.exists() {
        host.suite(&bytes(&[
            "network",
            "assemble",
            "--draft",
            &text(&draft)?,
            "--acceptance",
            &text(&acceptance)?,
            "--output",
            &text(&bootstrap)?,
        ]))?;
    }
    let inspected = host.suite(&bytes(&[
        "network",
        "inspect-bootstrap",
        "--bootstrap",
        &text(&bootstrap)?,
    ]))?;
    if inspected["trust"]["draft"] != false || inspected["trust"]["voters"] != spec["voters"] {
        return Err(Error::State);
    }
    host.artifact(&acceptance)?;
    host.artifact(&bootstrap)?;
    host.remember("bootstrap", inspected["trust"].clone())?;
    host.phase("Authority preparation")?;
    for n in 1..=4 {
        let input = host.p(&format!("A{n}Inputs"));
        let folder = host.p(&format!("A{n}"));
        if !input.exists() {
            let mut a = bytes(&[
                "runtime",
                "provision",
                "replica",
                "--directory",
                &text(&input)?,
                "--identity-directory",
                &text(&host.p(&format!("Keys/Voter{n}")))?,
            ]);
            a.extend(host.trust()?);
            a.push("--peer".into());
            for k in 1..=4 {
                a.push(text(&host.p(&format!("Peers/Voter{k}.json")))?);
            }
            a.push("--peer-digest".into());
            for k in 1..=4 {
                a.push(digest(
                    &native::public_file(&host.p(&format!("Peers/Voter{k}.json")), 16384)
                        .map_err(|_| Error::State)?,
                ));
            }
            a.extend(bytes(&[
                "--clock-observation",
                &text(&host.p("Clock/Public/ClockHealth.cbor"))?,
                "--monitor-key",
                &host.monitor()?,
            ]));
            host.core(&a)?;
        }
        if !folder.exists() {
            let mut a = bytes(&[
                "runtime",
                "setup",
                "--directory",
                &text(&folder)?,
                "--image",
                &host.state.image,
            ]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--voter-key",
                &text(&input.join("Identity.json"))?,
                "--replica-config",
                &text(&input.join("ReplicaConfig.json"))?,
                "--peer-certificate",
            ]));
            for k in 1..=4 {
                a.push(text(&input.join(format!("Peer{k}.pem")))?);
            }
            a.extend(bytes(&[
                "--bind",
                &host.c.bind_address.to_string(),
                "--port",
                &(host.c.authority_first_port + n - 1).to_string(),
                "--subnet",
                &format!("10.89.{}.0", u16::from(host.c.subnet_octet) + n - 1),
                "--memory-bytes",
                &host.c.resources.memory_bytes_per_role.to_string(),
                "--pids",
                &host.c.resources.pids_per_role.to_string(),
                "--cpu-quota",
                &host.c.resources.cpu_quota_per_role.to_string(),
                "--state-bytes",
                &host.c.resources.state_bytes_per_role.to_string(),
                "--lifetime-seconds",
                &(u64::from(host.c.lifetime_hours) * 3600).to_string(),
            ]));
            host.core(&a)?;
        }
        host.core(&bytes(&[
            "runtime",
            "preview",
            "--directory",
            &text(&folder)?,
        ]))?;
    }
    Ok(())
}
pub(super) fn activate(host: &mut Host<'_>) -> Result<()> {
    host.phase("Authority activation")?;
    for n in 1..=4 {
        let folder = host.p(&format!("A{n}"));
        let name = format!("a{n}");
        let preview = host.core(&bytes(&[
            "runtime",
            "preview",
            "--directory",
            &text(&folder)?,
        ]))?;
        let consent_name = format!("consent/A{n}");
        if host.remembered(&consent_name).is_none() {
            let op = host.id(&consent_name)?;
            let result = host.core(&bytes(&[
                "runtime",
                "consent",
                "--directory",
                &text(&folder)?,
                "--operation-id",
                &op[..32],
                "--expected-generation",
                &number(&preview, "generation")?.to_string(),
                "--profile-digest",
                &string(&preview, "profileDigest")?,
            ]))?;
            host.remember(&consent_name, result)?;
        }
        host.unit(
            &name,
            &host.c.core,
            &bytes(&["runtime", "serve", "--directory", &text(&folder)?]),
        )?;
        host.wait(
            || {
                host.core(&bytes(&[
                    "runtime",
                    "status",
                    "--directory",
                    &text(&folder)?,
                ]))?;
                Ok(())
            },
            15,
        )?;
        let current = host.core(&bytes(&[
            "runtime",
            "status",
            "--directory",
            &text(&folder)?,
        ]))?;
        if current["running"] != true {
            let op = host.id(&format!("start/A{n}/{}", number(&current, "generation")?))?;
            let floor = current["minimumSignerGeneration"]
                .as_u64()
                .ok_or(Error::State)?
                .max(1);
            host.core(&bytes(&[
                "runtime",
                "start",
                "--directory",
                &text(&folder)?,
                "--operation-id",
                &op[..32],
                "--expected-generation",
                &number(&current, "generation")?.to_string(),
                "--profile-digest",
                &string(&preview, "profileDigest")?,
                "--minimum-signer-generation",
                &floor.to_string(),
            ]))?;
        }
    }
    host.wait(
        || {
            super::services::authority_context(host)?;
            Ok(())
        },
        60,
    )
}
