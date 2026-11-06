// SPDX-License-Identifier: Apache-2.0
//! Fixed mapped-UID operator calls and separately consented relay/application services.
use super::{Error, Result, engine::*};
use crate::operations::native;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const PODMAN: &str = "/usr/bin/podman";
pub(super) fn online(host: &Host<'_>, who: &str) -> Result<Vec<String>> {
    let mut a = host.trust()?;
    a.extend(bytes(&[
        "--directory",
        &text(&host.p(&format!("{who}Floor")))?,
        "--clock-witness",
        &text(&host.p("Clock/Public/ClockHealth.cbor"))?,
        "--key",
        &text(&host.p(&format!("Keys/{who}.json")))?,
        "--socket",
        &text(&host.p("A1/Launch/State/Control/Control.sock"))?,
    ]));
    Ok(a)
}
fn podman(host: &Host<'_>, a: &[String]) -> Result<Vec<u8>> {
    raw(
        Path::new(PODMAN),
        a,
        host.cancel,
        host.end,
        &host.state.phase,
    )
}
pub(super) fn operator(host: &Host<'_>, who: &str, arguments: &[String]) -> Result<Value> {
    if !["Administrator", "ServiceOwner"].contains(&who) {
        return Err(Error::State);
    }
    let allowed = match arguments.first().map(String::as_str) {
        Some("authority-inspection") => matches!(
            arguments.get(1).map(String::as_str),
            Some(
                "initialise"
                    | "context"
                    | "delegate-grant"
                    | "invite-member"
                    | "admit-member"
                    | "deployments"
            )
        ),
        Some("routes") => matches!(
            arguments.get(1).map(String::as_str),
            Some("register" | "issue" | "invite")
        ),
        Some("streams") => matches!(
            arguments.get(1).map(String::as_str),
            Some("register" | "lookup")
        ),
        _ => false,
    };
    if !allowed {
        return Err(Error::State);
    }
    let root = host.p(&format!("Op{who}"));
    if !root.exists() {
        native::directory(&root).map_err(|_| Error::State)?;
        for child in ["Inputs", "Output"] {
            native::directory(&root.join(child)).map_err(|_| Error::State)?;
        }
        let key = hrc::service::files::read(&host.p(&format!("Keys/{who}.json")), 8192)
            .map_err(|_| Error::State)?;
        let key = zeroize::Zeroizing::new(key);
        native::exact_file(&root.join("Identity.json"), &key).map_err(|_| Error::State)?;
        podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/cp",
                "--",
                &text(&host.c.suite)?,
                &text(&root.join("HyperNetSuite"))?,
            ]),
        )?;
        podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/chmod",
                "0700",
                &text(&root.join("HyperNetSuite"))?,
            ]),
        )?;
        podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/chown",
                "-R",
                "1001:1001",
                &text(&root)?,
            ]),
        )?;
    }
    let owner = podman(
        host,
        &bytes(&["unshare", "/usr/bin/stat", "-c", "%u:%a", &text(&root)?]),
    )?;
    if owner != b"1001:700\n" {
        return Err(Error::State);
    }
    podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/cmp",
            "--",
            &text(&host.c.suite)?,
            &text(&root.join("HyperNetSuite"))?,
        ]),
    )?;
    podman(
        host,
        &bytes(&[
            "unshare",
            "/usr/bin/cmp",
            "--",
            &text(&host.p(&format!("Keys/{who}.json")))?,
            &text(&root.join("Identity.json"))?,
        ]),
    )?;
    let mut converted = Vec::new();
    let mut output: Option<(PathBuf, String)> = None;
    let mut offers: Option<PathBuf> = None;
    for (index, arg) in arguments.iter().enumerate() {
        if arg == &text(&host.p(&format!("{who}Floor")))? {
            converted.push("/Operator/Floor".into());
        } else if arg == &text(&host.p(&format!("Keys/{who}.json")))? {
            converted.push("/Operator/Identity.json".into());
        } else if arg == &text(&host.p("Clock/Public/ClockHealth.cbor"))? {
            converted.push("/Clock/ClockHealth.cbor".into());
        } else if arg == &text(&host.p("A1/Launch/State/Control/Control.sock"))? {
            converted.push("/Control/Control.sock".into());
        } else if index > 0 && arguments[index - 1] == "--offers-directory" {
            let path = PathBuf::from(arg);
            if !path.starts_with(&host.c.root)
                || path.file_name().and_then(|v| v.to_str()) != Some("OperationalOffers")
            {
                return Err(Error::State);
            }
            {
                use std::os::unix::fs::MetadataExt;
                let m = std::fs::symlink_metadata(&path).map_err(|_| Error::State)?;
                if !m.is_dir()
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.mode() & 0o022 != 0
                    || path.canonicalize().map_err(|_| Error::State)? != path
                {
                    return Err(Error::State);
                }
            }
            converted.push("/Offers".into());
            offers = Some(path);
        } else if index > 0
            && (arguments[index - 1] == "--output"
                || (arguments[index - 1] == "--receipt"
                    && arguments.iter().any(|a| a == "admit-member")))
        {
            let path = PathBuf::from(arg);
            if !path.starts_with(&host.c.root) {
                return Err(Error::State);
            }
            let name = format!(
                "{}-{}",
                &digest(arg.as_bytes())[..16],
                path.file_name()
                    .and_then(|v| v.to_str())
                    .ok_or(Error::State)?
            );
            converted.push(format!("/Operator/Output/{name}"));
            output = Some((path, name));
        } else if Path::new(arg).is_absolute() {
            let path = Path::new(arg);
            if !path.starts_with(&host.c.root) {
                return Err(Error::State);
            }
            let data = native::public_file(path, 1_048_576).map_err(|_| Error::State)?;
            let name = format!(
                "{}-{}",
                digest(&data),
                path.file_name()
                    .and_then(|v| v.to_str())
                    .ok_or(Error::State)?
            );
            let target = root.join("Inputs").join(&name);
            podman(
                host,
                &bytes(&["unshare", "/usr/bin/cp", "--", arg, &text(&target)?]),
            )?;
            podman(
                host,
                &bytes(&["unshare", "/usr/bin/chown", "1001:1001", &text(&target)?]),
            )?;
            converted.push(format!("/Operator/Inputs/{name}"));
        } else {
            converted.push(arg.clone());
        }
    }
    if converted.iter().any(|v| v == "--clock-witness") {
        converted.extend(bytes(&[
            "--clock-monitor-key",
            &host.monitor()?,
            "--host-kernel-boot",
            &string(&host.state.results["clock"], "kernelBoot")?,
        ]));
    }
    if let Some((destination, name)) = &output {
        let source = root.join("Output").join(name);
        if !destination.exists()
            && podman(
                host,
                &bytes(&["unshare", "/usr/bin/test", "-f", &text(&source)?]),
            )
            .is_ok()
        {
            podman(
                host,
                &bytes(&[
                    "unshare",
                    "/usr/bin/cp",
                    "--",
                    &text(&source)?,
                    &text(destination)?,
                ]),
            )?;
            podman(
                host,
                &bytes(&["unshare", "/usr/bin/chown", "0:0", &text(destination)?]),
            )?;
            // The next native consumer checks the exact signed output, including interrupted exports.
            return Ok(json!({"status":"RecoveredNativeOutput"}));
        }
    }
    let mut command = bytes(&[
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--userns=nomap",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pids-limit=64",
        "--memory=268435456",
        "--cpus=1",
        "--volume",
        &format!("{}:/Operator:rw", text(&root)?),
        "--volume",
        &format!("{}:/Clock:ro", text(&host.p("Clock/Public"))?),
        "--volume",
        &format!("{}:/Control:ro", text(&host.p("A1/Launch/State/Control"))?),
    ]);
    if let Some(path) = offers {
        command.extend(bytes(&[
            "--volume",
            &format!("{}:/Offers:ro", text(&path)?),
        ]));
    }
    command.extend(bytes(&[
        "--entrypoint=/Operator/HyperNetSuite",
        &host.state.image,
    ]));
    command.extend(converted);
    let result = invoke(
        Path::new(PODMAN),
        &command,
        host.cancel,
        host.end,
        &host.state.phase,
    )?;
    if let Some((destination, name)) = output {
        // Export only the named result of this fixed native command. No directory recursion or wildcard is accepted.
        if destination.exists() {
            return Err(Error::State);
        }
        podman(
            host,
            &bytes(&[
                "unshare",
                "/usr/bin/cp",
                "--",
                &text(&root.join("Output").join(name))?,
                &text(&destination)?,
            ]),
        )?;
        podman(
            host,
            &bytes(&["unshare", "/usr/bin/chown", "0:0", &text(&destination)?]),
        )?;
    }
    Ok(result)
}
pub(super) fn initialise(host: &Host<'_>, who: &str) -> Result<()> {
    let directory = host.p(&format!("Op{who}/Floor"));
    let exists = podman(
        host,
        &bytes(&["unshare", "/usr/bin/test", "-d", &text(&directory)?]),
    )
    .is_ok();
    if !exists {
        let mut a = bytes(&[
            "authority-inspection",
            "initialise",
            "--requester",
            &string(&host.state.results[who], "publicKey")?,
        ]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--directory",
            &text(&host.p(&format!("{who}Floor")))?,
            "--clock-witness",
            &text(&host.p("Clock/Public/ClockHealth.cbor"))?,
        ]));
        operator(host, who, &a)?;
    }
    Ok(())
}
pub(super) fn authority_context(host: &Host<'_>) -> Result<Value> {
    initialise(host, "Administrator")?;
    let mut a = bytes(&["authority-inspection", "context"]);
    a.extend(online(host, "Administrator")?);
    a.extend(bytes(&["--grant", &host.root_grant()?]));
    operator(host, "Administrator", &a)
}
fn raw_id(s: &str) -> Result<Vec<u8>> {
    let v = hex::decode(s).map_err(|_| Error::State)?;
    if v.len() != 32 {
        return Err(Error::State);
    }
    Ok(v)
}
fn der(host: &Host<'_>, pem: &Path) -> Result<Vec<u8>> {
    raw(
        Path::new("/usr/bin/openssl"),
        &bytes(&["x509", "-in", &text(pem)?, "-outform", "DER"]),
        host.cancel,
        host.end,
        "certificate conversion",
    )
}
pub(super) fn roles() -> [(&'static str, &'static str, &'static str, &'static str); 3] {
    [
        ("Relay", "RelayOperator", "relay", "relay"),
        (
            "AuthorityEndpoint",
            "AuthorityOperator",
            "authority",
            "authority",
        ),
        (
            "ApplicationEndpoint",
            "ApplicationOperator",
            "application",
            "application",
        ),
    ]
}
pub(super) fn active_directory(host: &Host<'_>, name: &str) -> Result<PathBuf> {
    match host.remembered(&format!("active-service/{name}")) {
        Some(value) => {
            let path = PathBuf::from(value.as_str().ok_or(Error::State)?);
            if !path.starts_with(host.p("Successor")) {
                return Err(Error::State);
            }
            Ok(path)
        }
        None => Ok(host.p(&format!("Services/{name}"))),
    }
}
pub(super) fn author_route(
    host: &Host<'_>,
    role: (&str, &str, &str, &str),
    manifest: &Path,
    profile: &str,
    output: &Path,
) -> Result<()> {
    let (name, operator_name, id_name, protocol) = role;
    let mut a = bytes(&["routes", "profile"]);
    a.extend(host.trust()?);
    a.extend(bytes(&[
        "--manifest",
        &text(manifest)?,
        "--profile-digest",
        profile,
        "--key",
        &text(&host.p(&format!("Keys/{operator_name}.json")))?,
        "--service",
        &host.state.ids[id_name],
        "--endpoint",
        &host.state.ids[&format!("endpoint/{name}")],
        "--domain",
        &host.state.ids["domain"],
        "--mode",
        if name == "Relay" { "relay" } else { "attached" },
        "--protocol",
        protocol,
        "--server-name",
        &host.c.advertised_address.to_string(),
        "--certificate-authority",
        &text(&host.p(&format!("Services/{name}/Inputs/CertificateAuthority.pem")))?,
        "--assurance",
        "Organisational",
        "--maximum-bytes",
        &host.c.resources.connection_bytes.to_string(),
        "--maximum-duration-ms",
        &(host.c.resources.connection_seconds * 1000).to_string(),
        "--maximum-idle-ms",
        "30000",
        "--maximum-connections",
        &if name == "Relay" {
            host.c.resources.relay_connections
        } else {
            host.c.resources.endpoint_connections
        }
        .to_string(),
    ]));
    if name != "Relay" {
        a.extend(bytes(&["--relay", &host.state.ids["relay"]]));
    }
    a.extend(bytes(&["--output", &text(output)?]));
    host.suite(&a)?;
    Ok(())
}
pub(super) fn prepare(host: &mut Host<'_>) -> Result<()> {
    host.phase("Route deployment review")?;
    let bootstrap = host.bootstrap()?;
    for (name, operator_name, id_name, protocol) in roles() {
        let folder = host.dir(&format!("Services/{name}"))?;
        let inputs = host.dir(&format!("Services/{name}/Inputs"))?;
        let peer = public_read(&host.p(&format!("Peers/{name}.json")))?;
        let role = host
            .remembered(&format!("role/{name}"))
            .ok_or(Error::State)?;
        native::exact_file(
            &inputs.join("Certificate.pem"),
            string(&peer, "certificatePem")?.as_bytes(),
        )
        .map_err(|_| Error::State)?;
        native::exact_file(
            &inputs.join("CertificateAuthority.pem"),
            string(&peer, "authorityPem")?.as_bytes(),
        )
        .map_err(|_| Error::State)?;
        for file in ["Service.key", "Transport.key"] {
            let data = zeroize::Zeroizing::new(
                hrc::service::files::read(&host.p(&format!("Keys/{name}/{file}")), 16384)
                    .map_err(|_| Error::State)?,
            );
            native::exact_file(&inputs.join(file), &data).map_err(|_| Error::State)?;
        }
        native::exact_file(
            &inputs.join("Bootstrap.cbor"),
            &native::public_file(&host.p("Network/Bootstrap.cbor"), 1_048_576)
                .map_err(|_| Error::State)?,
        )
        .map_err(|_| Error::State)?;
        let endpoint = host.id(&format!("endpoint/{name}"))?;
        let volume = host.id(&format!("volume/{name}"))?;
        let host_id = host.id(&format!("host/{name}"))?;
        let deployment = host.id(&format!("deployment/{name}"))?;
        let mut endpoints = vec![
            json!({"endpointId":raw_id(&endpoint)?,"serviceKey":raw_id(&string(&role,"identity")?)?,"address":host.c.advertised_address,"port":host.c.relay_port,"transportKey":raw_id(&string(&role,"transport")?)?,"leafDer":der(host,&inputs.join("Certificate.pem"))?}),
        ];
        let mut outbound: Vec<Vec<u8>> = Vec::new();
        if name != "Relay" {
            let id = host.id(&format!("outbound/{name}"))?;
            outbound.push(raw_id(&id)?);
            let relay = host.remembered("role/Relay").ok_or(Error::State)?;
            endpoints.push(json!({"endpointId":raw_id(&id)?,"serviceKey":raw_id(&string(&relay,"identity")?)?,"address":host.c.advertised_address,"port":host.c.relay_port,"transportKey":raw_id(&string(&relay,"transport")?)?,"leafDer":der(host,&host.p("Services/Relay/Inputs/Certificate.pem"))?}));
        }
        endpoints.sort_by_key(|v| {
            v["endpointId"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
                .unwrap_or_default()
        });
        let manifest = json!({"generation":1,"previousProfile":null,"previousConsent":null,"network":raw_id(&string(&bootstrap,"network")?)?,"incarnation":raw_id(&string(&bootstrap,"incarnation")?)?,"deployment":raw_id(&deployment)?,"host":raw_id(&host_id)?,"operator":raw_id(&string(&host.state.results[operator_name],"publicKey")?)?,"bootstrapDigest":raw_id(&host.bootstrap_file_digest()?)?,"softwareDigest":raw_id(&digest(&native::public_file(&host.c.core,268_435_456).map_err(|_|Error::Package)?))?,"validity":[host.state.created_ms,host.state.expires_ms],"sessionMode":0,
            "roles":[{"role":5,"serviceKey":raw_id(&string(&role,"identity")?)?,"imageDigest":raw_id(host.state.image.strip_prefix("sha256:").ok_or(Error::State)?)?,"memoryBytes":host.c.resources.memory_bytes_per_role,"pids":host.c.resources.pids_per_role,"cpuQuota":host.c.resources.cpu_quota_per_role,"cpuPeriod":100000,"stateAdmissionBytes":host.c.resources.state_bytes_per_role,"bindEndpointIds":[raw_id(&endpoint)?],"outboundEndpointIds":outbound,"volumeIds":[raw_id(&volume)?]}],
            "volumes":[{"volumeId":raw_id(&volume)?,"readOnly":false,"storageAdmissionBytes":host.c.resources.state_bytes_per_role}],"endpoints":endpoints,"clock":{"monitorKey":raw_id(&host.monitor()?)?,"kernelBoot":host.state.results["clock"]["kernelBoot"],"witnessFileName":"ClockHealth.cbor","maximumErrorMs":250,"maximumObservationAgeMs":1000},"placement":{"hosts":[raw_id(&host_id)?],"volumes":[raw_id(&volume)?],"backups":[],"copies":1},"limits":[host.c.resources.connection_bytes,1024,if name=="Relay"{host.c.resources.relay_connections}else{host.c.resources.endpoint_connections},32],"consentPolicy":{"allowOpaque":true,"reviewerRoots":[]},"authorityConfig":null});
        host.immutable_json(&folder.join("Manifest.json"), &manifest)?;
        let prepared_key = format!("manifest/{name}");
        let prepared = if let Some(v) = host.remembered(&prepared_key) {
            v
        } else {
            let original = inputs.join("Manifest.cbor");
            let target = if original.exists() {
                inputs.join(format!(".manifest-{}.cbor", random()?))
            } else {
                original.clone()
            };
            let mut a = bytes(&["authority-inspection", "deployments", "prepare"]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--manifest-json",
                &text(&folder.join("Manifest.json"))?,
                "--output",
                &text(&target)?,
            ]));
            let result = host.suite(&a)?;
            if target != original {
                let old = native::public_file(&original, 65536).map_err(|_| Error::State)?;
                let new = native::public_file(&target, 65536).map_err(|_| Error::State)?;
                if old != new {
                    return Err(Error::State);
                }
                std::fs::remove_file(&target).map_err(|_| Error::State)?;
            }
            host.remember(&prepared_key, result)?
        };
        let profile = string(&prepared, "profileDigest")?;
        let consent = folder.join("Consent.cbor");
        if !consent.exists() {
            let mut a = bytes(&["authority-inspection", "deployments", "consent"]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--manifest",
                &text(&inputs.join("Manifest.cbor"))?,
                "--profile-digest",
                &profile,
                "--key",
                &text(&host.p(&format!("Keys/{operator_name}.json")))?,
                "--output",
                &text(&consent)?,
            ]));
            host.suite(&a)?;
        }
        let expiry = (host.state.created_ms + 86_400_000).min(host.state.expires_ms);
        for (class, flag, key) in [
            (
                "service",
                "--key",
                host.p(&format!("Keys/{name}/Identity.json")),
            ),
            (
                "transport",
                "--tls-key",
                host.p(&format!("Keys/{name}/Transport.key")),
            ),
            ("monitor", "--key", host.p("Clock/ClockSigner.json")),
        ] {
            let out = folder.join(format!("{class}.cbor"));
            if !out.exists() {
                let mut a = bytes(&["authority-inspection", "deployments", "possess"]);
                a.extend(host.trust()?);
                a.extend(bytes(&[
                    "--manifest",
                    &text(&inputs.join("Manifest.cbor"))?,
                    "--class",
                    class,
                    flag,
                    &text(&key)?,
                    "--not-before-ms",
                    &host.state.created_ms.to_string(),
                    "--expires-ms",
                    &expiry.to_string(),
                    "--output",
                    &text(&out)?,
                ]));
                host.suite(&a)?;
            }
        }
        let offer = folder.join("Offer.cbor");
        if !offer.exists() {
            let mut a = bytes(&["authority-inspection", "deployments", "assemble"]);
            a.extend(host.trust()?);
            a.extend(bytes(&[
                "--manifest",
                &text(&inputs.join("Manifest.cbor"))?,
                "--consent",
                &text(&consent)?,
            ]));
            for class in ["service", "transport", "monitor"] {
                a.extend(bytes(&[
                    "--possession",
                    &text(&folder.join(format!("{class}.cbor")))?,
                ]));
            }
            a.extend(bytes(&["--output", &text(&offer)?]));
            host.suite(&a)?;
        }
        let mut inspect = bytes(&["authority-inspection", "deployments", "inspect-offer"]);
        inspect.extend(host.trust()?);
        inspect.extend(bytes(&["--offer", &text(&offer)?]));
        let inspected = host.suite(&inspect)?;
        if inspected["profileDigest"] != profile {
            return Err(Error::State);
        }
        for file in [
            "Manifest.cbor",
            "Bootstrap.cbor",
            "Service.key",
            "Transport.key",
        ] {
            host.artifact(&inputs.join(file))?;
        }
        host.artifact(&offer)?;
        host.artifact(&consent)?;
        let route = inputs.join("RouteProfile.cbor");
        if !route.exists() {
            author_route(
                host,
                (name, operator_name, id_name, protocol),
                &inputs.join("Manifest.cbor"),
                &profile,
                &route,
            )?;
        }
        host.artifact(&route)?;
        let config = if name == "Relay" {
            json!({"version":1,"relayIdentity":null,"relayAddress":null})
        } else {
            let relay = host.remembered("role/Relay").ok_or(Error::State)?;
            let peer = public_read(&host.p("Peers/Relay.json"))?;
            json!({"version":1,"relayIdentity":{"service":raw_id(&host.state.ids["relay"])?,"serverName":host.c.advertised_address.to_string(),"transportKey":raw_id(&string(&relay,"transport")?)?,"leafDer":der(host,&host.p("Services/Relay/Inputs/Certificate.pem"))?,"certificateAuthorityPem":peer["authorityPem"]},"relayAddress":format!("{}:{}",host.c.advertised_address,host.c.relay_port)})
        };
        host.immutable_json(&folder.join("RelayConfiguration.json"), &config)?;
        if name != "ApplicationEndpoint" {
            host.immutable_json(&inputs.join("ServiceConfig.json"), &config)?;
        }
        let key = format!("deployment/{name}");
        if host.remembered(&key).is_none() {
            let mut a = bytes(&["authority-inspection", "deployments", "register"]);
            a.extend(online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--offer",
                &text(&offer)?,
            ]));
            let v = operator(host, "Administrator", &a)?;
            host.remember(&key, v)?;
        }
        let key = format!("route/{name}");
        if host.remembered(&key).is_none() {
            let mut a = bytes(&["routes", "register"]);
            a.extend(online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--profile",
                &text(&route)?,
            ]));
            let v = operator(host, "Administrator", &a)?;
            host.remember(&key, v)?;
        }
    }
    Ok(())
}
pub(super) fn activate_role(host: &mut Host<'_>, name: &str, operator_name: &str) -> Result<()> {
    let folder = host.p(&format!("Services/{name}"));
    let runtime = host.p(name);
    let input = folder.join("Inputs");
    if !runtime.exists() {
        let mut a = bytes(&[
            "runtime",
            "services",
            "setup",
            "--directory",
            &text(&runtime)?,
            "--configuration",
            &text(&input)?,
            "--operator-key",
            &text(&host.p(&format!("Keys/{operator_name}.json")))?,
            "--host-consent",
            &text(&folder.join("Consent.cbor"))?,
            "--authority-directory",
            &text(&host.p("A1"))?,
            "--clock-directory",
            &text(&host.p("Clock/Public"))?,
        ]);
        if name == "ApplicationEndpoint" {
            a.extend(bytes(&[
                "--application-directory",
                &text(&host.p("Receiver/Ingress"))?,
            ]));
        }
        host.core(&a)?;
    }
    let preview = host.core(&bytes(&[
        "runtime",
        "services",
        "preview",
        "--directory",
        &text(&runtime)?,
    ]))?;
    let consent_key = format!("local-consent/{name}");
    if host.remembered(&consent_key).is_none() {
        let v = host.core(&bytes(&[
            "runtime",
            "services",
            "consent",
            "--directory",
            &text(&runtime)?,
            "--profile-digest",
            &string(&preview, "profileDigest")?,
        ]))?;
        host.remember(&consent_key, v)?;
    }
    let generation = number(&preview, "localGeneration")?;
    let request = folder.join(format!("ActivationRequest{generation}.cbor"));
    if !request.exists() {
        let mut a = bytes(&["authority-inspection", "deployments", "activation-request"]);
        let mut common = online(host, "Administrator")?;
        common.truncate(common.len() - 2);
        a.extend(common);
        a.extend(bytes(&[
            "--deployment",
            &host.state.ids[&format!("deployment/{name}")],
            "--grant",
            &host.root_grant()?,
            "--role",
            "5",
            "--generation",
            &generation.to_string(),
            "--output",
            &text(&request)?,
        ]));
        operator(host, "Administrator", &a)?;
    }
    host.unit(
        &name.to_ascii_lowercase(),
        &host.c.core,
        &bytes(&[
            "runtime",
            "services",
            "start",
            "--directory",
            &text(&runtime)?,
            "--activation-request",
            &text(&request)?,
        ]),
    )?;
    let receipt = folder.join(format!("ActivationReceipt{generation}.cbor"));
    if !receipt.exists() {
        host.wait(
            || {
                host.core(&bytes(&[
                    "runtime",
                    "services",
                    "activation-receipt",
                    "--directory",
                    &text(&runtime)?,
                    "--output",
                    &text(&receipt)?,
                ]))?;
                Ok(())
            },
            45,
        )?;
    }
    let key = format!("activation/{name}/{generation}");
    if host.remembered(&key).is_none() {
        let mut a = bytes(&["authority-inspection", "deployments", "activation-complete"]);
        a.extend(online(host, "Administrator")?);
        a.extend(bytes(&["--receipt", &text(&receipt)?]));
        let v = operator(host, "Administrator", &a)?;
        host.remember(&key, v)?;
    }
    Ok(())
}
pub(super) fn activate(host: &mut Host<'_>) -> Result<()> {
    host.phase("Relay activation")?;
    activate_role(host, "Relay", "RelayOperator")?;
    activate_role(host, "AuthorityEndpoint", "AuthorityOperator")?;
    super::clients::service_owner(host)?;
    host.phase("HRC application activation")?;
    prepare_application(host)?;
    start_receiver(host)?;
    register_application(host)?;
    activate_role(host, "ApplicationEndpoint", "ApplicationOperator")
}
pub(super) fn prepare_application(host: &mut Host<'_>) -> Result<()> {
    let folder = active_directory(host, "ApplicationEndpoint")?;
    let input = folder.join("Inputs");
    let route = host
        .state
        .results
        .get("route/ApplicationEndpoint")
        .ok_or(Error::State)?;
    let reference = record_reference(route, 165)?;
    let owner = string(&host.state.results["ServiceOwner"], "publicKey")?;
    let offer = folder.join("ServiceOffer.cbor");
    let accepted = folder.join("ServiceAccepted.cbor");
    if !offer.exists() {
        let mut a = bytes(&["streams", "offer"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--key",
            &text(&host.p("Keys/ServiceOwner.json"))?,
            "--service",
            &host.state.ids["application"],
            "--route",
            &reference,
            "--operator",
            &string(&host.state.results["ApplicationOperator"], "publicKey")?,
            "--endpoint",
            &string(&host.state.results["role/ApplicationEndpoint"], "identity")?,
            "--protocol",
            "hrc/1",
            "--not-before-ms",
            &host
                .state
                .results
                .get("active-route-from-ms")
                .and_then(Value::as_u64)
                .unwrap_or(host.state.created_ms)
                .to_string(),
            "--expires-ms",
            &host.state.expires_ms.to_string(),
            "--maximum-bytes",
            &host.c.resources.connection_bytes.to_string(),
            "--duration-ms",
            &(host.c.resources.connection_seconds * 1000).to_string(),
            "--idle-ms",
            "30000",
            "--output",
            &text(&offer)?,
        ]));
        if let Some(previous) = host.remembered("renew-application-from") {
            a.extend(bytes(&[
                "--renew-from",
                previous.as_str().ok_or(Error::State)?,
            ]));
        }
        host.suite(&a)?;
    }
    if !accepted.exists() {
        let mut a = bytes(&["streams", "accept"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--offer",
            &text(&offer)?,
            "--owner-key",
            &owner,
            "--key",
            &text(&host.p("Keys/ApplicationOperator.json"))?,
            "--route-profile",
            &text(&input.join("RouteProfile.cbor"))?,
            "--output",
            &text(&accepted)?,
        ]));
        host.suite(&a)?;
    }
    let mut inspection = bytes(&["streams", "inspect-offer"]);
    inspection.extend(host.trust()?);
    inspection.extend(bytes(&["--offer", &text(&offer)?, "--owner-key", &owner]));
    host.suite(&inspection)?;
    if !input.join("ServiceConfig.json").exists() {
        let mut a = bytes(&["streams", "endpoint-config"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--accepted",
            &text(&accepted)?,
            "--configuration",
            &text(&folder.join("RelayConfiguration.json"))?,
            "--output",
            &text(&input.join("ServiceConfig.json"))?,
        ]));
        host.suite(&a)?;
    }
    host.artifact(&offer)?;
    host.artifact(&accepted)?;
    host.artifact(&input.join("ServiceConfig.json"))?;
    Ok(())
}
pub(super) fn start_receiver(host: &mut Host<'_>) -> Result<()> {
    let accepted = active_directory(host, "ApplicationEndpoint")?.join("ServiceAccepted.cbor");
    if !host.p("ReceiverFloor").exists() {
        let mut a = bytes(&[
            "authority-inspection",
            "initialise",
            "--requester",
            &string(&host.state.results["Receiver"], "publicKey")?,
        ]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--directory",
            &text(&host.p("ReceiverFloor"))?,
            "--clock-witness",
            &text(&host.p("Clock/ClockHealth.json"))?,
        ]));
        host.suite(&a)?;
    }
    let mut a = bytes(&["streams", "agent"]);
    a.extend(host.trust()?);
    a.extend(bytes(&[
        "--directory",
        &text(&host.p("ReceiverFloor"))?,
        "--clock-witness",
        &text(&host.p("Clock/ClockHealth.json"))?,
        "--key",
        &text(&host.p("Keys/Receiver.json"))?,
        "--socket",
        &text(&host.p("A1/Launch/State/Control/Control.sock"))?,
        "--ipc-directory",
        &text(&host.p("Receiver"))?,
        "--binding",
        &text(&accepted)?,
    ]));
    host.unit("receiver", &host.c.suite, &a)?;
    host.wait(
        || {
            podman(
                host,
                &bytes(&[
                    "unshare",
                    "/usr/bin/test",
                    "-f",
                    &text(&host.p("Receiver/Ingress/Binding.json"))?,
                ]),
            )?;
            Ok(())
        },
        20,
    )?;
    Ok(())
}
pub(super) fn register_application(host: &mut Host<'_>) -> Result<()> {
    let folder = active_directory(host, "ApplicationEndpoint")?;
    let accepted = folder.join("ServiceAccepted.cbor");
    let registration_key = format!("application-registration/{}", text(&folder)?);
    if host.remembered(&registration_key).is_none() {
        let mut a = bytes(&["streams", "register"]);
        a.extend(online(host, "ServiceOwner")?);
        a.extend(bytes(&[
            "--grant",
            &super::clients::grant_reference(host, "owner-manage")?,
            "--accepted",
            &text(&accepted)?,
        ]));
        let v = operator(host, "ServiceOwner", &a)?;
        host.remember(&registration_key, v)?;
    }
    Ok(())
}
pub(super) fn record_reference(value: &Value, kind: u64) -> Result<String> {
    let records = value["result"][3].as_array().ok_or(Error::State)?;
    let r = records
        .iter()
        .find(|r| r[0].as_u64() == Some(kind))
        .ok_or(Error::State)?;
    Ok(format!(
        "{}:{}:{}",
        string(&r[1], "hex")?,
        r[2].as_u64().ok_or(Error::State)?,
        string(&r[3], "hex")?
    ))
}
