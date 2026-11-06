// SPDX-License-Identifier: Apache-2.0
//! Candidate-bound HyperNet invitations and the first authenticated HRC desktop account.
use super::{Configuration, Error, Result, Status, engine::*, services};
use crate::operations::native;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

pub(super) fn grant_start(created_ms: u64, current_ms: u64) -> u64 {
    // Native validity includes 1250 ms uncertainty; keep a whole-second margin.
    created_ms.max((current_ms / 1000 * 1000).saturating_sub(2000))
}

fn delegate(
    host: &mut Host<'_>,
    label: &str,
    subject: &str,
    actions: &str,
    service: bool,
) -> Result<()> {
    let actual = if service {
        host.remembered("grant-epoch")
            .and_then(|v| v.as_u64())
            .map(|v| format!("{label}/{v}"))
            .unwrap_or_else(|| label.into())
    } else {
        label.into()
    };
    let key = format!("grant/{actual}");
    if host.remembered(&key).is_some() {
        host.remember(&format!("active-grant/{label}"), json!(actual))?;
        return Ok(());
    }
    let id = host.id(&actual)?;
    let start_key = format!("grant-start/{actual}");
    let not_before = if service {
        match host.remembered(&start_key) {
            Some(value) => value.as_u64().ok_or(Error::State)?,
            None => {
                let start = grant_start(host.state.created_ms, now()?);
                host.remember(&start_key, json!(start))?;
                start
            }
        }
    } else {
        host.state.created_ms
    };
    let mut a = bytes(&["authority-inspection", "delegate-grant"]);
    a.extend(services::online(host, "Administrator")?);
    a.extend(bytes(&[
        "--context-grant",
        &host.root_grant()?,
        "--parent",
        &host.root_grant()?,
        "--id",
        &id,
        "--subject",
        subject,
        "--actions",
        actions,
        "--not-before-ms",
        &not_before.to_string(),
        "--expires-ms",
        &if service {
            host.state.expires_ms
        } else {
            governance_expiry(host)
        }
        .to_string(),
        "--limits",
        &host.c.resources.connection_bytes.to_string(),
        "1024",
        "8",
        "16",
    ]));
    if service {
        a.extend(bytes(&[
            "--scopes",
            &format!("3:{}", host.state.ids["application"]),
        ]));
    }
    let v = services::operator(host, "Administrator", &a)?;
    host.remember(&key, v)?;
    host.remember(&format!("active-grant/{label}"), json!(actual))?;
    Ok(())
}
pub(super) fn governance_expiry(host: &Host<'_>) -> u64 {
    host.state.created_ms + u64::from(host.c.governance_days) * 86_400_000
}
pub(super) fn grant_reference(host: &Host<'_>, label: &str) -> Result<String> {
    let actual = host.remembered(&format!("active-grant/{label}"));
    let label = actual.as_ref().and_then(Value::as_str).unwrap_or(label);
    let value = host
        .state
        .results
        .get(&format!("grant/{label}"))
        .ok_or(Error::State)?;
    Ok(format!(
        "{}:1:{}",
        host.state.ids.get(label).ok_or(Error::State)?,
        string(value, "recordDigest")?
    ))
}
fn member_offer(host: &mut Host<'_>, label: &str, reader: &str, output: &Path) -> Result<()> {
    if output.exists() {
        return Ok(());
    }
    let member = host.id(&format!("member/{label}"))?;
    let mut a = bytes(&["authority-inspection", "invite-member"]);
    let mut common = services::online(host, "Administrator")?;
    common.truncate(common.len() - 2);
    a.extend(common);
    a.extend(bytes(&[
        "--reader-grant",
        host.state.ids.get(reader).ok_or(Error::State)?,
        "--member",
        &member,
        "--not-before-ms",
        &host.state.created_ms.to_string(),
        "--expires-ms",
        &governance_expiry(host).to_string(),
        "--output",
        &text(output)?,
    ]));
    services::operator(host, "Administrator", &a)?;
    Ok(())
}
pub(super) fn service_owner(host: &mut Host<'_>) -> Result<()> {
    let subject = string(&host.state.results["ServiceOwner"], "publicKey")?;
    delegate(host, "owner-reader", &subject, "0,6", false)?;
    delegate(host, "owner-manage", &subject, "29", true)?;
    let folder = host.dir("Owner")?;
    let offer = folder.join("Offer.cbor");
    let accepted = folder.join("Accepted.cbor");
    let receipt = folder.join("Receipt.cbor");
    member_offer(host, "owner", "owner-reader", &offer)?;
    if !accepted.exists() {
        let mut a = bytes(&["authority-inspection", "accept-member"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--key",
            &text(&host.p("Keys/ServiceOwner.json"))?,
            "--offer",
            &text(&offer)?,
            "--output",
            &text(&accepted)?,
        ]));
        host.suite(&a)?;
    }
    if !receipt.exists() {
        let mut a = bytes(&["authority-inspection", "admit-member"]);
        a.extend(services::online(host, "Administrator")?);
        a.extend(bytes(&[
            "--context-grant",
            &host.root_grant()?,
            "--grant",
            &host.root_grant()?,
            "--accepted",
            &text(&accepted)?,
            "--receipt",
            &text(&receipt)?,
        ]));
        services::operator(host, "Administrator", &a)?;
    }
    let mut a = bytes(&["authority-inspection", "confirm-member"]);
    a.extend(host.trust()?);
    a.extend(bytes(&[
        "--accepted",
        &text(&accepted)?,
        "--receipt",
        &text(&receipt)?,
    ]));
    host.suite(&a)?;
    services::initialise(host, "ServiceOwner")
}
fn template(host: &Host<'_>, application: bool) -> Result<PathBuf> {
    let name = if application {
        "ApplicationTemplate.json"
    } else {
        "AuthorityTemplate.json"
    };
    let path = services::active_directory(host, "Relay")?.join(name);
    if !path.exists() {
        let mut a = bytes(&["routes", "template"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--relay-profile",
            &text(&services::active_directory(host, "Relay")?.join("Inputs/RouteProfile.cbor"))?,
            "--destination-profile",
            &text(
                &services::active_directory(
                    host,
                    if application {
                        "ApplicationEndpoint"
                    } else {
                        "AuthorityEndpoint"
                    },
                )?
                .join("Inputs/RouteProfile.cbor"),
            )?,
            "--minimum-route",
            "Organisational",
            "--output",
            &text(&path)?,
        ]));
        host.suite(&a)?;
    }
    Ok(path)
}
fn route(
    host: &mut Host<'_>,
    label: &str,
    request: &Value,
    application: bool,
    join: bool,
    output: &Path,
) -> Result<()> {
    if output.exists() {
        return Ok(());
    }
    let label = match host.remembered("grant-epoch").and_then(|v| v.as_u64()) {
        Some(v) => format!("{label}/{v}"),
        None => label.into(),
    };
    let id = host.id(&label)?;
    let count = if join { 8 } else { 64 };
    let maximum = host.c.resources.connection_bytes * count;
    let expiry = host.state.expires_ms.min(now()? + 86_390_000);
    let template = template(host, application)?;
    let mut a = bytes(&["routes", "issue"]);
    a.extend(services::online(host, "Administrator")?);
    a.extend(bytes(&[
        "--grant",
        &host.root_grant()?,
        "--id",
        &id,
        "--relay",
        &host.state.ids["relay"],
        "--destination",
        &host.state.ids[if application {
            "application"
        } else {
            "authority"
        }],
        "--possession",
        &string(request, "relayPublicKey")?,
        "--action",
        if join { "10" } else { "0" },
        "--scope",
        &string(&host.bootstrap()?, "network")?,
        "--connections",
        &count.to_string(),
        "--bytes",
        &maximum.to_string(),
        "--expires-ms",
        &expiry.to_string(),
        "--route-template",
        &text(&template)?,
        "--output",
        &text(output)?,
    ]));
    services::operator(host, "Administrator", &a)?;
    host.remember(&format!("route-expiry/{}", text(output)?), json!(expiry))?;
    Ok(())
}
pub(super) fn ensure_service(host: &mut Host<'_>) -> Result<()> {
    let directory = host.c.service_directory();
    if !directory.exists() {
        let bootstrap = host.bootstrap()?;
        host.hrc(&bytes(&[
            "service",
            "init",
            "--directory",
            &text(&directory)?,
            "--network",
            &string(&bootstrap, "network")?,
            "--incarnation",
            &string(&bootstrap, "incarnation")?,
            "--service",
            &host.state.ids["application"],
            "--motd",
            &host.c.name,
            "--companion",
            &text(&host.p("Receiver"))?,
            "--clock-observation",
            &text(&host.p("Clock/Public/ClockHealth.cbor"))?,
            "--clock-key",
            &host.monitor()?,
        ]))?;
    }
    let config = hrc::service::Config::load(&directory).map_err(|_| Error::State)?;
    if config.descriptor.home.service.as_hex() != host.state.ids["application"]
        || config.companion != host.p("Receiver")
    {
        return Err(Error::State);
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientDelivery {
    pub bundle: PathBuf,
    pub fingerprint: String,
    pub expires_ms: u64,
    pub principal: String,
    pub registration_pending: bool,
}
fn invite(
    host: &mut Host<'_>,
    request_path: &Path,
    operator: Option<&str>,
) -> Result<ClientDelivery> {
    host.phase("Client invitation")?;
    let request = host.suite(&bytes(&[
        "network",
        "inspect-request",
        "--request",
        &text(request_path)?,
    ]))?;
    let bootstrap = host.bootstrap()?;
    if request["network"] != bootstrap["network"]
        || request["incarnation"] != bootstrap["incarnation"]
        || request["descriptorDigest"] != bootstrap["descriptorDigest"]
        || request["minimumRoute"] != "Organisational"
    {
        return Err(Error::Configuration(
            "candidate request belongs to another network or requires independent relay operators",
        ));
    }
    let subject = string(&request, "devicePublicKey")?;
    let label = format!("client-{}", &subject[..16]);
    let identity_folder = host.dir(&format!("Exchange/{label}"))?;
    let folder = if let Some(epoch) = host.remembered("grant-epoch").and_then(|v| v.as_u64()) {
        host.dir(&format!("Exchange/{label}/Renewed{epoch}"))?
    } else {
        identity_folder.clone()
    };
    let request_data = native::public_file(request_path, 65536).map_err(|_| Error::State)?;
    native::exact_file(&folder.join("Request.cbor"), &request_data).map_err(|_| Error::State)?;
    // The native request inspection verifies its self-signature; grant creation binds this exact key.
    host.artifact(&folder.join("Request.cbor"))?;
    delegate(host, &format!("{label}-reader"), &subject, "0,6", false)?;
    delegate(host, &format!("{label}-connect"), &subject, "30", true)?;
    let offer = identity_folder.join("MemberOffer.cbor");
    member_offer(host, &label, &format!("{label}-reader"), &offer)?;
    let key = format!("pending-member/{label}");
    if host.remembered(&key).is_none() {
        let mut a = bytes(&["routes", "invite"]);
        a.extend(services::online(host, "Administrator")?);
        a.extend(bytes(&[
            "--grant",
            &host.root_grant()?,
            "--offer",
            &text(&offer)?,
        ]));
        let v = services::operator(host, "Administrator", &a)?;
        host.remember(&key, v)?;
    }
    let join_route = identity_folder.join("JoinRoute.json");
    route(
        host,
        &format!("{label}-join"),
        &request,
        false,
        true,
        &join_route,
    )?;
    let invitation = identity_folder.join("Invitation.json");
    if !invitation.exists() {
        let mut a = bytes(&["network", "invitation"]);
        a.extend(host.trust()?);
        a.extend(bytes(&[
            "--offer",
            &text(&offer)?,
            "--admission-grant",
            &host.root_grant()?,
            "--authority-route",
            &text(&join_route)?,
            "--output",
            &text(&invitation)?,
        ]));
        host.suite(&a)?;
    }
    let authority_route = folder.join("AuthorityRoute.json");
    let application_route = folder.join("ApplicationRoute.json");
    route(
        host,
        &format!("{label}-authority"),
        &request,
        false,
        false,
        &authority_route,
    )?;
    route(
        host,
        &format!("{label}-application"),
        &request,
        true,
        false,
        &application_route,
    )?;
    ensure_service(host)?;
    let hrc_invitation = identity_folder.join("HrcInvitation.json");
    if !hrc_invitation.exists() {
        let mut a = bytes(&[
            "service",
            "invite",
            "--directory",
            &text(&host.c.service_directory())?,
            "--principal",
            &subject,
            "--output",
            &text(&hrc_invitation)?,
        ]);
        if let Some(owner) = operator {
            a.extend(bytes(&["--operator", owner]));
        }
        host.hrc(&a)?;
    }
    let inputs = crate::onboarding::BundleInputs {
        bootstrap: host.p("Network/Bootstrap.cbor"),
        network_invitation: invitation,
        authority_route,
        application_route,
        hrc_invitation,
        connect_grant: grant_reference(host, &format!("{label}-connect"))?,
        renewal_ms: 0,
    };
    let (data, fingerprint) = crate::onboarding::build_bundle(inputs).map_err(|_| Error::State)?;
    let bundle = folder.join("HrcSetup.json");
    native::exact_file(&bundle, &data).map_err(|_| Error::State)?;
    host.artifact(&bundle)?;
    host.remember(
        &format!("delivery/{label}"),
        json!({"principal":subject,"operator":operator,"fingerprint":fingerprint}),
    )?;
    Ok(ClientDelivery {
        bundle,
        fingerprint,
        expires_ms: host
            .remembered(&format!(
                "route-expiry/{}",
                text(&folder.join("ApplicationRoute.json"))?
            ))
            .and_then(|v| v.as_u64())
            .unwrap_or(host.state.expires_ms),
        principal: subject,
        registration_pending: true,
    })
}
pub fn invite_client(
    c: &Configuration,
    request: &Path,
    operator: Option<&str>,
    cancel: &AtomicBool,
) -> Result<ClientDelivery> {
    let mut host = Host::open(c, cancel, None)?;
    let was_running = super::lifecycle::unit_active(&host, "hrc");
    let result = (|| {
        if was_running {
            host.stop_unit("hrc")?;
        }
        invite(&mut host, request, operator)
    })();
    restore_after_admission(&host, was_running, result)
}
pub fn enrol_client(c: &Configuration, registration: &Path, cancel: &AtomicBool) -> Result<Status> {
    let mut host = Host::open(c, cancel, None)?;
    let was_running = super::lifecycle::unit_active(&host, "hrc");
    let result = (|| {
        if was_running {
            host.stop_unit("hrc")?;
        }
        host.hrc(&bytes(&[
            "service",
            "enrol",
            "--directory",
            &text(&c.service_directory())?,
            "--registration",
            &text(registration)?,
        ]))
    })();
    restore_after_admission(&host, was_running, result)?;
    super::lifecycle::observe(&mut host)
}
fn restore_after_admission<T>(host: &Host<'_>, was_running: bool, result: Result<T>) -> Result<T> {
    if was_running && super::lifecycle::restore_hrc(host).is_err() {
        let outcome = match &result {
            Ok(_) => "The account operation completed.".to_owned(),
            Err(error) => error.to_string(),
        };
        return Err(Error::ServiceRestore(outcome));
    }
    result
}
pub(super) fn create_owner(host: &mut Host<'_>) -> Result<()> {
    host.phase("Desktop account")?;
    ensure_service(host)?;
    let folder = host.p("Client");
    let profile = folder.join("Network.json");
    if !profile.exists() {
        host.suite(&bytes(&[
            "network",
            "prepare",
            "--bootstrap",
            &text(&host.p("Network/Bootstrap.cbor"))?,
            "--fingerprint",
            &string(&host.bootstrap()?, "fingerprint")?,
            "--minimum-route",
            "Organisational",
            "--output",
            &text(&profile)?,
        ]))?;
    }
    let prepared = host.suite(&bytes(&[
        "network",
        "inspect",
        "--profile",
        &text(&profile)?,
    ]))?;
    let request = folder.join("Request.cbor");
    if !request.exists() {
        host.suite(&bytes(&[
            "network",
            "request",
            "--profile",
            &text(&profile)?,
            "--output",
            &text(&request)?,
        ]))?;
    }
    let subject = string(&prepared, "devicePublicKey")?;
    let label = format!("client-{}", &subject[..16]);
    let exchange = host.p(&format!("Exchange/{label}"));
    if host.remembered("owner-enrolled").is_none() {
        if super::lifecycle::unit_active(host, "hrc") {
            host.stop_unit("hrc")?;
        }
        invite(host, &request, None)?;
    }
    let joined = folder.join("Joined");
    let joined_status = host.suite(&bytes(&[
        "network",
        "status",
        "--profile",
        &text(&profile)?,
    ]));
    if !joined_status
        .as_ref()
        .is_ok_and(|v| v["membership"] == true || v["joined"] == true || v["state"] == "Joined")
    {
        let invitation = exchange.join("Invitation.json");
        let pin = digest(&native::public_file(&invitation, 1_048_576).map_err(|_| Error::State)?);
        host.suite(&bytes(&[
            "network",
            "join",
            "--profile",
            &text(&profile)?,
            "--invitation",
            &text(&invitation)?,
            "--invitation-digest",
            &pin,
            "--directory",
            &text(&joined)?,
            "--clock-witness",
            &text(&host.p("Clock/ClockHealth.json"))?,
        ]))?;
    }
    for (name, id) in [
        ("Authority", host.state.ids["authority"].clone()),
        ("Application", host.state.ids["application"].clone()),
    ] {
        let route = exchange.join(format!("{name}Route.json"));
        let pin = digest(&native::public_file(&route, 1_048_576).map_err(|_| Error::State)?);
        host.suite(&bytes(&[
            "network",
            "retain-route",
            "--profile",
            &text(&profile)?,
            "--route-profile",
            &text(&route)?,
            "--fingerprint",
            &pin,
            "--subject",
            &id,
        ]))?;
    }
    let target = json!([{"service":host.state.ids["application"],"protocol":"hrc/1","grant":grant_reference(host,&format!("{label}-connect"))?,"route":joined.join("Routes").join(format!("{}.json",host.state.ids["application"])),"renewalMs":0}]);
    host.immutable_json(&folder.join("Targets.json"), &target)?;
    if let Some(expiry) = host.remembered(&format!(
        "route-expiry/{}",
        text(&exchange.join("ApplicationRoute.json"))?
    )) {
        host.remember("client-expires-ms", expiry)?;
    }
    start_client(host)?;
    let hrc_profile = host.c.hrc_profile();
    let registration = folder.join("Registration.cbor");
    if !hrc_profile.exists() {
        host.hrc(&bytes(&[
            "profile",
            "create",
            "--directory",
            &text(&hrc_profile)?,
            "--invitation",
            &text(&exchange.join("HrcInvitation.json"))?,
            "--recovery-key-file",
            &text(&host.c.recovery_directory.join("Account.key"))?,
            "--registration-output",
            &text(&registration)?,
            "--companion",
            &text(&folder.join("Companion"))?,
            "--clock-observation",
            &text(&host.p("Clock/Public/ClockHealth.cbor"))?,
            "--clock-key",
            &host.monitor()?,
        ]))?;
    }
    let loaded = hrc::client::Profile::load(&hrc_profile).map_err(|_| Error::State)?;
    if loaded.registration.transport_principal.as_hex() != subject
        || loaded.server.home.service.as_hex() != host.state.ids["application"]
    {
        return Err(Error::State);
    }
    if host.remembered("owner-enrolled").is_none() {
        let value = host.hrc(&bytes(&[
            "service",
            "enrol",
            "--directory",
            &text(&host.c.service_directory())?,
            "--registration",
            &text(&registration)?,
        ]))?;
        host.remember("owner-enrolled", value)?;
    }
    let mut runtime = crate::onboarding::RuntimeConfig::at(folder.clone());
    runtime.core = host.c.core.clone();
    runtime.suite = host.c.suite.clone();
    runtime.network_profile = profile;
    runtime.joined_directory = joined;
    runtime.companion_directory = folder.join("Companion");
    runtime.targets_file = folder.join("Targets.json");
    runtime.clock_directory = host.p("Clock");
    runtime.clock_observation = host.p("Clock/Public/ClockHealth.cbor");
    runtime.clock_monitor_key = host.monitor()?;
    runtime.chronyc = host.c.chronyc.clone();
    runtime.chrony_socket = host.c.chrony_socket.clone();
    runtime.hrc_profile = hrc_profile;
    runtime.recovery_key = host.c.recovery_directory.join("Account.key");
    runtime.registration_file = registration;
    runtime.save().map_err(|_| Error::State)?;
    Ok(())
}
pub(super) fn start_client(host: &Host<'_>) -> Result<()> {
    let targets = host
        .remembered("active-client-targets")
        .and_then(|v| v.as_str().map(PathBuf::from))
        .unwrap_or_else(|| host.p("Client/Targets.json"));
    if !targets.starts_with(&host.c.root) {
        return Err(Error::State);
    }
    let args = bytes(&[
        "network",
        "connect",
        "--profile",
        &text(&host.p("Client/Network.json"))?,
        "--",
        "streams",
        "agent",
        "--ipc-directory",
        &text(&host.p("Client/Companion"))?,
        "--targets",
        &text(&targets)?,
    ]);
    host.unit("client", &host.c.suite, &args)?;
    host.wait(
        || {
            let v = host.suite(&bytes(&[
                "streams",
                "status",
                "--directory",
                &text(&host.p("Client/Companion"))?,
            ]))?;
            if v.is_object() {
                Ok(())
            } else {
                Err(Error::NotReady)
            }
        },
        20,
    )
}
pub(super) fn renew_local_client(host: &mut Host<'_>) -> Result<()> {
    let request = host.p("Client/Request.cbor");
    let delivery = invite(host, &request, None)?;
    let exchange = delivery.bundle.parent().ok_or(Error::State)?;
    let profile = host.p("Client/Network.json");
    for (name, id) in [
        ("Authority", host.state.ids["authority"].clone()),
        ("Application", host.state.ids["application"].clone()),
    ] {
        let path = exchange.join(format!("{name}Route.json"));
        let pin = digest(&native::public_file(&path, 1_048_576).map_err(|_| Error::State)?);
        host.suite(&bytes(&[
            "network",
            "retain-route",
            "--profile",
            &text(&profile)?,
            "--route-profile",
            &text(&path)?,
            "--fingerprint",
            &pin,
            "--subject",
            &id,
        ]))?;
    }
    let label = format!("client-{}", &delivery.principal[..16]);
    let path = exchange.join("Targets.json");
    host.immutable_json(&path,&json!([{"service":host.state.ids["application"],"protocol":"hrc/1","grant":grant_reference(host,&format!("{label}-connect"))?,"route":host.p("Client/Joined/Routes").join(format!("{}.json",host.state.ids["application"])),"renewalMs":0}]))?;
    host.remember("active-client-targets", json!(path))?;
    host.remember("client-expires-ms", json!(delivery.expires_ms))?;
    let mut runtime =
        crate::onboarding::RuntimeConfig::load(&host.p("Client/OnboardingRuntime.json"))
            .map_err(|_| Error::State)?;
    runtime.targets_file = path;
    runtime.save().map_err(|_| Error::State)?;
    Ok(())
}
