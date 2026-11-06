// SPDX-License-Identifier: Apache-2.0
//! Explicit same-identity renewal: native host consent, certified routes, application consent and client vouchers.
use super::{Configuration, Error, Result, Status, clients, engine::*, lifecycle, services};
use crate::operations::native;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalPreview {
    pub digest: String,
    pub valid_until_ms: u64,
    pub domain_expires_ms: u64,
    pub host_boot: String,
    pub preserves_network_identity: bool,
    pub proposals: Vec<RenewalProposal>,
    pub governance_expires_ms: u64,
    pub client_voucher_maximum_ms: u64,
    pub client_principal: String,
    pub renewed_permissions: Vec<Value>,
    pub artifacts: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalProposal {
    pub role: String,
    pub service: bool,
    pub directory: PathBuf,
    pub proposal: PathBuf,
    pub preview_digest: String,
    pub preview: Value,
}
fn review_digest(value: &RenewalPreview) -> Result<String> {
    let mut value = value.clone();
    value.digest.clear();
    Ok(digest(
        &serde_json::to_vec(&value).map_err(|_| Error::State)?,
    ))
}
fn role_names() -> Vec<(String, bool)> {
    let mut roles = (1..=4)
        .map(|n| (format!("A{n}"), false))
        .collect::<Vec<_>>();
    roles.extend(
        services::roles()
            .into_iter()
            .map(|(n, _, _, _)| (n.to_owned(), true)),
    );
    roles
}
fn command(service: bool) -> Vec<String> {
    let mut args = bytes(&["runtime"]);
    if service {
        args.push("services".into());
    }
    args.push("transition".into());
    args
}
fn stopped(host: &Host<'_>) -> bool {
    ![
        "a1",
        "a2",
        "a3",
        "a4",
        "relay",
        "authorityendpoint",
        "applicationendpoint",
        "hrc",
        "client",
        "receiver",
    ]
    .iter()
    .any(|v| lifecycle::unit_active(host, v))
}
fn validate_deadline(now: u64, until: u64, governance: u64) -> Result<()> {
    if !until.is_multiple_of(1000)
        || until <= now
        || until > now.saturating_add(604_800_000)
        || until > governance
    {
        return Err(Error::Configuration(
            "renewal expiry must be a whole Unix second within seven days and the accepted governance horizon",
        ));
    }
    Ok(())
}
pub fn renewal_preview(
    c: &Configuration,
    valid_until_ms: u64,
    cancel: &AtomicBool,
) -> Result<RenewalPreview> {
    let mut host = Host::open(c, cancel, None)?;
    if !stopped(&host) {
        return Err(Error::Configuration(
            "stop the host before reviewing renewal",
        ));
    }
    if !host.state.completed {
        return Err(Error::Configuration(
            "complete initial setup before renewal",
        ));
    }
    validate_deadline(now()?, valid_until_ms, clients::governance_expiry(&host))?;
    if valid_until_ms <= host.state.expires_ms {
        return Err(Error::Configuration(
            "renewal must extend the current signed application consent",
        ));
    }
    super::bootstrap::clock(&mut host)?;
    let base = host.dir("Successor")?;
    let directory = base.join(valid_until_ms.to_string());
    native::directory(&directory).map_err(|_| Error::State)?;
    let mut proposals = Vec::new();
    for (role, service) in role_names() {
        let runtime = host.p(&role);
        let proposal = directory.join(format!("{role}.json"));
        if !proposal.exists() {
            let mut args = command(service);
            args.extend(bytes(&[
                "prepare",
                "--directory",
                &text(&runtime)?,
                "--valid-until",
                &(valid_until_ms / 1000).to_string(),
                "--refresh-host-boot",
                "--output",
                &text(&proposal)?,
            ]));
            host.core(&args)?;
        }
        let mut args = command(service);
        args.extend(bytes(&[
            "preview",
            "--directory",
            &text(&runtime)?,
            "--proposal",
            &text(&proposal)?,
        ]));
        let preview = host.core(&args)?;
        proposals.push(RenewalProposal {
            role,
            service,
            directory: runtime,
            proposal,
            preview_digest: string(&preview, "previewDigest")?,
            preview,
        });
    }
    let client = host.suite(&bytes(&[
        "network",
        "inspect",
        "--profile",
        &text(&host.p("Client/Network.json"))?,
    ]))?;
    let client_principal = string(&client, "devicePublicKey")?;
    let application = host.state.ids.get("application").ok_or(Error::State)?;
    let mut value = RenewalPreview {
        digest: String::new(),
        valid_until_ms,
        domain_expires_ms: valid_until_ms,
        host_boot: string(&host.state.results["clock"], "kernelBoot")?,
        preserves_network_identity: true,
        proposals,
        governance_expires_ms: clients::governance_expiry(&host),
        client_voucher_maximum_ms: 86_390_000,
        client_principal: client_principal.clone(),
        renewed_permissions: vec![
            json!({"subject":host.state.results["ServiceOwner"]["publicKey"],"actions":[29],"service":application,"expiresMs":valid_until_ms}),
            json!({"subject":client_principal,"actions":[30],"service":application,"expiresMs":valid_until_ms}),
        ],
        artifacts: host.state.artifacts.clone(),
    };
    value.digest = review_digest(&value)?;
    write(&directory.join("Review.json"), &value)?;
    Ok(value)
}
fn apply_proposal(host: &mut Host<'_>, item: &RenewalProposal, label: &str) -> Result<()> {
    let op = host.id(label)?;
    let mut a = command(item.service);
    a.extend(bytes(&[
        "apply",
        "--directory",
        &text(&item.directory)?,
        "--proposal",
        &text(&item.proposal)?,
        "--preview-digest",
        &item.preview_digest,
        "--operation-id",
        &op[..32],
    ]));
    host.core(&a)?;
    Ok(())
}
fn synchronise(host: &Host<'_>, name: &str) -> Result<()> {
    let mut a = bytes(&["authority-inspection", "deployments", "synchronise"]);
    a.extend(services::online(host, "Administrator")?);
    a.extend(bytes(&[
        "--grant",
        &host.root_grant()?,
        "--offers-directory",
        &text(&host.p(name).join("OperationalOffers"))?,
    ]));
    services::operator(host, "Administrator", &a)?;
    Ok(())
}
fn renew_routes(host: &mut Host<'_>, review: &RenewalPreview, base: &Path) -> Result<()> {
    host.phase("Renewing signed route consent")?;
    for (name, operator, id_name, protocol) in services::roles() {
        let folder = base.join(name);
        native::directory(&folder).map_err(|_| Error::State)?;
        let inputs = folder.join("Inputs");
        native::directory(&inputs).map_err(|_| Error::State)?;
        let item = review
            .proposals
            .iter()
            .find(|v| v.role == name)
            .ok_or(Error::State)?;
        let generation = number(&item.preview, "generation")?;
        let retained = host
            .p(name)
            .join(format!("OperationalOffers/Generation{generation:020}.cbor"));
        let mut a = bytes(&["authority-inspection", "deployments", "inspect-offer"]);
        a.extend(host.trust()?);
        a.extend(bytes(&["--offer", &text(&retained)?]));
        let inspected = host.suite(&a)?;
        if inspected["manifest"] != item.preview["successor"] {
            return Err(Error::PreviewChanged);
        }
        let manifest = inputs.join("Manifest.cbor");
        if !manifest.exists() {
            native::exact_file(
                &manifest,
                &native::public_file(&host.p(name).join("Config/Manifest.cbor"), 65536)
                    .map_err(|_| Error::State)?,
            )
            .map_err(|_| Error::State)?;
        }
        let profile = inputs.join("RouteProfile.cbor");
        if !profile.exists() {
            services::author_route(
                host,
                (name, operator, id_name, protocol),
                &manifest,
                &string(&inspected, "profileDigest")?,
                &profile,
            )?;
        }
        host.artifact(&manifest)?;
        host.artifact(&profile)?;
        let key = format!("renewed-route/{}/{name}", review.valid_until_ms);
        let result = if let Some(v) = host.remembered(&key) {
            v
        } else {
            let mut a = bytes(&["routes", "register"]);
            a.extend(services::online(host, "Administrator")?);
            a.extend(bytes(&[
                "--grant",
                &host.root_grant()?,
                "--profile",
                &text(&profile)?,
            ]));
            let v = services::operator(host, "Administrator", &a)?;
            host.remember(&key, v)?
        };
        host.remember(&format!("route/{name}"), result)?;
        let previous = services::active_directory(host, name)?;
        if name == "ApplicationEndpoint"
            && host
                .remembered(&format!("previous-application/{}", review.valid_until_ms))
                .is_none()
        {
            host.remember(
                &format!("previous-application/{}", review.valid_until_ms),
                json!(previous.join("ServiceAccepted.cbor")),
            )?;
        }
        let configuration = native::public_file(
            &host.p(&format!("Services/{name}/RelayConfiguration.json")),
            16384,
        )
        .map_err(|_| Error::State)?;
        native::exact_file(&folder.join("RelayConfiguration.json"), &configuration)
            .map_err(|_| Error::State)?;
        host.artifact(&folder.join("RelayConfiguration.json"))?;
        host.remember(&format!("active-service/{name}"), json!(folder))?;
    }
    let from = review
        .proposals
        .iter()
        .filter(|v| v.service)
        .map(|v| {
            v.preview["successor"]["validity"][0]
                .as_u64()
                .ok_or(Error::State)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or(Error::State)?;
    host.remember("active-route-from-ms", json!(from))?;
    let previous = host
        .remembered(&format!("previous-application/{}", review.valid_until_ms))
        .ok_or(Error::State)?;
    host.remember("renew-application-from", previous)?;
    Ok(())
}
fn apply_bindings(host: &mut Host<'_>, review: &RenewalPreview, base: &Path) -> Result<()> {
    host.phase("Applying exact renewed native bindings")?;
    for (name, _, _, _) in services::roles() {
        let marker = format!("bindings/{}/{name}", review.valid_until_ms);
        if host.remembered(&marker).is_some() {
            continue;
        }
        let runtime = host.p(name);
        let proposal = base.join(format!("{name}-Bindings.json"));
        let saved = base.join(format!("{name}-BindingsReview.json"));
        let input = services::active_directory(host, name)?.join("Inputs");
        if !proposal.exists() {
            let mut a = command(true);
            a.extend(bytes(&[
                "prepare",
                "--directory",
                &text(&runtime)?,
                "--route-profile",
                &text(&input.join("RouteProfile.cbor"))?,
            ]));
            if name == "ApplicationEndpoint" {
                a.extend(bytes(&[
                    "--application-config",
                    &text(&input.join("ServiceConfig.json"))?,
                ]));
            }
            a.extend(bytes(&["--output", &text(&proposal)?]));
            host.core(&a)?;
        }
        let value = if saved.exists() {
            read(&saved)?
        } else {
            let mut a = command(true);
            a.extend(bytes(&[
                "preview",
                "--directory",
                &text(&runtime)?,
                "--proposal",
                &text(&proposal)?,
            ]));
            let v = host.core(&a)?;
            write(&saved, &v)?;
            v
        };
        // Core checks every identity, privacy property, resource budget, local socket binding and signature.
        // This second exact proposal is authorised only inside the already reviewed same-scope renewal.
        if value["routeBindings"]["samePermanentIdentity"] != true
            || value["routeBindings"]["unchangedExposurePrivacyAndBudgets"] != true
            || value["routeBindings"]["validUntilMs"] != review.valid_until_ms
        {
            return Err(Error::PreviewChanged);
        }
        let item = RenewalProposal {
            role: name.into(),
            service: true,
            directory: runtime,
            proposal,
            preview_digest: string(&value, "previewDigest")?,
            preview: value,
        };
        apply_proposal(host, &item, &marker)?;
        host.remember(&marker, json!(true))?;
        synchronise(host, name)?;
    }
    Ok(())
}
fn retain_current_journal(host: &mut Host<'_>, expiry: u64) -> Result<()> {
    let current = expiry.to_string();
    // Keep native replay journals unchanged. Old HRC reviews remain on disk; the active index is bounded.
    host.state.results.retain(|key, _| {
        if [
            "renewal/",
            "renewed-route/",
            "bindings/",
            "successor/",
            "previous-application/",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
        {
            return key.split('/').nth(1) == Some(current.as_str());
        }
        if key.starts_with("grant/")
            && key
                .rsplit('/')
                .next()
                .is_some_and(|v| v.parse::<u64>().is_ok())
        {
            return key.rsplit('/').next() == Some(current.as_str());
        }
        if key.starts_with("route-expiry/") && key.contains("/Renewed") {
            return key.contains(&format!("/Renewed{current}/"));
        }
        true
    });
    host.state.ids.retain(|key, _| {
        if key.starts_with("successor/") || key.starts_with("bindings/") {
            return key.split('/').nth(1) == Some(current.as_str());
        }
        if (key.starts_with("client-") || key.starts_with("owner-manage/"))
            && key
                .rsplit('/')
                .next()
                .is_some_and(|v| v.parse::<u64>().is_ok())
        {
            return key.rsplit('/').next() == Some(current.as_str());
        }
        true
    });
    let successor = host.p("Successor");
    let active = successor.join(&current);
    host.state.artifacts.retain(|path, _| {
        if Path::new(path).starts_with(&successor) {
            return Path::new(path).starts_with(&active);
        }
        !path.contains("/Renewed") || path.contains(&format!("/Renewed{current}/"))
    });
    host.state.results.remove("renew-application-from");
    host.save()
}
pub fn renew(
    c: &Configuration,
    valid_until_ms: u64,
    reviewed_digest: &str,
    cancel: &AtomicBool,
) -> Result<Status> {
    let mut host = Host::open(c, cancel, None)?;
    let base = host.p(&format!("Successor/{valid_until_ms}"));
    let review: RenewalPreview =
        serde_json::from_value(read(&base.join("Review.json"))?).map_err(|_| Error::State)?;
    if review.digest != reviewed_digest
        || review.digest != review_digest(&review)?
        || review.valid_until_ms != valid_until_ms
    {
        return Err(Error::PreviewChanged);
    }
    validate_deadline(now()?, valid_until_ms, clients::governance_expiry(&host))?;
    let key = format!("renewal/{valid_until_ms}");
    let resumed = host.remembered(&key);
    if resumed
        .as_ref()
        .is_some_and(|v| v["digest"] != reviewed_digest)
    {
        return Err(Error::PreviewChanged);
    }
    if resumed.is_none() {
        if !stopped(&host) {
            return Err(Error::Configuration(
                "stop the host before applying renewal",
            ));
        }
        if host.state.artifacts != review.artifacts {
            return Err(Error::PreviewChanged);
        }
        host.remember(&key, json!({"digest":reviewed_digest,"completed":false}))?;
    } else if resumed.as_ref().is_some_and(|v| v["completed"] == true) {
        return lifecycle::observe(&mut host);
    }
    super::bootstrap::clock(&mut host)?;
    if string(&host.state.results["clock"], "kernelBoot")? != review.host_boot {
        return Err(Error::PreviewChanged);
    }
    for (index, (name, service)) in role_names().iter().enumerate() {
        let item = review.proposals.get(index).ok_or(Error::State)?;
        if item.role != *name
            || item.service != *service
            || item.directory != host.p(name)
            || item.proposal != base.join(format!("{name}.json"))
        {
            return Err(Error::State);
        }
        let marker = format!("successor/{valid_until_ms}/{name}");
        if host.remembered(&marker).is_none() {
            apply_proposal(&mut host, item, &marker)?;
            host.remember(&marker, json!(true))?;
        }
    }
    host.state.expires_ms = valid_until_ms;
    host.save()?;
    super::bootstrap::activate(&mut host)?;
    for (name, _, _, _) in services::roles() {
        synchronise(&host, name)?;
    }
    renew_routes(&mut host, &review, &base)?;
    host.remember("grant-epoch", json!(valid_until_ms))?;
    clients::service_owner(&mut host)?;
    services::prepare_application(&mut host)?;
    services::register_application(&mut host)?;
    apply_bindings(&mut host, &review, &base)?;
    services::activate(&mut host)?;
    clients::renew_local_client(&mut host)?;
    clients::start_client(&host)?;
    lifecycle::start_host(&mut host)?;
    let observed = lifecycle::observe(&mut host)?;
    if !observed.quorum_verified || !observed.client_authenticated {
        return Err(Error::NotReady);
    }
    host.remember(&key, json!({"digest":reviewed_digest,"completed":true}))?;
    retain_current_journal(&mut host, valid_until_ms)?;
    host.phase("Ready")?;
    lifecycle::observe(&mut host)
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Operations/Network/Renewal.rs"]
mod tests;
