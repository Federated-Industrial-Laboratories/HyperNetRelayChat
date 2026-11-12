// SPDX-License-Identifier: Apache-2.0
//! Ordinary candidate admission and exact signed registration through supported native operations.
use super::*;
use serde::{Deserialize, Serialize};
use state::{Admission, Candidate};
#[path = "Lifecycle.rs"]
mod lifecycle;
pub(crate) use lifecycle::{renew, revoke};

pub(crate) fn metadata(
    config: &Config,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<NetworkMetadata> {
    let _lock = state::Lock::acquire(config)?;
    let native = native::Native::new(config, cancel, end);
    checked_metadata(&native).map(|(metadata, _)| metadata)
}
fn checked_metadata(native: &native::Native<'_>) -> Result<(NetworkMetadata, Value)> {
    let config = native.config;
    use crate::operations::packages::{Product, verify_installed};
    let core = verify_installed(
        Product::Core,
        &config.core,
        &config.publisher_key,
        native.cancel,
        native.end,
    )
    .map_err(|_| Error::Native)?;
    verify_installed(
        Product::Suite,
        &config.suite,
        &config.publisher_key,
        native.cancel,
        native.end,
    )
    .map_err(|_| Error::Native)?;
    if core["metadata"]["imageId"] != config.image {
        return Err(Error::State);
    }
    native.prepare()?;
    let bootstrap = native.bootstrap()?;
    let network = string(&bootstrap, "network")?;
    let incarnation = string(&bootstrap, "incarnation")?;
    let mut expires = config.access_expires_ms.min(
        bootstrap["route"]["expiresMs"]
            .as_u64()
            .ok_or(Error::State)?,
    );
    for route in [&config.relay, &config.authority, &config.application]
        .into_iter()
        .chain(config.reader.iter().map(|reader| &reader.content))
    {
        expires = expires.min(routes::profile_expiry(route, &network, &incarnation)?);
    }
    if !is_id(&network) || !is_id(&incarnation) || expires <= now_ms()? {
        return Err(Error::Expired);
    }
    let home = crate::operations::home::Configuration::load(&config.home_config)
        .map_err(|_| Error::State)?;
    let service = hrc::service::Config::load(&home.directory)
        .map_err(|_| Error::State)?
        .descriptor
        .home;
    if service.network.network.as_hex() != network
        || service.network.incarnation.as_hex() != incarnation
        || service.service.as_hex() != config.application.service
    {
        return Err(Error::State);
    }
    Ok((
        NetworkMetadata {
            bootstrap: Artifact::from_bytes(
                &process::public_file(&config.bootstrap, 1_048_576).map_err(|_| Error::State)?,
            )?,
            bootstrap_fingerprint: string(&bootstrap, "fingerprint")?,
            network,
            incarnation,
            application_service: config.application.service.clone(),
            reader_available: config.reader.is_some(),
            access_expires_ms: expires,
        },
        bootstrap,
    ))
}
fn inspect_request(
    native: &native::Native<'_>,
    folder: &Path,
    bytes: &[u8],
    bootstrap: &Value,
) -> Result<Value> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(Error::Invalid);
    }
    state::directory(folder)?;
    let path = folder.join("Request.cbor");
    state::exact(&path, bytes)?;
    let value = native.suite(&args(&[
        "network",
        "inspect-request",
        "--request",
        &text(&path)?,
    ]))?;
    for name in ["network", "incarnation", "descriptorDigest"] {
        if value[name] != bootstrap[name] {
            return Err(Error::Bound);
        }
    }
    if value["minimumRoute"] != "Organisational" {
        return Err(Error::Invalid);
    }
    Ok(value)
}
pub(super) fn distinct(chat: &Candidate, reader: &Candidate) -> Result<()> {
    if [&chat.principal, &chat.relay]
        .iter()
        .any(|key| [&reader.principal, &reader.relay].contains(key))
    {
        return Err(Error::Bound);
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Current {
    pub round: u64,
    pub delivery: Delivery,
}
pub(super) fn current(work: &Path) -> Result<Current> {
    state::read(&work.join("Current.json"))
}
pub(super) fn store_current(work: &Path, value: &Current) -> Result<()> {
    // Deliveries contain several public artifacts and exceed the setup-file limit.
    super::super::store::write(&work.join("Current.json"), value)
}

fn recorded_routes(
    native: &native::Native<'_>,
    admission: &Admission,
    round: &Path,
) -> Result<bool> {
    for (name, second) in std::iter::once(("Chat", "Application"))
        .chain(admission.reader.iter().map(|_| ("Reader", "Page")))
    {
        let folder = round.join(name);
        for role in ["Authority", second] {
            let name = format!("{role}Route");
            let output = folder.join(format!("{name}.json"));
            if !state::recover_recorded_effect(native, &folder, &name, &output)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(super) fn completed_round(
    native: &native::Native<'_>,
    admission: &Admission,
    work: &Path,
    round: &Path,
) -> Result<Option<Delivery>> {
    let path = round.join("Delivery.json");
    if path.exists() {
        return state::read(&path).map(Some);
    }
    if !work.join("Setup.json").exists() || !recorded_routes(native, admission, round)? {
        return Ok(None);
    }
    let value = delivery(native, admission, work, round)?;
    state::save(&path, &value)?;
    Ok(Some(value))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn issue(
    config: &Config,
    work: &Path,
    chat_request: &[u8],
    reader_request: Option<&[u8]>,
    access_expires_ms: u64,
    route_seconds: u64,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Delivery> {
    let _lock = state::Lock::acquire(config)?;
    state::directory(work)?;
    state::active(work)?;
    if !(120..=86_390).contains(&route_seconds)
        || config.reader.is_some() != reader_request.is_some()
    {
        return Err(Error::Invalid);
    }
    let native = native::Native::new(config, cancel, end);
    let (metadata, bootstrap) = checked_metadata(&native)?;
    if access_expires_ms > metadata.access_expires_ms
        || access_expires_ms <= now_ms()?.saturating_add(60_000)
    {
        return Err(Error::Expired);
    }
    let chat_folder = work.join("Chat");
    let chat = inspect_request(&native, &chat_folder, chat_request, &bootstrap)?;
    let reader = reader_request
        .map(|bytes| inspect_request(&native, &work.join("Reader"), bytes, &bootstrap))
        .transpose()?;
    let path = work.join("Admission.json");
    let admission: Admission = if path.exists() {
        state::read(&path)?
    } else {
        let now = now_ms()?;
        let chat = Candidate::new(chat_request, &chat, false)?;
        let reader = reader_request
            .zip(reader.as_ref())
            .map(|(bytes, value)| Candidate::new(bytes, value, true))
            .transpose()?;
        if let Some(reader) = &reader {
            distinct(&chat, reader)?;
        }
        let admission = Admission {
            config_digest: digest(&serde_json::to_vec(config).map_err(|_| Error::State)?),
            bootstrap_sha256: metadata.bootstrap.sha256.clone(),
            network: metadata.network,
            incarnation: metadata.incarnation,
            access_expires_ms,
            route_seconds,
            not_before_ms: (now / 1000 * 1000).saturating_sub(2000),
            initial_expires_ms: access_expires_ms.min(now + route_seconds * 1000),
            join_expires_ms: access_expires_ms.min(now + 86_390_000),
            invitation_id: id()?,
            invitation_expires_ms: access_expires_ms.min(now + 86_398_000),
            chat,
            reader,
        };
        state::save(&path, &admission)?;
        admission
    };
    admission.validate(config)?;
    if admission.chat.request_sha256 != digest(chat_request)
        || admission.reader.as_ref().map(|v| &v.request_sha256)
            != reader_request.map(digest).as_ref()
        || admission.access_expires_ms != access_expires_ms
        || admission.route_seconds != route_seconds
    {
        return Err(Error::Bound);
    }
    if work.join("Current.json").exists() {
        return Ok(current(work)?.delivery);
    }
    let round = work.join("Round0");
    state::directory(&round)?;
    if let Some(delivery) = completed_round(&native, &admission, work, &round)? {
        store_current(
            work,
            &Current {
                round: 0,
                delivery: delivery.clone(),
            },
        )?;
        return Ok(delivery);
    }
    let now = now_ms()?;
    if now
        >= admission
            .join_expires_ms
            .min(admission.invitation_expires_ms)
        || (admission.initial_expires_ms <= now.saturating_add(60_000)
            && !recorded_routes(&native, &admission, &round)?)
    {
        return Err(Error::Expired);
    }
    let root = routes::root_grant(&bootstrap)?;
    native.prepare()?;
    for (name, second) in std::iter::once(("Chat", "Application"))
        .chain(admission.reader.iter().map(|_| ("Reader", "Page")))
    {
        let routes = round.join(name);
        state::directory(&routes)?;
        routes::prepare_template(
            &native,
            "Authority",
            &work.join(name).join("JoinTemplate.json"),
        )?;
        routes::prepare_template(&native, "Authority", &routes.join("AuthorityTemplate.json"))?;
        routes::prepare_template(
            &native,
            second,
            &routes.join(format!("{second}Template.json")),
        )?;
    }
    let connect = candidate(
        &native,
        &admission,
        &admission.chat,
        &chat_folder,
        &round.join("Chat"),
        &root,
        false,
    )?;
    if let Some(reader) = &admission.reader {
        candidate(
            &native,
            &admission,
            reader,
            &work.join("Reader"),
            &round.join("Reader"),
            &root,
            true,
        )?;
    }
    let invitation_path = chat_folder.join("HrcInvitation.json");
    let invitation = native.home(&work.join("HrcInvitation"), |home, active| {
        if active {
            return hrc::service::live_admission::legacy_invite(
                home,
                admission.chat.principal.parse().map_err(|_| Error::State)?,
                admission.invitation_id.parse().map_err(|_| Error::State)?,
                admission.invitation_expires_ms,
            )
            .map_err(|_| Error::Native);
        }
        hrc::service::setup::invite_exact(
            home,
            admission.chat.principal.parse().map_err(|_| Error::State)?,
            admission.invitation_id.parse().map_err(|_| Error::State)?,
            admission.invitation_expires_ms,
        )
        .map_err(|_| Error::Native)
    })?;
    state::save(&invitation_path, &invitation)?;
    let (bundle, _) = crate::onboarding::build_bundle(crate::onboarding::BundleInputs {
        bootstrap: config.bootstrap.clone(),
        network_invitation: chat_folder.join("Invitation.json"),
        authority_route: round.join("Chat/AuthorityRoute.json"),
        application_route: round.join("Chat/ApplicationRoute.json"),
        hrc_invitation: invitation_path,
        connect_grant: connect.ok_or(Error::State)?,
        renewal_ms: 0,
    })
    .map_err(|_| Error::State)?;
    state::exact(&work.join("Setup.json"), &bundle)?;
    let delivery = delivery(&native, &admission, work, &round)?;
    state::save(&round.join("Delivery.json"), &delivery)?;
    store_current(
        work,
        &Current {
            round: 0,
            delivery: delivery.clone(),
        },
    )?;
    Ok(delivery)
}
fn candidate(
    native: &native::Native<'_>,
    admission: &Admission,
    person: &Candidate,
    folder: &Path,
    round: &Path,
    root: &str,
    reader: bool,
) -> Result<Option<String>> {
    state::directory(round)?;
    routes::delegate(native, admission, person, folder, root, false)?;
    let connect = if reader {
        None
    } else {
        Some(routes::delegate(
            native, admission, person, folder, root, true,
        )?)
    };
    let offer = folder.join("MemberOffer.cbor");
    let mut online = native.online()?;
    online.truncate(online.len() - 2);
    let mut arguments = args(&["authority-inspection", "invite-member"]);
    arguments.extend(online);
    arguments.extend(args(&[
        "--reader-grant",
        &person.reader_grant,
        "--member",
        &person.member,
        "--not-before-ms",
        &admission.not_before_ms.to_string(),
        "--expires-ms",
        &admission.access_expires_ms.to_string(),
        "--acceptance-ms",
        "86400000",
        "--output",
        &text(&offer)?,
    ]));
    state::effect(native, folder, "MemberOffer", arguments, Some(&offer))?;
    let mut arguments = args(&["routes", "invite"]);
    arguments.extend(native.online()?);
    arguments.extend(args(&["--grant", root, "--offer", &text(&offer)?]));
    state::effect(native, folder, "PendingMember", arguments, None)?;
    routes::issue_route(
        native,
        admission,
        person,
        root,
        "Authority",
        folder,
        admission.join_expires_ms,
        None,
        true,
    )?;
    let invitation = folder.join("Invitation.json");
    if !invitation.exists() {
        let mut arguments = args(&["network", "invitation"]);
        arguments.extend(native.trust()?);
        arguments.extend(args(&[
            "--offer",
            &text(&offer)?,
            "--admission-grant",
            root,
            "--authority-route",
            &text(&folder.join("JoinRoute.json"))?,
            "--output",
            &text(&invitation)?,
        ]));
        native.suite(&arguments)?;
    }
    routes::issue_route(
        native,
        admission,
        person,
        root,
        "Authority",
        round,
        admission.initial_expires_ms,
        None,
        false,
    )?;
    routes::issue_route(
        native,
        admission,
        person,
        root,
        if reader { "Page" } else { "Application" },
        round,
        admission.initial_expires_ms,
        None,
        false,
    )?;
    Ok(connect)
}
fn delivery(
    native: &native::Native<'_>,
    admission: &Admission,
    work: &Path,
    round: &Path,
) -> Result<Delivery> {
    let collect = |candidate: &Candidate, reader: bool| -> Result<Vec<RouteDelivery>> {
        ["Authority", if reader { "Page" } else { "Application" }]
            .iter()
            .map(|role| {
                let path = round
                    .join(if reader { "Reader" } else { "Chat" })
                    .join(format!("{role}Route.json"));
                let voucher = routes::voucher(&path)?;
                let expected = if *role == "Authority" {
                    &candidate.authority
                } else {
                    &candidate.destination
                };
                if voucher.id != *expected || voucher.possession != candidate.relay {
                    return Err(Error::State);
                }
                let subject = match *role {
                    "Authority" => native.config.authority.service.clone(),
                    "Application" => native.config.application.service.clone(),
                    _ => native
                        .config
                        .reader
                        .as_ref()
                        .ok_or(Error::State)?
                        .page_host_key
                        .clone(),
                };
                Ok(RouteDelivery {
                    role: (*role).into(),
                    subject,
                    artifact: state::artifact(&path)?,
                    voucher_id: voucher.id,
                    generation: voucher.generation,
                    expires_ms: voucher.expiry,
                })
            })
            .collect()
    };
    let chat_routes = collect(&admission.chat, false)?;
    let reader = admission
        .reader
        .as_ref()
        .map(|candidate| {
            Ok(ReaderDelivery {
                network_invitation: state::artifact(&work.join("Reader/Invitation.json"))?,
                request_sha256: candidate.request_sha256.clone(),
                routes: collect(candidate, true)?,
            })
        })
        .transpose()?;
    let all = chat_routes
        .iter()
        .chain(reader.iter().flat_map(|r| &r.routes));
    let route_expires_ms = all
        .clone()
        .map(|route| route.expires_ms)
        .min()
        .ok_or(Error::State)?;
    let renewal_after_ms = all
        .map(|route| route.expires_ms)
        .max()
        .ok_or(Error::State)?
        .checked_add(2000)
        .ok_or(Error::State)?;
    Ok(Delivery {
        setup_bundle: state::artifact(&work.join("Setup.json"))?,
        chat_request_sha256: admission.chat.request_sha256.clone(),
        chat_routes,
        reader,
        access_expires_ms: admission.access_expires_ms,
        join_expires_ms: admission
            .join_expires_ms
            .min(admission.invitation_expires_ms),
        route_expires_ms,
        renewal_after_ms,
    })
}
pub(crate) fn enrol(
    config: &Config,
    work: &Path,
    bytes: &[u8],
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let _lock = state::Lock::acquire(config)?;
    state::active(work)?;
    let admission: Admission = state::read(&work.join("Admission.json"))?;
    admission.validate(config)?;
    let _delivery = current(work)?;
    if now_ms()? >= admission.access_expires_ms {
        return Err(Error::Expired);
    }
    let signed = hrc::protocol::verify_registration_request(bytes).map_err(|_| Error::Invalid)?;
    let registration = signed.value();
    if registration.transport_principal.as_hex() != admission.chat.principal
        || registration.invitation.as_hex() != admission.invitation_id
        || registration.home.network.network.as_hex() != admission.network
        || registration.home.network.incarnation.as_hex() != admission.incarnation
        || registration.home.service.as_hex() != config.application.service
        || registration.classification != hrc::protocol::AccountClass::Human
    {
        return Err(Error::Bound);
    }
    state::exact(&work.join("Registration.cbor"), bytes)?;
    if work.join("Enrolled.json").exists() {
        return Ok(());
    }
    let native = native::Native::new(config, cancel, end);
    let actor = native.home(&work.join("HrcEnrolment"), |home, active| {
        if active {
            return hrc::service::live_admission::legacy_enrol(home, bytes)
                .map_err(|_| Error::Native);
        }
        hrc::service::setup::enrol_exact(home, bytes).map_err(|_| Error::Native)
    })?;
    state::save(
        &work.join("Enrolled.json"),
        &json!({"registrationSha256":digest(bytes), "actor":actor}),
    )
}
