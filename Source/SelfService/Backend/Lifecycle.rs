// SPDX-License-Identifier: Apache-2.0
//! Same-voucher renewal and exact grant revocation preserve enrolled identities and uncertain effects.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Renewal {
    round: u64,
    expires_ms: u64,
}

pub(crate) fn renew(
    config: &Config,
    work: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Delivery> {
    let _lock = state::Lock::acquire(config)?;
    state::active(work)?;
    let admission: Admission = state::read(&work.join("Admission.json"))?;
    admission.validate(config)?;
    let mut previous = current(work)?;
    let now = now_ms()?;
    if now < previous.delivery.renewal_after_ms {
        return Ok(previous.delivery);
    }
    if now >= admission.access_expires_ms
        || (!work.join("Enrolled.json").exists()
            && now
                >= admission
                    .join_expires_ms
                    .min(admission.invitation_expires_ms))
    {
        return Err(Error::Expired);
    }
    let native = native::Native::new(config, cancel, end);
    let (metadata, bootstrap) = checked_metadata(&native)?;
    loop {
        process::check(cancel, end).map_err(|_| Error::Cancelled)?;
        let now = now_ms()?;
        let number = previous
            .round
            .checked_add(1)
            .filter(|n| *n <= 8192)
            .ok_or(Error::State)?;
        let round = work.join(format!("Round{number}"));
        state::directory(&round)?;
        let intent_path = round.join("Intent.json");
        let intent: Renewal = if intent_path.exists() {
            state::read(&intent_path)?
        } else {
            let expires = now
                .saturating_add(admission.route_seconds * 1000)
                .min(admission.access_expires_ms)
                .min(metadata.access_expires_ms);
            if expires <= now.saturating_add(60_000) {
                return Err(Error::Expired);
            }
            let intent = Renewal {
                round: number,
                expires_ms: expires,
            };
            state::save(&intent_path, &intent)?;
            intent
        };
        if intent.round != number {
            return Err(Error::State);
        }
        // Recover committed routes before considering their old expiry. If the caller
        // missed that entire generation, continue from it without changing its IDs.
        if let Some(delivery) = completed_round(&native, &admission, work, &round)? {
            if delivery.setup_bundle != previous.delivery.setup_bundle {
                return Err(Error::State);
            }
            previous = Current {
                round: number,
                delivery,
            };
            store_current(work, &previous)?;
            if now_ms()? < previous.delivery.renewal_after_ms {
                return Ok(previous.delivery);
            }
            continue;
        }
        if intent.expires_ms <= now.saturating_add(60_000) {
            return Err(Error::Expired);
        }
        let root = routes::root_grant(&bootstrap)?;
        native.prepare()?;
        for (name, person, second) in std::iter::once(("Chat", &admission.chat, "Application"))
            .chain(
                admission
                    .reader
                    .iter()
                    .map(|candidate| ("Reader", candidate, "Page")),
            )
        {
            let folder = round.join(name);
            state::directory(&folder)?;
            for role in ["Authority", second] {
                let prior = work
                    .join(format!("Round{}", previous.round))
                    .join(name)
                    .join(format!("{role}Route.json"));
                routes::issue_route(
                    &native,
                    &admission,
                    person,
                    &root,
                    role,
                    &folder,
                    intent.expires_ms,
                    Some(&prior),
                    false,
                )?;
            }
        }
        let delivery = delivery(&native, &admission, work, &round)?;
        if delivery.setup_bundle != previous.delivery.setup_bundle {
            return Err(Error::State);
        }
        state::save(&round.join("Delivery.json"), &delivery)?;
        store_current(
            work,
            &Current {
                round: number,
                delivery: delivery.clone(),
            },
        )?;
        return Ok(delivery);
    }
}

pub(crate) fn revoke(
    config: &Config,
    work: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let _lock = state::Lock::acquire(config)?;
    state::directory(work)?;
    state::save(
        &work.join("Revocation.json"),
        &json!({"status":"RevocationRequested"}),
    )?;
    if work.join("Revoked.json").exists() {
        return Ok(());
    }
    if !work.join("Admission.json").exists() {
        return state::save(
            &work.join("Revoked.json"),
            &json!({"status":"NoNativeAdmission"}),
        );
    }
    let admission: Admission = state::read(&work.join("Admission.json"))?;
    admission.validate(config)?;
    let native = native::Native::new(config, cancel, end);
    let root = routes::root_grant(&native.bootstrap()?)?;
    let mut uncertain = false;
    let mut targets = Vec::new();
    for (name, candidate, connect) in [
        ("Chat", &admission.chat, true),
        ("Chat", &admission.chat, false),
    ]
    .into_iter()
    .chain(
        admission
            .reader
            .iter()
            .map(|reader| ("Reader", reader, false)),
    ) {
        let label = if connect { "Connect" } else { "Reader" };
        let folder = work.join(name);
        let result_path = folder.join(format!("{label}Grant.json"));
        let effect = folder.join("Effects").join(format!("{label}Grant"));
        let result = if result_path.exists() {
            Some(state::read::<Value>(&result_path)?)
        } else if effect.join("Result.json").exists() {
            Some(state::read::<Value>(&effect.join("Result.json"))?)
        } else {
            if effect.join("Intent.json").exists() {
                uncertain = true;
            }
            None
        };
        if let Some(result) = result {
            let reference = routes::check_grant(config, &admission, candidate, connect, &result)?;
            let parts = reference.split(':').collect::<Vec<_>>();
            if parts.len() != 3 || parts[0] == root {
                return Err(Error::State);
            }
            targets.push((
                format!("{name}{label}"),
                parts[0].to_owned(),
                parts[2].to_owned(),
            ));
        }
    }
    for (name, target, digest) in &targets {
        let mut arguments = args(&["authority-inspection", "context"]);
        arguments.extend(native.online()?);
        arguments.extend(args(&["--grant", &root]));
        state::effect(
            &native,
            work,
            &format!("{name}RevokeContext"),
            arguments,
            None,
        )?;
        let mut arguments = args(&["authority-inspection", "revoke-grant"]);
        arguments.extend(native.online()?);
        arguments.extend(args(&[
            "--grant",
            &root,
            "--target",
            target,
            "--target-generation",
            "1",
            "--target-digest",
            digest,
        ]));
        let result = state::effect(&native, work, &format!("{name}Revocation"), arguments, None)?;
        let fields = result["record"].as_array().ok_or(Error::State)?;
        if result["status"] != "GrantRevoked"
            || result["grant"] != *target
            || fields.len() != 9
            || fields[0] != 126
            || fields[1] != 1
            || fields[4] != 1
            || !fields[5].is_null()
            || fields[2] != json!({"hex":admission.network})
            || fields[3] != json!({"hex":admission.incarnation})
            || fields[6] != json!([102, {"hex":target}, 1, {"hex":digest}])
            || result["recordDigest"] != routes::record_digest(&result["record"])?
        {
            return Err(Error::State);
        }
    }
    if uncertain {
        state::save(
            &work.join("RevocationBlocked.json"),
            &json!({"reason":"GrantOutcomeUncertain", "knownRevoked":targets}),
        )?;
        return Err(Error::Native);
    }
    state::save(
        &work.join("Revoked.json"),
        &json!({"status":"NativeGrantsRevoked", "targets":targets}),
    )
}
