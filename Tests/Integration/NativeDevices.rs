// SPDX-License-Identifier: Apache-2.0
//! Real device proof, owner-key recovery and future-only encrypted readmission.
use super::*;
use hrc::{client::devices, service::files};
use std::path::Path;

fn snapshot(run: &mut Run, bob: &mut Client) -> Result<IdentitySnapshot> {
    let account = bob.profile.registration.account;
    match run.effect(
        "Bob",
        bob,
        Operation::AccountDevices,
        Target::Account(account),
        &home::Empty {},
    )? {
        Outcome::Result { body } => body
            .deserialized()
            .map_err(|_| "IdentitySnapshotShape".into()),
        _ => Err("IdentitySnapshotUnavailable".into()),
    }
}

fn prepare(
    run: &mut Run,
    profile: &client::Profile,
    root: &Path,
    descriptor: &Path,
    purpose: DevicePurpose,
) -> Result<devices::PendingDevice> {
    run.step("Bob", "PrepareExactDeviceRequest", |_| {
        devices::prepare(devices::Prepare {
            directory: root,
            server: descriptor,
            account: profile.registration.account,
            principal: profile.registration.transport_principal,
            companion: profile.companion.clone(),
            clock: profile.clock.clone(),
            purpose,
            replacement: None,
            request_output: &root.with_extension("cbor"),
        })
        .map_err(|_| "DevicePreparationFailed".into())
    })
}

fn activate(run: &mut Run, directory: &Path, recovery: Option<&Path>) -> Result<DeviceActivated> {
    run.step("Bob", "ActivateExactDeviceRequest", |end| {
        loop {
            ensure(Instant::now() < end, "DeviceActivationDeadline")?;
            match devices::activate(directory, recovery) {
                Ok(receipt) => {
                    let (_, body) = committed(receipt.outcome)?;
                    return body.deserialized().map_err(|_| "DeviceReceiptShape".into());
                }
                Err(devices::Error::Authority | devices::Error::Unknown) => {
                    ensure(
                        Instant::now() + Duration::from_secs(1) < end,
                        "DeviceActivationDeadline",
                    )?;
                    thread::sleep(Duration::from_secs(1));
                }
                Err(_) => return Err("DeviceActivationRefused".into()),
            }
        }
    })
}

pub(super) fn workflow(
    run: &mut Run,
    request: &Request,
    alice: &mut Client,
    bob: &mut Client,
    room: RoomId,
    old_event: Id,
) -> Result<()> {
    let root = request
        .bob
        .parent()
        .ok_or("FixtureParent")?
        .join("DeviceLifecycle");
    files::directory(&root, true).map_err(|_| "DeviceFixtureDirectory")?;
    let descriptor = root.join("Service.json");
    files::create_json(&descriptor, &bob.profile.server).map_err(|_| "DeviceDescriptor")?;
    let enrol = root.join("Enrolled");
    let pending = prepare(run, &bob.profile, &enrol, &descriptor, DevicePurpose::Enrol)?;
    let before = snapshot(run, bob)?;
    let signed = files::read(&enrol.join("DeviceRequest.cbor"), ORDINARY_FRAME_BYTES)
        .map_err(|_| "DeviceRequestRead")?;
    run.effect(
        "Bob",
        bob,
        Operation::AccountEnrolEndpoint,
        Target::Account(before.account),
        &identity::ApproveEndpoint {
            request: Blob(signed),
            revision: before.revision,
            head: before.head.ok_or("ContinuityHead")?,
        },
    )
    .and_then(committed)?;
    let admitted = activate(run, &enrol, None)?;
    ensure(
        admitted.endpoint.as_ref().is_some_and(|a| {
            a.endpoint == pending.request.endpoint
                && a.account == before.account
                && a.security_generation == before.security_generation
        }),
        "EnrolmentBinding",
    )?;
    let mut new_device = run.step("Bob", "ConnectEnrolledDevice", |_| {
        net(Client::open(&enrol))
    })?;
    let view = run.step("Bob", "EnrolledDeviceHasNoOldKeys", |end| {
        current_read(&mut new_device, end, |c| c.crypto_inspect(room, None))
    })?;
    ensure(view.local.is_none(), "EnrolmentCopiedEncryptionState")?;
    new_device.disconnect();
    drop(new_device);
    let current = snapshot(run, bob)?;
    run.effect(
        "Bob",
        bob,
        Operation::AccountDisableEndpoint,
        Target::Account(before.account),
        &identity::DisableEndpoint {
            endpoint: pending.request.endpoint,
            revision: current.revision,
            head: current.head.ok_or("ContinuityHead")?,
        },
    )
    .and_then(committed)?;
    let current = snapshot(run, bob)?;
    ensure(
        !current
            .endpoints
            .iter()
            .any(|e| e.actor.endpoint == pending.request.endpoint),
        "DisabledEndpointRemainsActive",
    )?;

    let recovered = root.join("Recovered");
    let pending = prepare(
        run,
        &bob.profile,
        &recovered,
        &descriptor,
        DevicePurpose::Recover,
    )?;
    let original_endpoint = bob.profile.registration.endpoint;
    bob.disconnect();
    let activated = activate(run, &recovered, Some(&request.bob_recovery))?;
    ensure(
        activated.identity.security_generation == before.security_generation + 1
            && activated.identity.endpoints.len() == 1
            && activated.identity.endpoints[0].actor.endpoint == pending.request.endpoint,
        "RecoveryDidNotReplaceOldAuthority",
    )?;
    let mut recovered = run.step("Bob", "ConnectRecoveredDevice", |_| {
        net(Client::open(&recovered))
    })?;
    let barrier = run.step("Alice", "InspectRecoveryBarrier", |end| {
        // Observe recovery through a fresh session after the device administration.
        net(alice.connect())?;
        ensure(Instant::now() < end, "RecoveryObservationDeadline")?;
        current_read(alice, end, |c| c.crypto_inspect(room, None))
    })?;
    ensure(
        barrier.remote.send_barrier
            && barrier
                .remote
                .required_removals
                .contains(&original_endpoint),
        "RecoveryBarrierMissing",
    )?;
    run.step("Alice", "RemoveRecoveredOldEndpoint", |end| {
        let response = net(alice.crypto_commit(room, &[], &[original_endpoint], None))?;
        membership_ready(alice, room, response, end)
    })?;
    run.step("Bob", "EnrolRecoveredMlsKey", |end| {
        net(recovered.connect())?;
        ensure(Instant::now() < end, "RecoveredEndpointReturnDeadline")?;
        completed(net(recovered.crypto_enrol())?)
    })?;
    run.step("Bob", "PublishRecoveredFuturePackage", |_| {
        completed(net(recovered.crypto_publish(room, None))?)
    })?;
    let roster = run.step("Alice", "VerifyRecoveredContinuity", |end| {
        pin(alice, room, None, end)
    })?;
    let package = roster
        .remote
        .packages
        .iter()
        .find(|p| p.member.actor.acting().endpoint == pending.request.endpoint)
        .ok_or("RecoveredPackageMissing")?
        .digest;
    run.step("Alice", "AdmitRecoveredFutureEndpoint", |end| {
        let response = net(alice.crypto_commit(room, &[package], &[], None))?;
        membership_ready(alice, room, response, end)
    })?;
    run.step("Bob", "TrustRecoveredRoster", |end| {
        pin(&mut recovered, room, None, end)
    })?;
    run.step("Bob", "RecoveredWelcomeReady", |end| {
        synchronise(&mut recovered, room, None, end)
    })?;
    let old = run.step("Bob", "RecoveredHistoryIsFutureOnly", |end| {
        history(&mut recovered, room, None, end)
    })?;
    ensure(
        old.events.iter().any(|e| e.event == old_event)
            && !matches!(
                old.content.get(&old_event),
                Some(MessageContent::Decrypted(_))
            ),
        "RecoveredPastPlaintext",
    )?;
    let message = message("native after owner-key recovery", vec![]);
    let (event, _) = send(run, "Alice", alice, room, &message, None)?;
    let page = run.step("Bob", "ReadAfterOwnerKeyRecovery", |end| {
        history(&mut recovered, room, None, end)
    })?;
    ensure(text(&page, event, &message), "RecoveredFutureDecryption")?;
    recovered.disconnect();
    Ok(())
}
