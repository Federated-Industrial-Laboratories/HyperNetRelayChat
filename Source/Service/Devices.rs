// SPDX-License-Identifier: Apache-2.0
//! One finite pre-session device exchange; it cannot submit conversation operations.
use super::*;
pub(super) fn serve(
    shared: &Shared,
    stream: &Stream,
    incoming: Frame,
    principal: Id,
    end: u64,
) -> Result<()> {
    let request = verify_new_device(&incoming.payload).map_err(|_| Error::Authentication)?;
    let transport = crate::home::DeviceTransport {
        principal,
        session: Id::from_hex(stream.peer().session()).map_err(|_| Error::Authentication)?,
        generation: stream.peer().generation(),
        service_boot: shared.boot,
    };
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let challenge = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .device_challenge(&request, transport, now)
        .map_err(|_| Error::Authentication)?;
    frame(
        stream,
        FrameKind::DeviceChallenge,
        challenge.signed_bytes().to_vec(),
        remaining(end)?,
    )?;
    let incoming = io::receive(stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if incoming.kind != FrameKind::DeviceProof {
        return Err(Error::Frame);
    }
    let proofs: DeviceProofs = canonical_decode(&incoming.payload, ORDINARY_FRAME_BYTES)
        .map_err(|_| Error::Frame)?
        .deserialized()
        .map_err(|_| Error::Frame)?;
    let check = shared
        .companion
        .check_authority(
            stream,
            *digest(&incoming.payload).as_bytes(),
            remaining(end)?.min(Duration::from_secs(1)),
        )
        .map_err(|_| Error::Authority)?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let receipt = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .activate_device(&request, &challenge, &proofs, transport, now, &|| {
            check.permitted() && clock::boot_ms().is_ok_and(|now| now < end)
        })
        .map_err(|_| Error::State)?;
    // A lost response after durable commit remains an unknown outcome until the exact request is resolved.
    frame(
        stream,
        FrameKind::DeviceReceipt,
        sign_device_receipt(&receipt, &shared.signer).map_err(|_| Error::Frame)?,
        remaining(end)?,
    )
}
