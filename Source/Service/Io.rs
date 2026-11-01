// SPDX-License-Identifier: Apache-2.0
//! Bounded HRC frames carried only by a verified HyperNet stream.
use crate::{
    clock,
    hypernet::Stream,
    protocol::{Frame, FrameHeader},
};
use std::time::Duration;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("transport unavailable; an operation outcome may be unknown")]
    Transport,
    #[error("invalid or unsupported HRC frame")]
    Frame,
    #[error("HRC frame deadline expired")]
    Deadline,
}
pub fn send(stream: &Stream, frame: &Frame, timeout: Duration) -> Result<(), Error> {
    let deadline = clock::boot_ms()
        .map_err(|_| Error::Deadline)?
        .checked_add(
            timeout
                .as_millis()
                .try_into()
                .map_err(|_| Error::Deadline)?,
        )
        .ok_or(Error::Deadline)?;
    let bytes = frame.encode().map_err(|_| Error::Frame)?;
    for chunk in bytes.chunks(65536) {
        stream
            .send_all_before(chunk, deadline)
            .map_err(|_| Error::Transport)?;
    }
    Ok(())
}
pub fn receive(stream: &Stream, timeout: Duration) -> Result<Frame, Error> {
    let deadline = clock::boot_ms()
        .map_err(|_| Error::Deadline)?
        .checked_add(
            timeout
                .as_millis()
                .try_into()
                .map_err(|_| Error::Deadline)?,
        )
        .ok_or(Error::Deadline)?;
    let mut header = [0; 5];
    stream
        .recv_exact_before(&mut header, deadline)
        .map_err(|_| Error::Transport)?;
    let parsed = FrameHeader::decode(header).map_err(|_| Error::Frame)?;
    let mut payload = vec![0; parsed.payload_len];
    for chunk in payload.chunks_mut(65536) {
        stream
            .recv_exact_before(chunk, deadline)
            .map_err(|_| Error::Transport)?;
    }
    Frame::new(parsed.kind, payload).map_err(|_| Error::Frame)
}
