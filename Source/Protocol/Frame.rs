// SPDX-License-Identifier: Apache-2.0
//! Length admission precedes allocation and semantic or cryptographic processing.
use super::{CRYPTO_FRAME_BYTES, Error, ORDINARY_FRAME_BYTES, Result, cbor};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    Challenge = 2,
    Proof = 3,
    Ready = 4,
    Action = 5,
    Response = 6,
    Event = 7,
    Close = 8,
    Federation = 9,
    CryptoAction = 10,
    CryptoEvent = 11,
    CryptoFederation = 12,
}
impl FrameKind {
    pub fn maximum_bytes(self) -> usize {
        if matches!(
            self,
            Self::CryptoAction | Self::CryptoEvent | Self::CryptoFederation
        ) {
            CRYPTO_FRAME_BYTES
        } else {
            ORDINARY_FRAME_BYTES
        }
    }
}
impl TryFrom<u8> for FrameKind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Proof),
            4 => Ok(Self::Ready),
            5 => Ok(Self::Action),
            6 => Ok(Self::Response),
            7 => Ok(Self::Event),
            8 => Ok(Self::Close),
            9 => Ok(Self::Federation),
            10 => Ok(Self::CryptoAction),
            11 => Ok(Self::CryptoEvent),
            12 => Ok(Self::CryptoFederation),
            _ => Err(Error::Feature),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: FrameKind,
    pub payload_len: usize,
}
impl FrameHeader {
    pub fn decode(bytes: [u8; 5]) -> Result<Self> {
        let kind = FrameKind::try_from(bytes[4])?;
        let length =
            u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error::Encoding)?) as usize;
        if length < 2 || length > kind.maximum_bytes() {
            return Err(Error::Limit);
        }
        Ok(Self {
            kind,
            payload_len: length - 1,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn new(kind: FrameKind, payload: Vec<u8>) -> Result<Self> {
        cbor::validate(&payload, kind.maximum_bytes() - 1, super::MAX_DEPTH)?;
        Ok(Self { kind, payload })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::validate(
            &self.payload,
            self.kind.maximum_bytes() - 1,
            super::MAX_DEPTH,
        )?;
        let mut bytes = Vec::with_capacity(5 + self.payload.len());
        bytes.extend_from_slice(&((self.payload.len() + 1) as u32).to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header = FrameHeader::decode(
            bytes
                .get(..5)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        )?;
        if bytes.len() != 5 + header.payload_len {
            return Err(Error::Encoding);
        }
        Self::new(header.kind, bytes[5..].to_vec())
    }
}
