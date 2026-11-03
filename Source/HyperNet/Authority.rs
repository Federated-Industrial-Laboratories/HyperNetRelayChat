//! Finite local observations of current transport authority for one immutable action.
use super::{
    Companion, Error, Lifecycle, Result, Stream,
    context::{ControlIdentity, Direction, Id, Privacy, decode},
    ipc, lock,
};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Disposition {
    Permitted,
    Denied,
    Unavailable,
    Expired,
    NotActive,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityObservation {
    network: Id,
    incarnation: Id,
    configuration: Id,
    epoch: u64,
    height: u64,
    state: Id,
    statement_digest: Id,
    evaluated_at_ms: u64,
    expires_at_ms: u64,
    code: u64,
}
impl AuthorityObservation {
    pub fn code(&self) -> u64 {
        self.code
    }
    pub fn configuration(&self) -> &str {
        self.configuration.as_str()
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn state(&self) -> &str {
        self.state.as_str()
    }
    pub fn statement_digest(&self) -> &str {
        self.statement_digest.as_str()
    }
    pub fn evaluated_at_ms(&self) -> u64 {
        self.evaluated_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

struct ReceiptIdentity {
    session: Id,
    generation: u64,
    companion_instance: Id,
    endpoint_instance: Id,
    control_generation: u64,
}

/// Validated receipt attributes; these values alone do not authorize an effect.
pub struct AuthorityIdentity<'a> {
    pub session: &'a str,
    pub generation: u64,
    pub companion_instance: &'a str,
    pub endpoint_instance: &'a str,
    pub control_generation: u64,
}

/// Borrowed evidence for a fresh origin attestation, never a portable permit.
/// Callers must recheck `permitted()` immediately before using its original deadline.
pub struct AuthorityAttestation<'a> {
    check: &'a AuthorityCheck,
    identity: &'a ReceiptIdentity,
    authority: &'a AuthorityObservation,
    privacy: &'a Privacy,
}
impl AuthorityAttestation<'_> {
    pub fn permitted(&self) -> bool {
        self.check.permitted()
    }
    pub fn action_digest(&self) -> &str {
        self.check.action_digest.as_str()
    }
    pub fn nonce(&self) -> &str {
        self.check.nonce.as_str()
    }
    pub fn not_after_boot_ms(&self) -> u64 {
        self.check.usable_until_boot_ms
    }
    pub fn authority(&self) -> &AuthorityObservation {
        self.authority
    }
    pub fn privacy(&self) -> &Privacy {
        self.privacy
    }
    pub fn identity(&self) -> AuthorityIdentity<'_> {
        AuthorityIdentity {
            session: self.identity.session.as_str(),
            generation: self.identity.generation,
            companion_instance: self.identity.companion_instance.as_str(),
            endpoint_instance: self.identity.endpoint_instance.as_str(),
            control_generation: self.identity.control_generation,
        }
    }
}

/// An endpoint observation bound to this stream, action and original call deadline.
///
/// `permitted()` is a local freshness check, not HRC authorization or an atomic
/// transaction with remote authority. A remote change may remain unobserved.
pub struct AuthorityCheck {
    disposition: Disposition,
    receipt_disposition: Option<Disposition>,
    id: Id,
    nonce: Id,
    action_digest: Id,
    authority: Option<AuthorityObservation>,
    companion_started_boot_ms: u64,
    companion_deadline_boot_ms: u64,
    receipt_not_after_boot_ms: u64,
    usable_until_boot_ms: u64,
    lifecycle: Weak<Lifecycle>,
    epoch: u64,
    privacy: Option<Privacy>,
    receipt_identity: Option<ReceiptIdentity>,
}
impl AuthorityCheck {
    pub fn disposition(&self) -> Disposition {
        if self.authority.is_none() {
            return self.disposition;
        }
        let Some(life) = self.lifecycle.upgrade() else {
            return Disposition::NotActive;
        };
        let Ok(local) = lock(&life.state) else {
            return Disposition::NotActive;
        };
        if !local.active || local.epoch != self.epoch {
            return Disposition::NotActive;
        }
        if !ipc::boot_ms().is_ok_and(|n| n < self.usable_until_boot_ms) {
            return Disposition::Expired;
        }
        self.disposition
    }
    pub fn certified(&self) -> bool {
        self.authority.is_some()
    }
    pub fn authority(&self) -> Option<&AuthorityObservation> {
        self.authority.as_ref()
    }
    pub fn usable(&self) -> bool {
        self.remaining().is_some()
    }
    pub fn permitted(&self) -> bool {
        self.disposition == Disposition::Permitted && self.usable()
    }
    pub fn remaining(&self) -> Option<Duration> {
        self.authority.as_ref()?;
        let life = self.lifecycle.upgrade()?;
        let local = lock(&life.state).ok()?;
        if !local.active
            || local.epoch != self.epoch
            || !matches!(
                self.disposition,
                Disposition::Permitted | Disposition::Denied
            )
        {
            return None;
        }
        self.usable_until_boot_ms
            .checked_sub(ipc::boot_ms().ok()?)
            .filter(|n| *n > 0)
            .map(Duration::from_millis)
    }
    pub fn privacy(&self) -> Option<Privacy> {
        self.privacy.clone().map(|mut privacy| {
            if !self.usable() {
                privacy.mark_historical();
            }
            privacy
        })
    }
    pub fn attestation(&self) -> Option<AuthorityAttestation<'_>> {
        if !self.permitted() {
            return None;
        }
        Some(AuthorityAttestation {
            check: self,
            identity: self.receipt_identity.as_ref()?,
            authority: self.authority.as_ref()?,
            privacy: self.privacy.as_ref()?,
        })
    }
}
impl Serialize for AuthorityCheck {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        json!({"disposition":self.disposition(),"receiptDisposition":self.receipt_disposition,
            "id":self.id,"nonce":self.nonce,"actionDigest":self.action_digest,"authority":self.authority,
            "companionStartedBootMs":self.companion_started_boot_ms,"companionDeadlineBootMs":self.companion_deadline_boot_ms,
            "receiptNotAfterBootMs":self.receipt_not_after_boot_ms,"usableUntilBootMs":self.usable_until_boot_ms,
            "usableNow":self.usable(),"privacy":self.privacy()}).serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Reply {
    version: u64,
    ok: bool,
    id: Id,
    nonce: Id,
    action_digest: Id,
    result: Receipt,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    disposition: Disposition,
    caller_started_boot_ms: u64,
    caller_deadline_boot_ms: u64,
    not_after_boot_ms: u64,
    authority: Option<AuthorityObservation>,
    session: Option<Id>,
    generation: Option<u64>,
    companion_instance: Option<Id>,
    endpoint_instance: Option<Id>,
    control_generation: Option<u64>,
    kernel_boot: Option<String>,
    privacy: Option<Value>,
}
impl Companion {
    pub fn check_authority(
        &self,
        stream: &Stream,
        action_digest: [u8; 32],
        timeout: Duration,
    ) -> Result<AuthorityCheck> {
        let ms = ipc::timeout_ms(timeout, 5000, 100)?;
        let started = ipc::boot_ms()?;
        let deadline = started.checked_add(ms).ok_or(Error::Clock)?;
        self.check_authority_bounded(stream, action_digest, started, deadline)
    }
    /// Preserve an enclosing boot-time deadline through admission and local IPC.
    pub(crate) fn check_authority_until(
        &self,
        stream: &Stream,
        action_digest: [u8; 32],
        end: u64,
    ) -> Result<AuthorityCheck> {
        let started = ipc::boot_ms()?;
        let deadline = end.min(started.checked_add(5000).ok_or(Error::Clock)?);
        self.check_authority_bounded(stream, action_digest, started, deadline)
    }
    fn check_authority_bounded(
        &self,
        stream: &Stream,
        action_digest: [u8; 32],
        started: u64,
        deadline: u64,
    ) -> Result<AuthorityCheck> {
        let ms = deadline
            .checked_sub(started)
            .filter(|ms| (100..=5000).contains(ms))
            .ok_or(Error::Timeout)?;
        if action_digest == [0; 32] {
            return Err(Error::InvalidInput);
        }
        if !self.owns(stream) || stream.peer.direction() != Direction::Incoming {
            return Err(Error::NotActive);
        }
        let boot = ipc::unshifted_boot()?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        if nonce == [0; 32] {
            return Err(Error::Unavailable);
        }
        let nonce = Id::parse(&hex::encode(nonce))?;
        let action_digest = Id::parse(&hex::encode(action_digest))?;
        let (epoch, control) = {
            let state = lock(&self.state)?;
            let mut local = lock(&stream.life.state)?;
            if !local.active || !local.eligible {
                return Err(Error::NotActive);
            }
            local.invalidate();
            if !local.active {
                return Err(Error::NotActive);
            }
            (local.epoch, state.control.clone())
        };
        let reply = ipc::request(
            &self.directory,
            json!({"version":2,"action":"checkAuthority","id":stream.id(),"nonce":nonce,"actionDigest":action_digest,"timeoutMs":ms}),
            deadline,
        );
        let value = match reply {
            Ok((v, _)) => v,
            Err(Error::Timeout | Error::Closed | Error::Unavailable) => {
                return Ok(AuthorityCheck {
                    disposition: if ipc::boot_ms()? >= deadline {
                        Disposition::Expired
                    } else {
                        Disposition::Unavailable
                    },
                    receipt_disposition: None,
                    id: stream.id.clone(),
                    nonce,
                    action_digest,
                    authority: None,
                    companion_started_boot_ms: 0,
                    companion_deadline_boot_ms: 0,
                    receipt_not_after_boot_ms: 0,
                    usable_until_boot_ms: 0,
                    lifecycle: Arc::downgrade(&stream.life),
                    epoch,
                    privacy: None,
                    receipt_identity: None,
                });
            }
            Err(e) => return Err(e),
        };
        let reply: Reply = decode(value)?;
        if reply.version != 2
            || !reply.ok
            || reply.id != stream.id
            || reply.nonce != nonce
            || reply.action_digest != action_digest
        {
            return Err(Error::Protocol);
        }
        let receipt = reply.result;
        if receipt.caller_started_boot_ms < started
            || receipt.caller_started_boot_ms > ipc::boot_ms()?
            || receipt
                .caller_deadline_boot_ms
                .checked_sub(receipt.caller_started_boot_ms)
                != Some(ms)
            || receipt.not_after_boot_ms > receipt.caller_deadline_boot_ms
        {
            return Err(Error::Protocol);
        }
        let certified = matches!(
            receipt.disposition,
            Disposition::Permitted | Disposition::Denied
        );
        if certified != receipt.authority.is_some() {
            return Err(Error::Protocol);
        }
        if let Some(a) = &receipt.authority
            && ((a.code == 0) != (receipt.disposition == Disposition::Permitted)
                || a.expires_at_ms <= a.evaluated_at_ms
                || a.network.as_str() != stream.peer.network()
                || a.incarnation.as_str() != stream.peer.incarnation()
                || receipt.not_after_boot_ms <= receipt.caller_started_boot_ms)
        {
            return Err(Error::Protocol);
        }
        let identity = ControlIdentity(
            receipt.companion_instance.clone(),
            receipt.endpoint_instance.clone(),
            receipt.control_generation,
        );
        let has_identity = receipt.session.is_some()
            || receipt.generation.is_some()
            || receipt.companion_instance.is_some()
            || receipt.endpoint_instance.is_some()
            || receipt.control_generation.is_some()
            || receipt.kernel_boot.is_some();
        if has_identity {
            if receipt.session.as_ref().map(Id::as_str) != Some(stream.peer.session())
                || receipt.generation != Some(stream.peer.generation())
                || identity.0.is_none()
                || identity.1.is_none()
                || identity.2.is_none_or(|g| g == 0)
                || receipt.kernel_boot.as_deref() != Some(&boot)
            {
                return Err(Error::Protocol);
            }
        } else if certified || receipt.privacy.is_some() {
            return Err(Error::Protocol);
        }
        let privacy = receipt
            .privacy
            .map(|v| Privacy::parse(v, Direction::Incoming, false))
            .transpose()?;
        if has_identity && privacy.is_none() {
            return Err(Error::Protocol);
        }
        if certified
            && !privacy
                .as_ref()
                .is_some_and(|p| p.provenance() == super::Provenance::EndpointAttestedArrival)
        {
            return Err(Error::Protocol);
        }
        let receipt_identity = if certified {
            Some(ReceiptIdentity {
                session: receipt.session.ok_or(Error::Protocol)?,
                generation: receipt.generation.ok_or(Error::Protocol)?,
                companion_instance: receipt.companion_instance.ok_or(Error::Protocol)?,
                endpoint_instance: receipt.endpoint_instance.ok_or(Error::Protocol)?,
                control_generation: receipt.control_generation.ok_or(Error::Protocol)?,
            })
        } else {
            None
        };
        let mut state = lock(&self.state)?;
        let context_current = {
            let local = lock(&stream.life.state)?;
            local.active && local.epoch == epoch && state.control == control
        };
        if has_identity && context_current {
            state.observe(identity)?;
        }
        let mut local = lock(&stream.life.state)?;
        let mut usable_until = deadline.min(receipt.not_after_boot_ms);
        let disposition = if !context_current {
            usable_until = 0;
            Disposition::NotActive
        } else if certified && ipc::boot_ms()? >= usable_until {
            Disposition::Expired
        } else {
            receipt.disposition
        };
        if context_current && let Some(p) = &privacy {
            local.privacy = p.clone();
        }
        Ok(AuthorityCheck {
            disposition,
            receipt_disposition: Some(receipt.disposition),
            id: stream.id.clone(),
            nonce,
            action_digest,
            authority: receipt.authority,
            companion_started_boot_ms: receipt.caller_started_boot_ms,
            companion_deadline_boot_ms: receipt.caller_deadline_boot_ms,
            receipt_not_after_boot_ms: receipt.not_after_boot_ms,
            usable_until_boot_ms: usable_until,
            lifecycle: Arc::downgrade(&stream.life),
            epoch: local.epoch,
            privacy,
            receipt_identity,
        })
    }
}

impl Stream {
    /// Write at this observation's original absolute deadline. This checks only
    /// transport authority; callers must already authorize their own action.
    pub fn send_observed(&self, check: &AuthorityCheck, bytes: &[u8]) -> Result<()> {
        if bytes.len() > ipc::MAX_PAYLOAD {
            return Err(Error::Frame);
        }
        if !check
            .lifecycle
            .upgrade()
            .is_some_and(|l| Arc::ptr_eq(&l, &self.life))
            || !check.permitted()
        {
            return Err(Error::NotActive);
        }
        let _lease = self.lease(false)?;
        let result = ipc::send_checked(&self.socket()?, bytes, check.usable_until_boot_ms, || {
            check.permitted()
        });
        if result.is_err() {
            self.close();
        }
        result
    }
}
