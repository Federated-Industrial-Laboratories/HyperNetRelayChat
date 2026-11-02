//! Directional context authenticated by the owner-private companion boundary.
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(super) struct Id(String);
impl Id {
    pub(super) fn parse(value: &str) -> Result<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Protocol);
        }
        Ok(Self(value.to_owned()))
    }
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Incoming,
    Outgoing,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "direction", content = "context", rename_all = "camelCase")]
pub enum Peer {
    Incoming(IncomingPeer),
    Outgoing(OutgoingPeer),
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingPeer {
    #[serde(flatten)]
    common: Common,
    principal: Id,
    grant: Id,
    grant_generation: u64,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutgoingPeer {
    #[serde(flatten)]
    common: Common,
    route: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Common {
    network: Id,
    incarnation: Id,
    service: Id,
    protocol: String,
    owner: Id,
    endpoint: Id,
    session: Id,
    generation: u64,
    expires_ms: u64,
    maximum_bytes: u64,
    duration_ms: u64,
    idle_ms: u64,
}
impl Peer {
    pub(super) fn parse(mut value: Value, direction: Direction) -> Result<Self> {
        let object = value.as_object_mut().ok_or(Error::Protocol)?;
        let extra = match direction {
            Direction::Incoming => {
                let principal = decode(object.remove("principal").ok_or(Error::Protocol)?)?;
                let grant = decode(object.remove("grant").ok_or(Error::Protocol)?)?;
                let generation = decode(object.remove("grantGeneration").ok_or(Error::Protocol)?)?;
                Some((principal, grant, generation))
            }
            Direction::Outgoing => None,
        };
        let route: Option<Id> = if direction == Direction::Outgoing {
            Some(decode(object.remove("route").ok_or(Error::Protocol)?)?)
        } else {
            None
        };
        let common: Common = decode(value)?;
        if !protocol_valid(&common.protocol)
            || common.maximum_bytes == 0
            || common.maximum_bytes > 1_073_741_824
            || common.duration_ms == 0
            || common.duration_ms > 3_600_000
            || common.idle_ms == 0
            || common.idle_ms > common.duration_ms
            || common.expires_ms == 0
        {
            return Err(Error::Protocol);
        }
        match (extra, route) {
            (Some((principal, grant, grant_generation)), None) => {
                Ok(Self::Incoming(IncomingPeer {
                    common,
                    principal,
                    grant,
                    grant_generation,
                }))
            }
            (None, Some(route)) => Ok(Self::Outgoing(OutgoingPeer { common, route })),
            _ => Err(Error::Protocol),
        }
    }
    fn common(&self) -> &Common {
        match self {
            Self::Incoming(p) => &p.common,
            Self::Outgoing(p) => &p.common,
        }
    }
    pub fn direction(&self) -> Direction {
        match self {
            Self::Incoming(_) => Direction::Incoming,
            Self::Outgoing(_) => Direction::Outgoing,
        }
    }
    pub fn service(&self) -> &str {
        self.common().service.as_str()
    }
    pub fn protocol(&self) -> &str {
        &self.common().protocol
    }
    pub fn network(&self) -> &str {
        self.common().network.as_str()
    }
    pub fn incarnation(&self) -> &str {
        self.common().incarnation.as_str()
    }
    pub fn session(&self) -> &str {
        self.common().session.as_str()
    }
    pub fn generation(&self) -> u64 {
        self.common().generation
    }
}
impl IncomingPeer {
    pub fn principal(&self) -> &str {
        self.principal.as_str()
    }
    pub fn grant(&self) -> &str {
        self.grant.as_str()
    }
    pub fn grant_generation(&self) -> u64 {
        self.grant_generation
    }
}

pub(super) fn protocol_valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic())
}
pub(super) fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|_| Error::Protocol)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key).ok_or(Error::Protocol)
}
fn string(v: &Value, key: &str) -> Result<String> {
    field(v, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or(Error::Protocol)
}
fn optional<T: serde::de::DeserializeOwned>(v: &Value, key: &str) -> Result<Option<T>> {
    v.get(key)
        .filter(|x| !x.is_null())
        .cloned()
        .map(decode)
        .transpose()
}
fn allowed(v: &Value, names: &[&str]) -> Result<()> {
    if v.as_object()
        .ok_or(Error::Protocol)?
        .keys()
        .any(|k| !names.contains(&k.as_str()))
    {
        return Err(Error::Protocol);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assurance {
    Organisation,
    Independent,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelayPath {
    Unknown,
    ApprovedAttachment,
    NestedTlsViaRelay,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Provenance {
    Unavailable,
    EndpointAttestedArrival,
    ObservedAuthenticatedTransport,
    Pending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportProtection {
    Tls13FinalService,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Privacy {
    historical: bool,
    direction: Direction,
    transport_authenticated: bool,
    relay_path: RelayPath,
    provenance: Provenance,
    tls: Option<String>,
    transport_protection: Option<TransportProtection>,
    relay_service: Option<Id>,
    destination_service: Option<Id>,
    selected_minimum: Option<Assurance>,
    configured_assurance: Option<Assurance>,
    endpoint_mode: Option<u64>,
    attachment_profile_digest: Option<Id>,
    certified_endpoint_profile: Option<ProfileEvidence>,
    physical_independence_verified: bool,
    profile_currentness_asserted: bool,
    end_to_end_message_encryption: &'static str,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileEvidence {
    profile_digest: Id,
    not_after_boot_ms: u64,
}
impl Privacy {
    pub(super) fn parse(v: Value, direction: Direction, compact: bool) -> Result<Self> {
        allowed(
            &v,
            &[
                "direction",
                "transport",
                "transportAuthenticated",
                "relayPath",
                "provenance",
                "tls",
                "transportProtection",
                "relayService",
                "destinationService",
                "selectedMinimum",
                "configuredAssurance",
                "endpointMode",
                "attachmentProfileDigest",
                "certifiedEndpointProfile",
                "certifiedRelayProfile",
                "physicalIndependenceVerified",
                "profileCurrentnessAsserted",
                "endToEndMessageEncryption",
            ],
        )?;
        if !compact
            && (decode::<Direction>(field(&v, "direction")?.clone())? != direction
                || string(&v, "transport")? != "HyperNet"
                || string(&v, "endToEndMessageEncryption")? != "applicationDefined")
        {
            return Err(Error::Protocol);
        }
        let authenticated = decode::<bool>(field(&v, "transportAuthenticated")?.clone())?;
        let relay_path = decode::<RelayPath>(field(&v, "relayPath")?.clone())?;
        let provenance = decode::<Provenance>(field(&v, "provenance")?.clone())?;
        for key in ["physicalIndependenceVerified", "profileCurrentnessAsserted"] {
            if optional::<bool>(&v, key)?.unwrap_or(false) || (!compact && v.get(key).is_none()) {
                return Err(Error::Protocol);
            }
        }
        if v.get("certifiedRelayProfile").is_some_and(|x| !x.is_null()) {
            return Err(Error::Protocol);
        }
        let result = Self {
            historical: false,
            direction,
            transport_authenticated: authenticated,
            relay_path,
            provenance,
            tls: optional(&v, "tls")?,
            transport_protection: optional(&v, "transportProtection")?,
            relay_service: optional(&v, "relayService")?,
            destination_service: optional(&v, "destinationService")?,
            selected_minimum: optional(&v, "selectedMinimum")?,
            configured_assurance: optional(&v, "configuredAssurance")?,
            endpoint_mode: optional(&v, "endpointMode")?,
            attachment_profile_digest: optional(&v, "attachmentProfileDigest")?,
            certified_endpoint_profile: v
                .get("certifiedEndpointProfile")
                .filter(|p| !p.is_null())
                .map(|p| {
                    allowed(
                        p,
                        if compact {
                            &["profileDigest", "notAfterBootMs"]
                        } else {
                            &[
                                "source",
                                "service",
                                "generation",
                                "recordDigest",
                                "profileDigest",
                                "endpointMode",
                                "evaluatedAtMs",
                                "expiresAtMs",
                                "notAfterBootMs",
                            ]
                        },
                    )?;
                    if !compact {
                        if string(p, "source")? != "certifiedServiceLookup" {
                            return Err(Error::Protocol);
                        }
                        decode::<Id>(field(p, "service")?.clone())?;
                        decode::<Id>(field(p, "recordDigest")?.clone())?;
                        decode::<u64>(field(p, "generation")?.clone())?;
                        decode::<u64>(field(p, "endpointMode")?.clone())?;
                        if decode::<u64>(field(p, "expiresAtMs")?.clone())?
                            <= decode::<u64>(field(p, "evaluatedAtMs")?.clone())?
                        {
                            return Err(Error::Protocol);
                        }
                    }
                    Ok(ProfileEvidence {
                        profile_digest: decode(field(p, "profileDigest")?.clone())?,
                        not_after_boot_ms: decode(field(p, "notAfterBootMs")?.clone())?,
                    })
                })
                .transpose()?,
            physical_independence_verified: false,
            profile_currentness_asserted: false,
            end_to_end_message_encryption: "applicationDefined",
        };
        match direction {
            Direction::Incoming => {
                if !authenticated
                    || result.tls.is_some()
                    || result.selected_minimum.is_some()
                    || result.configured_assurance.is_some()
                    || result.destination_service.is_some()
                    || result.certified_endpoint_profile.is_some()
                {
                    return Err(Error::Protocol);
                }
                match (
                    relay_path,
                    provenance,
                    result.endpoint_mode,
                    result.transport_protection,
                    result.relay_service.is_some(),
                    result.attachment_profile_digest.is_some(),
                ) {
                    (RelayPath::Unknown, Provenance::Unavailable, None, None, false, false) => {}
                    (
                        RelayPath::Unknown,
                        Provenance::EndpointAttestedArrival,
                        Some(2),
                        Some(TransportProtection::Tls13FinalService),
                        false,
                        false,
                    ) => {}
                    (
                        RelayPath::ApprovedAttachment,
                        Provenance::EndpointAttestedArrival,
                        Some(3),
                        Some(TransportProtection::Tls13FinalService),
                        true,
                        true,
                    ) => {}
                    _ => return Err(Error::Protocol),
                }
            }
            Direction::Outgoing => {
                if result.endpoint_mode.is_some()
                    || result.attachment_profile_digest.is_some()
                    || result.transport_protection.is_some()
                {
                    return Err(Error::Protocol);
                }
                if compact
                    && !authenticated
                    && relay_path == RelayPath::Unavailable
                    && provenance == Provenance::Pending
                {
                    if result.tls.is_some()
                        || result.relay_service.is_some()
                        || result.selected_minimum.is_some()
                        || result.configured_assurance.is_some()
                        || result.certified_endpoint_profile.is_some()
                    {
                        return Err(Error::Protocol);
                    }
                } else if !authenticated
                    || relay_path != RelayPath::NestedTlsViaRelay
                    || provenance != Provenance::ObservedAuthenticatedTransport
                    || result.tls.as_deref() != Some("TLS1.3")
                    || result.relay_service.is_none()
                    || (!compact && result.destination_service.is_none())
                    || result.selected_minimum.is_none()
                    || result.configured_assurance.is_none()
                    || matches!(
                        (result.selected_minimum, result.configured_assurance),
                        (Some(Assurance::Independent), Some(Assurance::Organisation))
                    )
                {
                    return Err(Error::Protocol);
                }
            }
        }
        Ok(result)
    }
    pub fn selected_minimum(&self) -> Option<Assurance> {
        self.selected_minimum
    }
    pub fn configured_assurance(&self) -> Option<Assurance> {
        self.configured_assurance
    }
    pub fn transport_protection(&self) -> Option<TransportProtection> {
        self.transport_protection
    }
    pub fn endpoint_mode(&self) -> Option<u64> {
        self.endpoint_mode
    }
    pub fn tls(&self) -> Option<&str> {
        self.tls.as_deref()
    }
    pub fn direction(&self) -> Direction {
        self.direction
    }
    /// Whether these facts describe a stream or control context known to be stale.
    pub fn is_historical(&self) -> bool {
        self.historical
    }
    pub(super) fn mark_historical(&mut self) {
        self.historical = true;
    }
    pub fn transport_authenticated(&self) -> bool {
        self.transport_authenticated
    }
    pub fn relay_path(&self) -> RelayPath {
        self.relay_path
    }
    pub fn provenance(&self) -> Provenance {
        self.provenance
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ControlIdentity(
    pub(super) Option<Id>,
    pub(super) Option<Id>,
    pub(super) Option<u64>,
);
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCapability {
    supported: bool,
    endpoint_ready: bool,
    capability: String,
    companion_instance: Option<Id>,
    endpoint_instance: Option<Id>,
    control_generation: Option<u64>,
}
impl AuthorityCapability {
    pub fn supported(&self) -> bool {
        self.supported
    }
    pub fn endpoint_ready(&self) -> bool {
        self.endpoint_ready
    }
    pub(super) fn identity(&self) -> ControlIdentity {
        ControlIdentity(
            self.companion_instance.clone(),
            self.endpoint_instance.clone(),
            self.control_generation,
        )
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    network: Id,
    incarnation: Id,
    principal: Id,
    incoming: bool,
    uptime_ms: u64,
    pub(super) check_authority: AuthorityCapability,
    pub(super) connections: Vec<ConnectionStatus>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatus {
    pub(super) id: Id,
    direction: Direction,
    pub(super) check_authority: bool,
    pub(super) privacy: Privacy,
}
impl Status {
    pub fn check_authority(&self) -> &AuthorityCapability {
        &self.check_authority
    }
    pub fn connections(&self) -> &[ConnectionStatus] {
        &self.connections
    }
    pub(super) fn parse(v: Value) -> Result<Self> {
        allowed(
            &v,
            &[
                "version",
                "ok",
                "status",
                "network",
                "incarnation",
                "principal",
                "binding",
                "uptimeMs",
                "incoming",
                "capabilities",
                "targets",
                "connections",
            ],
        )?;
        if string(&v, "status")? != "Ready" {
            return Err(Error::Protocol);
        }
        let c = field(&v, "capabilities")?;
        allowed(c, &["checkAuthority"])?;
        let capability: AuthorityCapability = decode(field(c, "checkAuthority")?.clone())?;
        if capability.capability != "checkAuthority-v2"
            || (capability.endpoint_ready
                && (!capability.supported
                    || capability.companion_instance.is_none()
                    || capability.endpoint_instance.is_none()
                    || capability.control_generation.is_none_or(|g| g == 0)))
        {
            return Err(Error::Protocol);
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Target {
            service: Id,
            protocol: String,
        }
        let targets: Vec<Target> = decode(field(&v, "targets")?.clone())?;
        if targets.len() > 16 || targets.iter().any(|t| !protocol_valid(&t.protocol)) {
            return Err(Error::Protocol);
        }
        for (i, target) in targets.iter().enumerate() {
            if targets[..i]
                .iter()
                .any(|t| t.service == target.service && t.protocol == target.protocol)
            {
                return Err(Error::Protocol);
            }
        }
        let incoming: bool = decode(field(&v, "incoming")?.clone())?;
        if let Some(binding) = field(&v, "binding")?.as_object() {
            allowed(
                &Value::Object(binding.clone()),
                &["service", "owner", "endpoint", "protocol"],
            )?;
            for name in ["service", "owner", "endpoint"] {
                decode::<Id>(binding.get(name).ok_or(Error::Protocol)?.clone())?;
            }
            if !incoming
                || !protocol_valid(
                    binding
                        .get("protocol")
                        .and_then(Value::as_str)
                        .ok_or(Error::Protocol)?,
                )
            {
                return Err(Error::Protocol);
            }
        } else if incoming || !field(&v, "binding")?.is_null() {
            return Err(Error::Protocol);
        }
        let entries = field(&v, "connections")?
            .as_array()
            .ok_or(Error::Protocol)?;
        if entries.len() > 16 {
            return Err(Error::Protocol);
        }
        let mut connections = Vec::with_capacity(entries.len());
        for entry in entries {
            allowed(
                entry,
                &["id", "direction", "service", "checkAuthority", "privacy"],
            )?;
            decode::<Id>(field(entry, "service")?.clone())?;
            let id: Id = decode(field(entry, "id")?.clone())?;
            if connections.iter().any(|c: &ConnectionStatus| c.id == id) {
                return Err(Error::Protocol);
            }
            let direction = decode(field(entry, "direction")?.clone())?;
            let check_authority: bool = decode(field(entry, "checkAuthority")?.clone())?;
            if check_authority && direction != Direction::Incoming {
                return Err(Error::Protocol);
            }
            connections.push(ConnectionStatus {
                id,
                direction,
                check_authority,
                privacy: Privacy::parse(field(entry, "privacy")?.clone(), direction, true)?,
            });
        }
        Ok(Self {
            network: decode(field(&v, "network")?.clone())?,
            incarnation: decode(field(&v, "incarnation")?.clone())?,
            principal: decode(field(&v, "principal")?.clone())?,
            incoming: decode(field(&v, "incoming")?.clone())?,
            uptime_ms: decode(field(&v, "uptimeMs")?.clone())?,
            check_authority: capability,
            connections,
        })
    }
}
