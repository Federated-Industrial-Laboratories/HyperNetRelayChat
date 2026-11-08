// SPDX-License-Identifier: Apache-2.0
//! Candidate-scoped grants and finite same-identifier native route generations.
use super::*;
use ciborium::Value as Cbor;
use state::{Admission, Candidate};

pub(super) fn root_grant(bootstrap: &Value) -> Result<String> {
    let grant = bootstrap["genesisGovernance"]["rootGrants"][0]["record"]["id"]
        .as_str()
        .ok_or(Error::State)?;
    if !is_id(grant) {
        return Err(Error::State);
    }
    Ok(grant.into())
}
fn wire(value: &Value, depth: usize) -> Result<Cbor> {
    if depth > 16 {
        return Err(Error::State);
    }
    Ok(match value {
        Value::Null => Cbor::Null,
        Value::Bool(value) => Cbor::Bool(*value),
        Value::Number(value) => Cbor::Integer(value.as_u64().ok_or(Error::State)?.into()),
        Value::String(value) => Cbor::Text(value.clone()),
        Value::Array(values) if values.len() <= 64 => Cbor::Array(
            values
                .iter()
                .map(|v| wire(v, depth + 1))
                .collect::<Result<_>>()?,
        ),
        Value::Object(map) if map.len() == 1 && map.contains_key("hex") => Cbor::Bytes(
            hex::decode(map["hex"].as_str().ok_or(Error::State)?).map_err(|_| Error::State)?,
        ),
        _ => return Err(Error::State),
    })
}
pub(super) fn record_digest(record: &Value) -> Result<String> {
    let bytes =
        hrc::protocol::canonical_encode(&wire(record, 0)?, 65536).map_err(|_| Error::State)?;
    let mut framed = b"HyperNet/RecordDigest/1\0".to_vec();
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend(bytes);
    Ok(digest(&framed))
}
pub(super) fn check_grant(
    config: &Config,
    admission: &Admission,
    candidate: &Candidate,
    connect: bool,
    value: &Value,
) -> Result<String> {
    let id = if connect {
        candidate.connect_grant.as_ref().ok_or(Error::State)?
    } else {
        &candidate.reader_grant
    };
    let fields = value["record"].as_array().ok_or(Error::State)?;
    let scope = if connect {
        json!([3, {"hex":config.application.service}])
    } else {
        json!([0, {"hex":admission.network}])
    };
    let actions = if connect { json!([30]) } else { json!([0, 6]) };
    if value["status"] != "GrantDelegated"
        || value["grant"] != *id
        || fields.len() != 17
        || fields[0] != 102
        || fields[1] != 1
        || fields[4] != 1
        || !fields[5].is_null()
        || fields[2] != json!({"hex":admission.network})
        || fields[3] != json!({"hex":admission.incarnation})
        || fields[6] != json!({"hex":id})
        || fields[8] != json!({"hex":candidate.principal})
        || fields[10] != actions
        || fields[11] != json!([scope])
        || fields[12] != json!([admission.not_before_ms, admission.access_expires_ms])
        || fields[14] != 0
        || fields[15] != json!([268435456_u64, 1024, 8, 16])
        || value["recordDigest"] != record_digest(&value["record"])?
    {
        return Err(Error::State);
    }
    Ok(format!("{id}:1:{}", string(value, "recordDigest")?))
}
pub(super) fn delegate(
    native: &native::Native<'_>,
    admission: &Admission,
    candidate: &Candidate,
    folder: &Path,
    root: &str,
    connect: bool,
) -> Result<String> {
    let label = if connect { "Connect" } else { "Reader" };
    let id = if connect {
        candidate.connect_grant.as_ref().ok_or(Error::State)?
    } else {
        &candidate.reader_grant
    };
    let mut arguments = args(&["authority-inspection", "delegate-grant"]);
    arguments.extend(native.online()?);
    arguments.extend(args(&[
        "--context-grant",
        root,
        "--parent",
        root,
        "--id",
        id,
        "--subject",
        &candidate.principal,
        "--actions",
        if connect { "30" } else { "0,6" },
        "--scopes",
        &format!(
            "{}:{}",
            if connect { 3 } else { 0 },
            if connect {
                &native.config.application.service
            } else {
                &admission.network
            }
        ),
        "--not-before-ms",
        &admission.not_before_ms.to_string(),
        "--expires-ms",
        &admission.access_expires_ms.to_string(),
        "--limits",
        "268435456",
        "1024",
        "8",
        "16",
    ]));
    let result = state::effect(native, folder, &format!("{label}Grant"), arguments, None)?;
    let reference = check_grant(native.config, admission, candidate, connect, &result)?;
    state::save(&folder.join(format!("{label}Grant.json")), &result)?;
    Ok(reference)
}
fn array(value: &Cbor) -> Result<&[Cbor]> {
    value.as_array().map(Vec::as_slice).ok_or(Error::State)
}
fn number(value: &Cbor) -> Result<u64> {
    value
        .as_integer()
        .and_then(|v| u64::try_from(v).ok())
        .ok_or(Error::State)
}
fn hex(value: &Cbor) -> Result<String> {
    value
        .as_bytes()
        .filter(|v| v.len() == 32)
        .map(hex::encode)
        .ok_or(Error::State)
}
pub(super) fn profile_expiry(route: &RouteConfig, network: &str, incarnation: &str) -> Result<u64> {
    let bytes = process::public_file(&route.profile, 32768).map_err(|_| Error::State)?;
    let outer = hrc::protocol::canonical_decode(&bytes, 32768).map_err(|_| Error::State)?;
    let outer = array(&outer)?;
    if outer.len() != 4 || number(&outer[0])? != 0 || number(&outer[1])? != 1 {
        return Err(Error::State);
    }
    let payload = outer[2].as_bytes().ok_or(Error::State)?;
    let payload = hrc::protocol::canonical_decode(payload, 32768).map_err(|_| Error::State)?;
    let fields = array(&payload)?;
    if fields.len() != 22
        || number(&fields[0])? != 200
        || number(&fields[1])? != 1
        || fields[2].as_text() != Some("AuthorityRouteProfile")
        || hex(&fields[3])? != network
        || hex(&fields[4])? != incarnation
    {
        return Err(Error::State);
    }
    // Field 6 is the service signing key; the route's logical ID belongs to its identity.
    let identity = array(&fields[11])?;
    if identity.len() != 5 || hex(&identity[0])? != route.service {
        return Err(Error::State);
    }
    let span = array(&fields[20])?;
    if span.len() != 2 || number(&span[0])? >= number(&span[1])? {
        return Err(Error::State);
    }
    // The native template command verifies this signed profile before any admission effect.
    number(&span[1])
}
#[derive(Debug)]
pub(super) struct Voucher {
    pub id: String,
    pub generation: u64,
    pub expiry: u64,
    pub possession: String,
    pub action: u64,
    pub network: String,
    pub incarnation: String,
    pub relay: String,
    pub destination: String,
}
pub(super) fn voucher(path: &Path) -> Result<Voucher> {
    let profile: Value = state::read(path)?;
    let bytes = profile["voucher"]
        .as_array()
        .ok_or(Error::State)?
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or(Error::State)
        })
        .collect::<Result<Vec<_>>>()?;
    let value = hrc::protocol::canonical_decode(&bytes, 65536).map_err(|_| Error::State)?;
    let fields = array(&value)?;
    if fields.len() != 8 || number(&fields[0])? != 166 || number(&fields[1])? != 1 {
        return Err(Error::State);
    }
    let payload = array(&fields[7])?;
    let payload = if payload.len() == 14 && number(&payload[0])? == 2 {
        &payload[1..12]
    } else {
        payload
    };
    if payload.len() != 11 {
        return Err(Error::State);
    }
    let relay = array(&payload[0])?;
    let destination = array(&payload[1])?;
    if relay.len() != 4 || destination.len() != 4 {
        return Err(Error::State);
    }
    Ok(Voucher {
        id: hex(&fields[6])?,
        generation: number(&fields[4])?,
        expiry: number(&payload[9])?,
        possession: hex(&payload[4])?,
        action: number(&payload[5])?,
        network: hex(&fields[2])?,
        incarnation: hex(&fields[3])?,
        relay: hex(&relay[1])?,
        destination: hex(&destination[1])?,
    })
}
pub(super) fn prepare_template(
    native: &native::Native<'_>,
    role: &str,
    output: &Path,
) -> Result<()> {
    if output.exists() {
        return Ok(());
    }
    let config = native.config;
    let destination = match role {
        "Authority" => &config.authority,
        "Application" => &config.application,
        "Page" => &config.reader.as_ref().ok_or(Error::State)?.content,
        _ => return Err(Error::State),
    };
    let mut arguments = args(&["routes", "template"]);
    arguments.extend(native.trust()?);
    arguments.extend(args(&[
        "--relay-profile",
        &text(&config.relay.profile)?,
        "--destination-profile",
        &text(&destination.profile)?,
        "--minimum-route",
        "Organisational",
        "--output",
        &text(output)?,
    ]));
    native.suite(&arguments)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn issue_route(
    native: &native::Native<'_>,
    admission: &Admission,
    candidate: &Candidate,
    root: &str,
    role: &str,
    folder: &Path,
    expiry: u64,
    prior: Option<&Path>,
    join: bool,
) -> Result<RouteDelivery> {
    let config = native.config;
    let (destination, subject) = match role {
        "Authority" => (&config.authority, &config.authority.service),
        "Application" => (&config.application, &config.application.service),
        "Page" => {
            let reader = config.reader.as_ref().ok_or(Error::State)?;
            (&reader.content, &reader.page_host_key)
        }
        _ => return Err(Error::State),
    };
    let name = if join { "Join" } else { role };
    let id = if join {
        &candidate.join
    } else if role == "Authority" {
        &candidate.authority
    } else {
        &candidate.destination
    };
    let output = folder.join(format!("{name}Route.json"));
    let template = folder.join(format!("{name}Template.json"));
    if prior.is_none() {
        prepare_template(native, role, &template)?;
    }
    let generation = prior
        .map(voucher)
        .transpose()?
        .map_or(Ok(1), |v| v.generation.checked_add(1).ok_or(Error::State))?;
    let mut arguments = args(&["routes", "issue"]);
    arguments.extend(native.online()?);
    let connections = if join { 8_u64 } else { 64 };
    arguments.extend(args(&[
        "--grant",
        root,
        "--id",
        id,
        "--relay",
        &config.relay.service,
        "--destination",
        &destination.service,
        "--possession",
        &candidate.relay,
        "--action",
        if join { "10" } else { "0" },
        "--scope",
        &admission.network,
        "--connections",
        &connections.to_string(),
        "--bytes",
        &(connections * 268_435_456).to_string(),
        "--expires-ms",
        &expiry.to_string(),
        "--route-template",
        &text(prior.unwrap_or(&template))?,
        "--output",
        &text(&output)?,
    ]));
    state::effect(
        native,
        folder,
        &format!("{name}Route"),
        arguments,
        Some(&output),
    )?;
    let actual = voucher(&output)?;
    if actual.id != *id
        || actual.generation != generation
        || actual.expiry != expiry
        || actual.possession != candidate.relay
        || actual.action != if join { 10 } else { 0 }
        || actual.network != admission.network
        || actual.incarnation != admission.incarnation
        || actual.relay != config.relay.service
        || actual.destination != destination.service
    {
        return Err(Error::State);
    }
    Ok(RouteDelivery {
        role: role.into(),
        subject: subject.clone(),
        artifact: state::artifact(&output)?,
        voucher_id: actual.id,
        generation,
        expires_ms: expiry,
    })
}
