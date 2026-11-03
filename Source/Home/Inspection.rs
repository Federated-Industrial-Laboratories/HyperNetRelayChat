// SPDX-License-Identifier: Apache-2.0
//! Bounded inspection pagination uses identities as positions, never as authority.
use super::types::*;
use crate::protocol::*;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectPage {
    pub after: Option<String>,
    pub limit: u16,
}
impl Default for InspectPage {
    fn default() -> Self {
        Self {
            after: None,
            limit: 16,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectionPage<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}
pub(crate) fn request(action: &Action) -> Domain<InspectPage> {
    let body: InspectPage = unpack(&action.body)?;
    if !(1..=16).contains(&body.limit)
        || body
            .after
            .as_ref()
            .is_some_and(|a| a.len() > 512 || !a.is_ascii() || a.chars().any(char::is_control))
    {
        return invalid("InspectionPage");
    }
    Ok(body)
}
pub(crate) fn own(action: &Action) -> Domain<()> {
    if matches!(action.actor, Actor::Delegated { .. })
        || action.target != Target::Account(action.actor.acting().account)
    {
        return deny("PrivateInspection");
    }
    Ok(())
}
pub(crate) fn page_bounded<T: Serialize>(
    rows: Vec<(String, T)>,
    limit: u16,
    bytes: usize,
) -> Domain<Outcome> {
    let mut items = Vec::new();
    let mut last = None;
    let mut more = false;
    for (id, item) in rows {
        if items.len() >= usize::from(limit) {
            more = true;
            break;
        }
        items.push(item);
        if canonical_encode(&value(&items)?, bytes).is_err() {
            items.pop();
            more = true;
            break;
        }
        last = Some(id);
    }
    if more && items.is_empty() {
        return Err(Fault::Reject(ErrorCode::Overloaded, "InspectionItemSize"));
    }
    Ok(Outcome::Result {
        body: value(&InspectionPage {
            items,
            next: if more { last } else { None },
        })?,
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceInformation {
    pub motd: String,
}
impl ServiceInformation {
    pub fn new(motd: String) -> super::Result<Self> {
        if motd.len() > 1024 || (!motd.is_empty() && crate::text::message(&motd).is_err()) {
            return Err(super::Error::Invalid);
        }
        Ok(Self { motd })
    }
}
