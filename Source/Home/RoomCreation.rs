// SPDX-License-Identifier: Apache-2.0
//! Local service policy for new rooms and direct conversations.
use super::{Error, Result};
use crate::protocol::{AccountId, Actor, NetworkId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum RoomCreationPolicy {
    /// Retain the existing creation rules for admitted accounts.
    #[default]
    All,
    /// Only these direct human accounts may create conversations.
    AllowList { accounts: Vec<AccountId> },
}
impl RoomCreationPolicy {
    pub fn validate(&self, network: NetworkId) -> Result<()> {
        if let Self::AllowList { accounts } = self
            && (accounts.len() > 32
                || accounts.iter().any(|account| account.origin != network)
                || accounts.iter().collect::<BTreeSet<_>>().len() != accounts.len())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn permits(&self, actor: &Actor) -> bool {
        match self {
            Self::All => true,
            Self::AllowList { accounts } => {
                matches!(actor, Actor::Direct { acting } if accounts.contains(&acting.account))
            }
        }
    }
}
