// SPDX-License-Identifier: Apache-2.0
//! Initial join naming uses the current store owner and ordinary revision-guarded effects.
use super::*;
const KEY: &str = "onboarding.initialNickname";
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    name: Option<String>,
    done: bool,
}
impl Worker {
    pub(super) fn initialize_nickname(&mut self, name: &str) -> Result<()> {
        crate::text::handle(name).map_err(|_| Error::Input)?;
        if self.client.profile.federation.is_some() {
            return Err(Error::Input);
        }
        let mut state: State =
            cache::preferences(&mut self.client.store, KEY).map_err(|_| Error::Storage)?;
        if state.done {
            return Ok(());
        }
        if state
            .name
            .as_deref()
            .is_some_and(|original| original != name)
        {
            return Err(Error::Input);
        }
        state.name = Some(name.into());
        cache::save_preferences(&mut self.client.store, KEY, &state).map_err(|_| Error::Storage)?;
        // Connect normally resolves uncertain outbox actions first. Direct callers may
        // not bypass that ordering and create a second initial-name action.
        if self
            .client
            .pending()?
            .iter()
            .any(|p| !p.abandoned && !p.held)
        {
            return Err(Error::Unknown);
        }
        let current: identity::AccountView = self.read(
            Operation::AccountInspect,
            Target::Account(self.snapshot.account),
            &home::Empty {},
        )?;
        let default_name = format!("account-{}", &self.snapshot.account.local.as_hex()[..12]);
        if current.revision == 1 && current.nickname == default_name {
            self.operation = Some(Operation::AccountSetNickname);
            self.delivery_room = None;
            let mut action = self.client.prepare(
                Operation::AccountSetNickname,
                Target::Account(self.snapshot.account),
                Value::serialized(&identity::Nickname {
                    nickname: name.into(),
                })
                .map_err(|_| Error::Input)?,
            )?;
            // A different endpoint/user rename between inspection and commit wins.
            action.expected.insert(Revision::Account, 1);
            self.remember(&action)?;
            let response = self.client.execute(&action)?;
            self.response(response)?;
            self.snapshot.nickname = name.into();
        } else {
            self.snapshot.nickname = current.nickname;
        }
        state.done = true;
        cache::save_preferences(&mut self.client.store, KEY, &state).map_err(|_| Error::Storage)?;
        Ok(())
    }
}
#[cfg(test)]
#[path = "../../Tests/Client/InitialNickname.rs"]
mod tests;
