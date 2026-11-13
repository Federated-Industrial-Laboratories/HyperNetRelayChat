// SPDX-License-Identifier: Apache-2.0
//! Host setup retains exact signed owner effects across uncertain process outcomes.
use super::{Client, Error, Result, outbox};
use crate::{conversations, home, identity, protocol::*, service::files};
use rusqlite::OptionalExtension;
use std::{path::Path, time::Duration};

fn exact<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| Error::Input)?;
    if path.exists() {
        if files::read(path, 16384).map_err(|_| Error::Storage)? != bytes {
            return Err(Error::Input);
        }
    } else {
        files::create(path, &bytes).map_err(|_| Error::Storage)?;
    }
    Ok(())
}
fn save_outcome(path: &Path, outcome: &Outcome) -> Result<()> {
    let value = Value::serialized(outcome).map_err(|_| Error::Input)?;
    let bytes = canonical_encode(&value, ORDINARY_FRAME_BYTES).map_err(|_| Error::Input)?;
    if path.exists() {
        if files::read(path, ORDINARY_FRAME_BYTES).map_err(|_| Error::Storage)? != bytes {
            return Err(Error::Input);
        }
    } else {
        files::create(path, &bytes).map_err(|_| Error::Storage)?;
    }
    Ok(())
}
impl Client {
    fn host_name_changed(&mut self) -> Result<bool> {
        self.host_connect()?;
        let response = self.call(
            Operation::AccountInspect,
            Target::Account(self.profile.registration.account),
            &home::Empty {},
        )?;
        let Outcome::Result { body } = response.outcome else {
            return Err(Error::from_outcome(response.outcome));
        };
        let account: identity::AccountView = body.deserialized().map_err(|_| Error::Input)?;
        let default = format!(
            "account-{}",
            &self.profile.registration.account.local.as_hex()[..12]
        );
        Ok(account.revision != 1 || account.nickname != default)
    }
    fn host_connect(&mut self) -> Result<()> {
        if self.session().is_err() {
            self.connect()?;
        }
        Ok(())
    }
    fn host_effect<T: serde::Serialize>(
        &mut self,
        directory: &Path,
        label: &str,
        operation: Operation,
        target: Target,
        body: &T,
    ) -> Result<Outcome> {
        let initial_revision = operation == Operation::AccountSetNickname;
        let saved = directory.join(format!("{label}.Outcome.cbor"));
        if saved.exists() {
            return canonical_decode(
                &files::read(&saved, ORDINARY_FRAME_BYTES).map_err(|_| Error::Storage)?,
                ORDINARY_FRAME_BYTES,
            )
            .map_err(|_| Error::Storage)?
            .deserialized()
            .map_err(|_| Error::Storage);
        }
        let path = directory.join(format!("{label}.Action.cbor"));
        let body = Value::serialized(body).map_err(|_| Error::Input)?;
        let bytes = if path.exists() {
            files::read(&path, ORDINARY_FRAME_BYTES).map_err(|_| Error::Storage)?
        } else {
            if self.pending()?.iter().any(|p| !p.abandoned && !p.held) {
                return Err(Error::Unknown);
            }
            self.host_connect()?;
            let mut action = self.prepare(operation, target.clone(), body.clone())?;
            if initial_revision {
                action.expected.insert(Revision::Account, 1);
            }
            let bytes = self.sign(&action)?;
            files::create(&path, &bytes).map_err(|_| Error::Storage)?;
            bytes
        };
        let verified =
            verify_action(&bytes, &self.key.verifying_key()).map_err(|_| Error::Input)?;
        let action = verified.action();
        if action.operation != operation
            || action.target != target
            || action.body != body
            || action.home != self.profile.server.home
            || action.actor.acting().account != self.profile.registration.account
            || initial_revision && action.expected.get(&Revision::Account) != Some(&1)
        {
            return Err(Error::Input);
        }
        // Recover a terminal local outcome before connect performs normal retention.
        let retained = self
            .store
            .read(Duration::from_secs(2), |db| {
                db.query_row(
                    "SELECT digest FROM client_outbox WHERE window=?1 AND operation=?2",
                    [
                        action.operation_id.window.as_hex(),
                        action.operation_id.operation.as_hex(),
                    ],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()
            })
            .map_err(|_| Error::Storage)?;
        if retained
            .as_ref()
            .is_some_and(|digest| digest.as_slice() != verified.digest().as_bytes())
        {
            return Err(Error::Input);
        }
        if retained.is_some()
            && let Some(outcome) =
                outbox::outcome(&mut self.store, action.operation_id, verified.digest())
                    .map_err(|_| Error::Storage)?
        {
            save_outcome(&saved, &outcome)?;
            return Ok(outcome);
        }
        self.host_connect()?;
        let response = if retained.is_some() {
            let response = self.retry_pending(action.operation_id, verified.digest())?;
            // Resolve replies wrap the original outcome. The normal outbox has
            // already verified its binding and stores that terminal outcome.
            if let Some(outcome) =
                outbox::outcome(&mut self.store, action.operation_id, verified.digest())
                    .map_err(|_| Error::Storage)?
            {
                save_outcome(&saved, &outcome)?;
                return Ok(outcome);
            }
            response
        } else {
            // A retained signed action is the only permitted submission, including
            // an interruption before outbox insertion. An expired window is not replaced.
            self.execute_signed(&bytes)?
        };
        if matches!(
            response.outcome,
            Outcome::Committed { .. } | Outcome::Rejected { .. }
        ) {
            save_outcome(&saved, &response.outcome)?;
        }
        Ok(response.outcome)
    }
    pub(crate) fn finish_host(&mut self, directory: &Path, nickname: &str) -> Result<RoomId> {
        crate::text::handle(nickname).map_err(|_| Error::Input)?;
        if self.profile.federation.is_some()
            || self.profile.registration.classification != AccountClass::Human
        {
            return Err(Error::Input);
        }
        let named = directory.join("Nickname.done");
        if !named.exists() {
            if !directory.join("Nickname.Action.cbor").exists() {
                if self.pending()?.iter().any(|p| !p.abandoned && !p.held) {
                    return Err(Error::Unknown);
                }
                if self.host_name_changed()? {
                    exact(&named, &true)?;
                }
            }
            if !named.exists() {
                let outcome = self.host_effect(
                    directory,
                    "Nickname",
                    Operation::AccountSetNickname,
                    Target::Account(self.profile.registration.account),
                    &identity::Nickname {
                        nickname: nickname.into(),
                    },
                )?;
                let renamed = matches!(
                    outcome,
                    Outcome::Rejected {
                        code: ErrorCode::Conflict,
                        ..
                    }
                ) && self.host_name_changed()?;
                if !matches!(outcome, Outcome::Committed { .. }) && !renamed {
                    return Err(Error::from_outcome(outcome));
                }
                exact(&named, &true)?;
            }
        } else if !files::json::<bool>(&named).map_err(|_| Error::Storage)? {
            return Err(Error::Input);
        }
        let outcome = self.host_effect(
            directory,
            "General",
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "general".into(),
                confidentiality: RoomConfidentiality::Community,
            },
        )?;
        let Outcome::Committed { body, .. } = outcome else {
            return Err(Error::from_outcome(outcome));
        };
        let room = body
            .deserialized::<crate::messaging::Committed>()
            .map_err(|_| Error::Input)?
            .room
            .ok_or(Error::Input)?;
        if room.home != self.profile.server.home {
            return Err(Error::Input);
        }
        Ok(room)
    }
}

#[cfg(test)]
#[path = "../../Tests/Client/HostSetup.rs"]
mod tests;
