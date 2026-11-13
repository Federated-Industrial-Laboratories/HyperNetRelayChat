// SPDX-License-Identifier: Apache-2.0
//! Enable enrolment only after the authenticated owner creates the retained community room.
use super::*;
pub(super) fn finish(directory: &Path, options: &Options) -> Result<()> {
    setup::verify(directory, options)?;
    if directory.join("Ready.json").exists() {
        return Ok(());
    }
    let mut client = crate::client::Client::open_offline(&directory.join("Owner/Profile"))?;
    let room = client.finish_host(directory, &options.nickname)?;
    drop(client);
    let registrar = files::key(&directory.join("Registrar.key"))?;
    let policy = crate::home::admission::Policy {
        enabled: true,
        registrar_key: Id::from_bytes(registrar.verifying_key().to_bytes()),
        rooms: vec![room],
        agents_enabled: options.agents_enabled,
        max_agents_per_operator: options.max_agents_per_operator,
    };
    service::live_admission::configure_host(&directory.join("Home"), policy)
        .map_err(|_| Error::Unconfirmed)?;
    exact(&directory.join("Ready.json"), &vec![room])
}
