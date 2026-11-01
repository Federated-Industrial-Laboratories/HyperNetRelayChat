// SPDX-License-Identifier: Apache-2.0
//! Explicit encrypted endpoint, contact trust and group lifecycle commands.
use super::*;
#[derive(Args)]
pub struct RoomAccess {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    room: RoomId,
    #[arg(long)]
    grant: Option<PathBuf>,
}
impl RoomAccess {
    fn grant(&self) -> Result<Option<delegation::Grant>, &'static str> {
        self.grant
            .as_ref()
            .map(|p| service::files::json(p).map_err(|_| "GrantFile"))
            .transpose()
    }
}
#[derive(Subcommand)]
pub enum Command {
    /// Register an independent MLS key for this authenticated endpoint.
    Enrol {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Show the exact current epoch, barrier, packages and contact trust.
    Inspect(RoomAccess),
    /// Inspect a contact's signed continuity before accepting its first trust anchor.
    Contact {
        #[command(flatten)]
        access: RoomAccess,
        #[arg(long)]
        account: AccountId,
    },
    /// Pin exactly the previously inspected public anchor; existing pins cannot be reset.
    Trust {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: AccountId,
        #[arg(long)]
        anchor: Id,
        #[arg(long)]
        legacy: bool,
    },
    /// Request admission of this endpoint to future encrypted traffic.
    Publish(RoomAccess),
    /// Initialise a one-member encrypted group, or explicitly recover into a fresh group.
    Initialise {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
        #[arg(long)]
        recover: bool,
    },
    /// Commit additions or removals; additions name published package digests.
    Commit {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
        #[arg(long)]
        add: Vec<Id>,
        #[arg(long)]
        remove: Vec<Id>,
    },
    /// Catch up and verify the ordered encrypted history for this endpoint.
    Sync(RoomAccess),
}
pub fn run(command: Command) -> Result<Json, &'static str> {
    match command {
        Command::Enrol { profile } => {
            json_value(open(&profile)?.crypto_enrol().map_err(|e| e.code())?)
        }
        Command::Inspect(access) => json_value(
            open(&access.profile)?
                .crypto_inspect(access.room, access.grant()?.as_ref())
                .map_err(|e| e.code())?,
        ),
        Command::Contact { access, account } => json_value(
            open(&access.profile)?
                .contact_trust(access.room, account, access.grant()?.as_ref())
                .map_err(|e| e.code())?,
        ),
        Command::Trust {
            profile,
            account,
            anchor,
            legacy,
        } => {
            open(&profile)?
                .trust_contact(account, anchor, legacy)
                .map_err(|e| e.code())?;
            Ok(json!({"status":"ContactTrusted","account":account,"anchor":anchor,"legacy":legacy}))
        }
        Command::Publish(access) => json_value(
            open(&access.profile)?
                .crypto_publish(access.room, access.grant()?.as_ref())
                .map_err(|e| e.code())?,
        ),
        Command::Initialise {
            profile,
            room,
            recover,
        } => json_value(
            open(&profile)?
                .crypto_initialise(room, recover)
                .map_err(|e| e.code())?,
        ),
        Command::Commit {
            profile,
            room,
            add,
            remove,
        } => json_value(
            open(&profile)?
                .crypto_commit(room, &add, &remove, None)
                .map_err(|e| e.code())?,
        ),
        Command::Sync(access) => {
            let mut client = open(&access.profile)?;
            let grant = access.grant()?;
            client
                .crypto_sync(access.room, grant.as_ref())
                .map_err(|e| e.code())?;
            json_value(
                client
                    .crypto_inspect(access.room, grant.as_ref())
                    .map_err(|e| e.code())?,
            )
        }
    }
}
