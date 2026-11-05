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
    Sync {
        #[command(flatten)]
        access: RoomAccess,
        /// Acknowledge a history gap while retaining encrypted content and MLS state.
        #[arg(long)]
        resynchronise: bool,
    },
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
        } => {
            let mut client = open(&profile)?;
            let response = client
                .crypto_initialise(room, recover)
                .map_err(|e| e.code())?;
            membership(&mut client, room, response)
        }
        Command::Commit {
            profile,
            room,
            add,
            remove,
        } => {
            let mut client = open(&profile)?;
            let response = client
                .crypto_commit(room, &add, &remove, None)
                .map_err(|e| e.code())?;
            membership(&mut client, room, response)
        }
        Command::Sync {
            access,
            resynchronise,
        } => {
            let mut client = open(&access.profile)?;
            let grant = access.grant()?;
            if resynchronise {
                client
                    .resynchronise_history(access.room)
                    .map_err(|e| e.code())?;
            }
            json_value(
                client
                    .crypto_sync(access.room, grant.as_ref())
                    .map_err(|e| e.code())?,
            )
        }
    }
}
fn membership(
    client: &mut client::Client,
    room: RoomId,
    response: Response,
) -> Result<Json, &'static str> {
    if !matches!(response.outcome, Outcome::Committed { .. }) {
        return Ok(json!({"response":json_value(response)?,"readiness":{"status":"NotStarted"}}));
    }
    let readiness = client.crypto_sync(room, None);
    let pending = client.pending().map(|pending| {
        pending
            .into_iter()
            .filter(|entry| {
                entry.action.action().operation == Operation::CryptoEpochReady
                    && entry.action.action().target == Target::Room(room)
            })
            .collect()
    });
    membership_report(response, readiness, pending)
}
fn problem(error: client::Error) -> Json {
    match error {
        client::Error::Rejected { code, detail } => json!({"code":code,"detail":detail}),
        client::Error::Refused {
            code,
            detail,
            retry_after_ms,
        } => json!({"code":code,"detail":detail,"retryAfterMs":retry_after_ms}),
        error => json!({"code":error.code()}),
    }
}
pub(crate) fn membership_report(
    response: Response,
    readiness: client::Result<client::CryptoView>,
    pending: client::Result<Vec<client::outbox::Pending>>,
) -> Result<Json, &'static str> {
    let readiness = match readiness {
        Ok(view) => {
            let ready = !view.remote.frozen
                && !view.remote.send_barrier
                && view.local.as_ref().is_some_and(|state| {
                    state.active && !state.frozen && state.epoch == view.remote.epoch
                });
            json!({"status":if ready {"Ready"} else {"Pending"},"view":json_value(view)?})
        }
        Err(error) => json!({"status":"Incomplete","error":problem(error),"resume":"crypto sync"}),
    };
    let pending = match pending {
        Ok(entries) => Json::Array(
            entries
                .into_iter()
                .map(|entry| {
                    Ok(
                        json!({"operationId":json_value(entry.action.action().operation_id)?,
                "actionDigest":entry.action.digest().as_hex(),
                "abandoned":entry.abandoned,
                "lastResponse":json_value(entry.last_response)?}),
                    )
                })
                .collect::<Result<Vec<_>, &'static str>>()?,
        ),
        Err(error) => json!({"unavailable":problem(error)}),
    };
    Ok(json!({"response":json_value(response)?,"readiness":readiness,"pendingReadiness":pending}))
}
