// SPDX-License-Identifier: Apache-2.0
//! Explicit service setup and shared conversation operations for people and agents.
use clap::{Args, Subcommand};
use hrc::{client, clock, conversations, delegation, home, messaging, protocol::*, service};
use serde_json::{Value as Json, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
};
type Result<T, E> = std::result::Result<T, E>;

#[derive(Subcommand)]
pub enum Draft {
    Save {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
        #[arg(long)]
        text: String,
    },
    Get {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
    },
}
pub fn draft(command: Draft) -> Result<Json, &'static str> {
    match command {
        Draft::Save {
            profile,
            room,
            text,
        } => {
            client::local::save_draft(&profile, room, &text).map_err(|_| "DraftStorage")?;
            Ok(json!({"status":"SavedLocally","room":room}))
        }
        Draft::Get { profile, room } => Ok(
            json!({"room":room,"draft":client::local::draft(&profile,room).map_err(|_|"DraftStorage")?}),
        ),
    }
}
pub fn outbox(profile: &Path) -> Result<Json, &'static str> {
    json_value(client::local::pending(profile).map_err(|_| "OutboxStorage")?)
}

#[derive(Subcommand)]
pub enum Service {
    /// Create a new home service. Existing directories are never reset.
    Init {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        network: Id,
        #[arg(long)]
        incarnation: Id,
        #[arg(long)]
        service: Id,
        #[arg(long, default_value = "")]
        motd: String,
        #[command(flatten)]
        connection: Connection,
    },
    /// Issue a one-use invitation for an admitted HyperNet application principal.
    Invite {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        principal: Id,
        #[arg(long)]
        operator: Option<AccountId>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Accept a signed endpoint registration while the service is stopped.
    Enrol {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        registration: PathBuf,
    },
    /// Serve native HRC operations through the configured HyperNet companion.
    Run {
        #[arg(long)]
        directory: PathBuf,
        /// Emit bounded session failure categories without conversation content.
        #[arg(long)]
        diagnostics: bool,
    },
}
#[derive(Args)]
pub struct Connection {
    #[arg(long)]
    companion: PathBuf,
    /// Signed HyperNet clock-export file.
    #[arg(long)]
    clock_observation: PathBuf,
    /// Pinned Ed25519 public key of the HyperNet clock monitor.
    #[arg(long)]
    clock_key: String,
}
impl Connection {
    fn clock(&self) -> clock::Config {
        clock::Config {
            observation: self.clock_observation.clone(),
            monitor_key: self.clock_key.clone(),
        }
    }
}
#[derive(Subcommand)]
pub enum Profile {
    /// Create a device; keep its owner recovery key outside the device directory.
    Create {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        recovery_key_file: PathBuf,
        #[arg(long)]
        registration_output: PathBuf,
        #[command(flatten)]
        connection: Connection,
    },
    /// Authenticate and show the exact account, endpoint, retry window and privacy state.
    Session {
        #[arg(long)]
        profile: PathBuf,
    },
}
#[derive(Subcommand)]
pub enum Room {
    List {
        #[arg(long)]
        profile: PathBuf,
    },
    Create {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        name: String,
    },
    Join {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
    },
    Leave {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
    },
    Topic {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        room: RoomId,
        #[arg(long)]
        text: String,
    },
}
#[derive(Args)]
pub struct Send {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    room: RoomId,
    #[arg(long)]
    text: String,
    #[arg(long)]
    reply: Option<Id>,
    /// Publish a typed /me action.
    #[arg(long)]
    action: bool,
    /// Explicit exported grant for delegated participation.
    #[arg(long)]
    grant: Option<PathBuf>,
    #[arg(long)]
    approval: Option<Id>,
    /// Save the exact signed candidate for review without sending it.
    #[arg(long)]
    prepare: Option<PathBuf>,
}
#[derive(Args)]
pub struct History {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long)]
    room: RoomId,
    #[arg(long,default_value_t=32,value_parser=clap::value_parser!(u16).range(1..=50))]
    limit: u16,
    /// Hexadecimal signed cursor from a previous response.
    #[arg(long)]
    cursor: Option<String>,
}
#[derive(Args)]
pub struct Search {
    #[command(flatten)]
    history: History,
    #[arg(long, required = true)]
    term: Vec<String>,
    #[arg(long)]
    sender: Option<AccountId>,
    #[arg(long)]
    represented: Option<AccountId>,
    #[arg(long)]
    from_ms: Option<u64>,
    #[arg(long)]
    until_ms: Option<u64>,
}
#[derive(Subcommand)]
pub enum Agent {
    /// Create a grant from a closed, structured permission document.
    Grant {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        permissions: PathBuf,
    },
    Inspect {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        export: Option<PathBuf>,
    },
    Pause {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
    },
    Resume {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
    },
    Revoke {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
    },
    /// Prepare the exact signed action for owner approval.
    Prepare {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        expires_ms: u64,
    },
    Approve {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        approval: Id,
        #[arg(long)]
        action_digest: Id,
    },
    Reject {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        grant: Id,
        #[arg(long)]
        generation: u64,
        #[arg(long)]
        approval: Id,
        #[arg(long)]
        action_digest: Id,
    },
}
#[derive(Args)]
pub struct Api {
    #[arg(long)]
    profile: PathBuf,
    /// Complete JSON Action. Its actor, retry window and revisions remain authoritative inputs.
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    sign_output: Option<PathBuf>,
}
fn json_value<T: serde::Serialize>(value: T) -> Result<Json, &'static str> {
    client::json::value(&value).map_err(|_| "Representation")
}
fn open(path: &Path) -> Result<client::Client, &'static str> {
    client::Client::open(path).map_err(|error| error.code())
}
fn call<T: serde::Serialize>(
    client: &mut client::Client,
    operation: Operation,
    target: Target,
    body: &T,
) -> Result<Json, &'static str> {
    json_value(
        client
            .call(operation, target, body)
            .map_err(|_| "OutcomeUnknown")?,
    )
}
pub fn service(command: Service) -> Result<Json, &'static str> {
    match command {
        Service::Init {
            directory,
            network,
            incarnation,
            service,
            motd,
            connection,
        } => {
            let clock = connection.clock();
            json_value(
                service::setup::create(
                    &directory,
                    ServiceId {
                        network: NetworkId {
                            network,
                            incarnation,
                        },
                        service,
                    },
                    connection.companion,
                    clock,
                    motd,
                )
                .map_err(|_| "ServiceSetupFailed")?,
            )
        }
        Service::Invite {
            directory,
            principal,
            operator,
            output,
        } => json_value(
            service::setup::invite(
                &directory,
                principal,
                operator.map_or(AccountClass::Human, |operator| AccountClass::Agent {
                    operator,
                }),
                &output,
            )
            .map_err(|_| "InvitationFailed")?,
        ),
        Service::Enrol {
            directory,
            registration,
        } => json_value(
            service::setup::enrol(&directory, &registration).map_err(|_| "EnrolmentFailed")?,
        ),
        Service::Run {
            directory,
            diagnostics,
        } => {
            service::runtime::run_with_ready(
                &directory,
                Arc::new(AtomicBool::new(false)),
                diagnostics,
                |descriptor| {
                    use std::io::Write;
                    let mut out = std::io::stdout().lock();
                    serde_json::to_writer(
                        &mut out,
                        &json!({"status":"Ready","home":descriptor.home}),
                    )
                    .map_err(|_| service::runtime::Error::State)?;
                    writeln!(out)
                        .and_then(|_| out.flush())
                        .map_err(|_| service::runtime::Error::State)
                },
            )
            .map_err(|error| error.code())?;
            Ok(json!({"status":"Stopped"}))
        }
    }
}
pub fn profile(command: Profile) -> Result<Json, &'static str> {
    match command {
        Profile::Create {
            directory,
            invitation,
            recovery_key_file,
            registration_output,
            connection,
        } => {
            let clock = connection.clock();
            let p = client::setup::create(
                &directory,
                &invitation,
                connection.companion,
                clock,
                &recovery_key_file,
                &registration_output,
            )
            .map_err(|_| "ProfileSetupFailed")?;
            Ok(
                json!({"status":"RegistrationRequired","account":p.registration.account,"endpoint":p.registration.endpoint,"home":p.server.home}),
            )
        }
        Profile::Session { profile } => {
            let c = open(&profile)?;
            Ok(
                json!({"status":"Authenticated","session":c.session().map_err(|_| "SessionUnavailable")?.ready,"privacy":c.session().map_err(|_| "SessionUnavailable")?.privacy()}),
            )
        }
    }
}
pub fn room(command: Room) -> Result<Json, &'static str> {
    match command {
        Room::List { profile } => call(
            &mut open(&profile)?,
            Operation::RoomList,
            Target::Service,
            &conversations::List {
                after: None,
                limit: 32,
            },
        ),
        Room::Create { profile, name } => call(
            &mut open(&profile)?,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name,
                confidentiality: RoomConfidentiality::Community,
            },
        ),
        Room::Join { profile, room } => call(
            &mut open(&profile)?,
            Operation::RoomJoin,
            Target::Room(room),
            &home::Empty {},
        ),
        Room::Leave { profile, room } => call(
            &mut open(&profile)?,
            Operation::RoomLeave,
            Target::Room(room),
            &home::Empty {},
        ),
        Room::Topic {
            profile,
            room,
            text,
        } => call(
            &mut open(&profile)?,
            Operation::RoomSetTopic,
            Target::Room(room),
            &conversations::Topic { topic: text },
        ),
    }
}
pub fn send(request: Send) -> Result<Json, &'static str> {
    client::local::save_draft(&request.profile, request.room, &request.text)
        .map_err(|_| "DraftStorage")?;
    let mut c = open(&request.profile)?;
    let operation = if request.action {
        Operation::MessageAction
    } else if request.reply.is_some() {
        Operation::MessageReply
    } else {
        Operation::MessageSend
    };
    let body = Value::serialized(&messaging::Send {
        mentions: Vec::new(),
        text: request.text,
        parent: request.reply,
        causation: None,
    })
    .map_err(|_| "InvalidInput")?;
    let mut action = c
        .prepare(operation, Target::Room(request.room), body)
        .map_err(|_| "InvalidInput")?;
    if let Some(path) = request.grant {
        let grant: delegation::Grant = service::files::json(&path).map_err(|_| "GrantFile")?;
        action.actor = Actor::Delegated {
            acting: c
                .session()
                .map_err(|_| "SessionUnavailable")?
                .ready
                .acting
                .clone(),
            operator: grant.operator,
            represented: grant.owner,
            represented_security_generation: grant.owner_security_generation,
            grant: grant.reference,
        };
    }
    action.approval = match (request.approval, request.prepare.is_some()) {
        (None, true) => Some(Id::random().map_err(|_| "RandomUnavailable")?),
        (value, _) => value,
    };
    if let Some(path) = request.prepare {
        return save_candidate(&c, &action, &path);
    }
    let response = c.execute(&action).map_err(|_| "OutcomeUnknown")?;
    if matches!(response.outcome, Outcome::Committed { .. }) {
        c.save_draft(request.room, "").map_err(|_| "DraftStorage")?;
    }
    json_value(response)
}
fn cursor(value: Option<String>) -> Result<Option<Blob>, &'static str> {
    value
        .map(|v| hex::decode(v).map(Blob).map_err(|_| "InvalidCursor"))
        .transpose()
}
pub fn history(h: History) -> Result<Json, &'static str> {
    call(
        &mut open(&h.profile)?,
        Operation::HistoryPage,
        Target::Room(h.room),
        &messaging::Page {
            cursor: cursor(h.cursor)?,
            limit: h.limit,
        },
    )
}
pub fn search(s: Search) -> Result<Json, &'static str> {
    call(
        &mut open(&s.history.profile)?,
        Operation::SearchQuery,
        Target::Room(s.history.room),
        &messaging::Search {
            terms: s.term,
            sender: s.sender,
            represented: s.represented,
            from_ms: s.from_ms,
            until_ms: s.until_ms,
            cursor: cursor(s.history.cursor)?,
            limit: s.history.limit,
        },
    )
}
pub fn agent(command: Agent) -> Result<Json, &'static str> {
    match command {
        Agent::Grant {
            profile,
            permissions,
        } => {
            let body: delegation::Create =
                service::files::json(&permissions).map_err(|_| "InvalidPermissions")?;
            let mut c = open(&profile)?;
            let owner = c
                .session()
                .map_err(|_| "SessionUnavailable")?
                .ready
                .acting
                .account;
            call(
                &mut c,
                Operation::DelegationCreate,
                Target::Account(owner),
                &body,
            )
        }
        Agent::Inspect {
            profile,
            grant,
            generation,
            export,
        } => {
            let response = open(&profile)?
                .call(
                    Operation::DelegationInspect,
                    Target::Delegation(GrantRef {
                        id: grant,
                        generation,
                    }),
                    &home::Empty {},
                )
                .map_err(|_| "OutcomeUnknown")?;
            let mut output = json_value(&response)?;
            if let Outcome::Result { body } = &response.outcome {
                let inspection: delegation::Inspection =
                    body.deserialized().map_err(|_| "InvalidResponse")?;
                if let Some(path) = export {
                    service::files::create_json(&path, &inspection.grant)
                        .map_err(|_| "ExportFailed")?;
                }
                let pending = output["outcome"]["body"]["pending"]
                    .as_array_mut()
                    .ok_or("InvalidResponse")?;
                if pending.len() != inspection.pending.len() {
                    return Err("InvalidResponse");
                }
                for (shown, record) in pending.iter_mut().zip(&inspection.pending) {
                    let action =
                        client::json::pending_action(record).map_err(|_| "InvalidResponse")?;
                    shown["proposedAction"] = json_value(&action)?;
                }
            } else if export.is_some() {
                return Err("GrantUnavailable");
            }
            Ok(output)
        }
        Agent::Pause {
            profile,
            grant,
            generation,
        } => call(
            &mut open(&profile)?,
            Operation::DelegationPause,
            Target::Delegation(GrantRef {
                id: grant,
                generation,
            }),
            &home::Empty {},
        ),
        Agent::Resume {
            profile,
            grant,
            generation,
        } => call(
            &mut open(&profile)?,
            Operation::DelegationResume,
            Target::Delegation(GrantRef {
                id: grant,
                generation,
            }),
            &home::Empty {},
        ),
        Agent::Revoke {
            profile,
            grant,
            generation,
        } => call(
            &mut open(&profile)?,
            Operation::DelegationRevoke,
            Target::Delegation(GrantRef {
                id: grant,
                generation,
            }),
            &home::Empty {},
        ),
        Agent::Prepare {
            profile,
            candidate,
            grant,
            generation,
            expires_ms,
        } => {
            let body = delegation::Prepare {
                candidate: Blob(
                    service::files::read(&candidate, CRYPTO_FRAME_BYTES)
                        .map_err(|_| "CandidateFile")?,
                ),
                expires_ms,
            };
            call(
                &mut open(&profile)?,
                Operation::ApprovalPrepare,
                Target::Delegation(GrantRef {
                    id: grant,
                    generation,
                }),
                &body,
            )
        }
        Agent::Approve {
            profile,
            grant,
            generation,
            approval,
            action_digest,
        } => call(
            &mut open(&profile)?,
            Operation::ApprovalApprove,
            Target::Delegation(GrantRef {
                id: grant,
                generation,
            }),
            &delegation::Decision {
                approval,
                action_digest,
            },
        ),
        Agent::Reject {
            profile,
            grant,
            generation,
            approval,
            action_digest,
        } => call(
            &mut open(&profile)?,
            Operation::ApprovalReject,
            Target::Delegation(GrantRef {
                id: grant,
                generation,
            }),
            &delegation::Decision {
                approval,
                action_digest,
            },
        ),
    }
}
pub fn api(request: Api) -> Result<Json, &'static str> {
    let bytes = service::files::read(&request.request, ORDINARY_FRAME_BYTES)
        .map_err(|_| "InvalidAction")?;
    let action = client::json::action(&bytes).map_err(|_| "InvalidAction")?;
    let mut c = open(&request.profile)?;
    if let Some(path) = request.sign_output {
        return save_candidate(&c, &action, &path);
    }
    json_value(c.execute(&action).map_err(|_| "OutcomeUnknown")?)
}
fn save_candidate(
    client: &client::Client,
    action: &Action,
    path: &Path,
) -> Result<Json, &'static str> {
    let bytes = client.sign(action).map_err(|_| "InvalidAction")?;
    service::files::create(path, &bytes).map_err(|_| "CandidateExport")?;
    Ok(
        json!({"status":"Prepared","operationId":action.operation_id,"actionDigest":action_digest(action).map_err(|_|"InvalidAction")?,"approval":action.approval}),
    )
}
pub fn submit(profile: &Path, candidate: &Path) -> Result<Json, &'static str> {
    let bytes = service::files::read(candidate, CRYPTO_FRAME_BYTES).map_err(|_| "CandidateFile")?;
    json_value(
        open(profile)?
            .execute_signed(&bytes)
            .map_err(|_| "OutcomeUnknown")?,
    )
}
pub fn resolve(profile: &Path) -> Result<Json, &'static str> {
    json_value(
        open(profile)?
            .resolve_pending()
            .map_err(|_| "OutcomeUnknown")?,
    )
}

#[derive(clap::Args)]
pub struct Abandon {
    #[arg(long)]
    pub profile: PathBuf,
    #[arg(long)]
    pub window: Id,
    #[arg(long)]
    pub operation: Id,
    #[arg(long)]
    pub action_digest: Id,
}
pub fn abandon(request: Abandon) -> Result<Json, &'static str> {
    let operation_id = OperationId {
        window: request.window,
        operation: request.operation,
    };
    client::local::abandon(&request.profile, operation_id, request.action_digest)
        .map_err(|_| "PendingOperationUnavailable")?;
    Ok(
        json!({"status":"RetryStoppedOutcomeUnknown","operationId":operation_id,"actionDigest":request.action_digest,"abandoned":true}),
    )
}
