// SPDX-License-Identifier: Apache-2.0
//! Explicit endpoint and separately held recovery-key operations for the native CLI.
use super::*;
use hrc::identity;
#[derive(Subcommand)]
pub enum Command {
    /// Export the pinned public service descriptor for explicit exchange with another device.
    Descriptor {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create a new separately held owner recovery key; existing files are never overwritten.
    KeyCreate {
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare private new-device state and its immutable signed admission request.
    Prepare {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        server: PathBuf,
        #[arg(long)]
        account: AccountId,
        #[arg(long)]
        principal: Id,
        #[arg(long,value_parser=["enrol","recover","rotate-recovery"])]
        purpose: String,
        #[arg(long)]
        replacement_key_file: Option<PathBuf>,
        #[arg(long)]
        request_output: PathBuf,
        #[command(flatten)]
        connection: Connection,
    },
    /// Authorize an exact proposed device with a current surviving controller.
    Authorize {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Prove the new admitted principal and key; recovery also needs the separately held owner key.
    Activate {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        recovery_key_file: Option<PathBuf>,
    },
    /// Inspect current eligible devices, public recovery key, revisions and continuity head.
    Devices {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: Option<AccountId>,
    },
    /// Disable an endpoint and invalidate its queued authority.
    Disable {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: Option<AccountId>,
        #[arg(long)]
        endpoint: Id,
    },
    /// Rotate the recovery key with current controller authority and replacement-key possession.
    Rotate {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: Option<AccountId>,
        #[arg(long)]
        replacement_key_file: PathBuf,
    },
    /// Inspect bounded continuity records; legacy service anchors are explicitly labelled.
    Continuity {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: Option<AccountId>,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u16).range(1..=16))]
        limit: u16,
    },
    /// Resolve an original lifecycle Action after its authorizing endpoint was disabled.
    Outcome {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        account: Option<AccountId>,
        #[arg(long)]
        window: Id,
        #[arg(long)]
        operation: Id,
        #[arg(long)]
        action_digest: Id,
    },
}
fn state(
    client: &mut client::Client,
    account: AccountId,
) -> Result<IdentitySnapshot, &'static str> {
    let response = client
        .call(
            Operation::AccountDevices,
            Target::Account(account),
            &home::Empty {},
        )
        .map_err(|_| "IdentityStateUnavailable")?;
    let Outcome::Result { body } = response.outcome else {
        return Err("IdentityStateUnavailable");
    };
    body.deserialized().map_err(|_| "IdentityStateInvalid")
}
fn effects(profile: &Path) -> Result<client::Client, &'static str> {
    let mut client = open(profile)?;
    if client
        .pending()
        .map_err(|_| "OutboxStorage")?
        .iter()
        .any(|p| !p.abandoned)
    {
        client.resolve_pending().map_err(|_| "OutcomeUnknown")?;
        if client
            .pending()
            .map_err(|_| "OutboxStorage")?
            .iter()
            .any(|p| !p.abandoned)
        {
            return Err("OutcomeUnknown");
        }
    }
    Ok(client)
}
pub fn run(command: Command) -> Result<Json, &'static str> {
    match command {
        Command::Descriptor { profile, output } => {
            let profile = client::Profile::load(&profile).map_err(|_| "ProfileUnavailable")?;
            service::files::create_json(&output, &profile.server)
                .map_err(|_| "DescriptorExportFailed")?;
            Ok(json!({"status":"DescriptorExported","home":profile.server.home}))
        }
        Command::KeyCreate { output } => {
            let key =
                service::files::create_key(&output).map_err(|_| "RecoveryKeyCreationFailed")?;
            Ok(
                json!({"status":"RecoveryKeyCreated","publicKey":Id::from_bytes(key.verifying_key().to_bytes())}),
            )
        }
        Command::Prepare {
            directory,
            server,
            account,
            principal,
            purpose,
            replacement_key_file,
            request_output,
            connection,
        } => {
            let purpose = match purpose.as_str() {
                "enrol" => DevicePurpose::Enrol,
                "recover" => DevicePurpose::Recover,
                "rotate-recovery" => DevicePurpose::RotateRecovery,
                _ => return Err("InvalidDevicePurpose"),
            };
            let clock = connection.clock();
            let pending = client::devices::prepare(client::devices::Prepare {
                directory: &directory,
                server: &server,
                account,
                principal,
                companion: connection.companion,
                clock,
                purpose,
                replacement: replacement_key_file.as_deref(),
                request_output: &request_output,
            })
            .map_err(|_| "DevicePreparationFailed")?;
            Ok(
                json!({"status":"DevicePrepared","account":account,"endpoint":pending.request.endpoint,"request":pending.request.request,"expiresMs":pending.request.expires_ms,"purpose":purpose}),
            )
        }
        Command::Activate {
            directory,
            recovery_key_file,
        } => json_value(
            client::devices::activate(&directory, recovery_key_file.as_deref()).map_err(
                |e| match e {
                    client::devices::Error::Configuration => "DeviceConfigurationUnavailable",
                    client::devices::Error::Authority => "DeviceAuthorityUnavailable",
                    client::devices::Error::Binding => "DeviceIdentityMismatch",
                    client::devices::Error::Unknown => "OutcomeUnknown",
                    client::devices::Error::Storage => "DeviceStorageUnavailable",
                    client::devices::Error::Refused(_) => "DeviceTransitionRefused",
                },
            )?,
        ),
        Command::Authorize { profile, request } => {
            let bytes = service::files::read(&request, ORDINARY_FRAME_BYTES)
                .map_err(|_| "DeviceRequestUnavailable")?;
            let request = verify_new_device(&bytes).map_err(|_| "DeviceRequestInvalid")?;
            let mut client = effects(&profile)?;
            let state = state(&mut client, request.value().account)?;
            call(
                &mut client,
                Operation::AccountEnrolEndpoint,
                Target::Account(state.account),
                &identity::ApproveEndpoint {
                    request: Blob(bytes),
                    revision: state.revision,
                    head: state.head.ok_or("ContinuityUnavailable")?,
                },
            )
        }
        Command::Devices { profile, account } => {
            let mut client = open(&profile)?;
            let account = account.unwrap_or(client.profile.registration.account);
            json_value(state(&mut client, account)?)
        }
        Command::Disable {
            profile,
            account,
            endpoint,
        } => {
            let mut client = effects(&profile)?;
            let account = account.unwrap_or(client.profile.registration.account);
            let state = state(&mut client, account)?;
            call(
                &mut client,
                Operation::AccountDisableEndpoint,
                Target::Account(account),
                &identity::DisableEndpoint {
                    endpoint,
                    revision: state.revision,
                    head: state.head.ok_or("ContinuityUnavailable")?,
                },
            )
        }
        Command::Rotate {
            profile,
            account,
            replacement_key_file,
        } => {
            if replacement_key_file.starts_with(&profile) {
                return Err("RecoveryKeyMustBeSeparate");
            }
            let key =
                service::files::key(&replacement_key_file).map_err(|_| "RecoveryKeyUnavailable")?;
            let mut client = effects(&profile)?;
            let account = account.unwrap_or(client.profile.registration.account);
            let state = state(&mut client, account)?;
            let proof = ReplacementKeyProof {
                home: client.profile.server.home,
                account,
                request: Id::random().map_err(|_| "RandomUnavailable")?,
                key: Id::from_bytes(key.verifying_key().to_bytes()),
            };
            let replacement =
                Blob(sign_replacement_key(&proof, &key).map_err(|_| "RecoveryKeyProof")?);
            call(
                &mut client,
                Operation::AccountRotateRecovery,
                Target::Account(account),
                &identity::RotateRecovery {
                    replacement,
                    revision: state.revision,
                    head: state.head.ok_or("ContinuityUnavailable")?,
                },
            )
        }
        Command::Continuity {
            profile,
            account,
            after,
            limit,
        } => {
            let mut client = open(&profile)?;
            let account = account.unwrap_or(client.profile.registration.account);
            call(
                &mut client,
                Operation::AccountContinuity,
                Target::Account(account),
                &identity::ContinuityPage { after, limit },
            )
        }
        Command::Outcome {
            profile,
            account,
            window,
            operation,
            action_digest,
        } => {
            let mut client = open(&profile)?;
            let account = account.unwrap_or(client.profile.registration.account);
            call(
                &mut client,
                Operation::AccountLifecycleOutcome,
                Target::Account(account),
                &home::Resolve {
                    operation_id: OperationId { window, operation },
                    action_digest,
                },
            )
        }
    }
}
