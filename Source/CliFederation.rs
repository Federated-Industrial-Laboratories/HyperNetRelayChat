// SPDX-License-Identifier: Apache-2.0
//! Explicit owner-private federation administration; service state remains exclusively locked.
use super::*;
use hrc::federation::{self, AgreementPins, IdentityImport, TrustAnchor};
use serde::{Deserialize, de::DeserializeOwned};

#[derive(Subcommand)]
pub enum Command {
    /// Pin bilateral service evidence and optionally select its foreign room home.
    ClientSelect {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        home_descriptor: PathBuf,
        #[arg(long)]
        origin_descriptor: PathBuf,
        #[arg(long)]
        home_signature: PathBuf,
        #[arg(long)]
        origin_signature: PathBuf,
        #[arg(long)]
        trust_only: bool,
    },
    /// Select the original local service while retaining agreed remote trust pins.
    ClientLocal {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Create an independent gateway or attestor key; print its public key only.
    KeyCreate {
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign an exact proposed agreement as this service's administration.
    Sign {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Accept matching bilateral signatures against separately supplied trust pins.
    Accept {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        home_signature: PathBuf,
        #[arg(long)]
        origin_signature: PathBuf,
        #[arg(long)]
        pins: PathBuf,
    },
    /// Inspect an accepted revision, including its expired or withdrawn state.
    Inspect {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
    },
    /// Export this origin's signed public identity checkpoint for deliberate exchange.
    Checkpoint {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
        #[arg(long)]
        account: AccountId,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export one bounded signed page from an exact identity checkpoint.
    IdentityPage {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
        #[arg(long)]
        checkpoint: Id,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t=4, value_parser=clap::value_parser!(u16).range(1..=4))]
        limit: u16,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import signed origin evidence under an explicitly checked first-contact anchor.
    ImportIdentity {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        page: PathBuf,
        #[arg(long)]
        trust_anchor: Id,
        #[arg(long)]
        accept_legacy_anchor: bool,
    },
    /// Approve one exact foreign endpoint and room scope; identity import alone grants no access.
    Admit {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Stop new exchange for an exact agreement revision and establish its local barrier.
    Withdraw {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        agreement: PathBuf,
        /// Establish the local stop without attempting the home acknowledgement.
        #[arg(long)]
        local_only: bool,
    },
    /// Withdraw an exact endpoint admission revision.
    WithdrawEndpoint {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        admission: PathBuf,
    },
    /// Atomically install at most two explicit destination-companion routes while stopped.
    RoutesInstall {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        configuration: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pins {
    home: ServiceId,
    origin: ServiceId,
    home_key: Id,
    origin_key: Id,
    origin_attestor: Id,
}
fn read<T: DeserializeOwned>(path: &Path) -> Result<T, &'static str> {
    let bytes = service::files::read(path, ORDINARY_FRAME_BYTES)
        .map_err(|_| "FederationInputUnavailable")?;
    serde_json::from_slice(&bytes).map_err(|_| "FederationInputInvalid")
}
fn blob(path: &Path) -> Result<Blob, &'static str> {
    service::files::read(path, ORDINARY_FRAME_BYTES)
        .map(Blob)
        .map_err(|_| "FederationInputUnavailable")
}
fn open(directory: &Path) -> Result<(service::Config, home::Home), &'static str> {
    let config =
        service::Config::load(directory).map_err(|_| "FederationConfigurationUnavailable")?;
    let key = service::files::key(&directory.join("Signing.key"))
        .map_err(|_| "FederationConfigurationUnavailable")?;
    let store = config
        .store(directory)
        .map_err(|_| "FederationServiceMustBeStopped")?;
    let home = home::Home::open(store, config.descriptor.home, key)
        .map_err(|_| "FederationStateUnavailable")?;
    Ok((config, home))
}
fn failure(error: federation::Error) -> &'static str {
    match error {
        federation::Error::Refused {
            code: ErrorCode::Denied,
            ..
        } => "FederationDenied",
        federation::Error::Refused {
            code: ErrorCode::Expired,
            ..
        } => "FederationExpired",
        federation::Error::Refused {
            code: ErrorCode::Conflict,
            ..
        } => "FederationConflict",
        federation::Error::Refused {
            code: ErrorCode::Overloaded,
            ..
        } => "FederationCapacity",
        federation::Error::Protocol(_)
        | federation::Error::Refused {
            code: ErrorCode::InvalidInput,
            ..
        } => "FederationEvidenceInvalid",
        _ => "FederationUnavailable",
    }
}
pub fn run(command: Command) -> Result<Json, &'static str> {
    match command {
        Command::ClientLocal { directory } => {
            client::federation::select(&directory, None, false)
                .map_err(|_| "FederationClientSelectionFailed")?;
            Ok(json!({"status":"LocalServiceSelected"}))
        }
        Command::ClientSelect {
            directory,
            home_descriptor,
            origin_descriptor,
            home_signature,
            origin_signature,
            trust_only,
        } => {
            let home: service::Descriptor = read(&home_descriptor)?;
            let origin: service::Descriptor = read(&origin_descriptor)?;
            let home_signature = blob(&home_signature)?;
            let key = VerifyingKey::from_bytes(home.signing_key.as_bytes())
                .map_err(|_| "FederationEvidenceInvalid")?;
            let checked = verify_agreement(&home_signature.0, &key)
                .map_err(|_| "FederationEvidenceInvalid")?;
            let agreement = AgreementRef {
                id: checked.value().id,
                revision: checked.value().revision,
                digest: checked.digest(),
            };
            let selection = client::federation::Selection {
                home,
                origin,
                agreement,
                home_signature,
                origin_signature: blob(&origin_signature)?,
            };
            client::federation::select(&directory, Some(selection), !trust_only)
                .map_err(|_| "FederationClientSelectionFailed")?;
            Ok(
                json!({"status":if trust_only {"FederationTrustStored"} else {"ForeignHomeSelected"},"agreement":agreement}),
            )
        }
        Command::KeyCreate { output } => {
            let key =
                service::files::create_key(&output).map_err(|_| "FederationKeyCreationFailed")?;
            Ok(json!({"publicKey":Id::from_bytes(key.verifying_key().to_bytes())}))
        }
        Command::Sign {
            directory,
            agreement,
            output,
        } => {
            let (config, _home) = open(&directory)?;
            let value: FederationAgreement = read(&agreement)?;
            let signer = service::files::key(&directory.join("Signing.key"))
                .map_err(|_| "FederationConfigurationUnavailable")?;
            let key = Id::from_bytes(signer.verifying_key().to_bytes());
            if !((config.descriptor.home == value.home && key == value.home_service_key)
                || (config.descriptor.home == value.origin && key == value.origin_service_key))
            {
                return Err("FederationSignerMismatch");
            }
            let signed =
                sign_agreement(&value, &signer).map_err(|_| "FederationAgreementInvalid")?;
            let reference = verify_agreement(&signed, &signer.verifying_key())
                .map_err(|_| "FederationAgreementInvalid")?;
            service::files::create(&output, &signed).map_err(|_| "FederationOutputUnavailable")?;
            Ok(
                json!({"agreement":AgreementRef{id:value.id,revision:value.revision,digest:reference.digest()},"status":"SignedProposal"}),
            )
        }
        Command::Accept {
            directory,
            home_signature,
            origin_signature,
            pins,
        } => {
            let (config, mut home) = open(&directory)?;
            let pins: Pins = read(&pins)?;
            let pins = AgreementPins {
                home: pins.home,
                origin: pins.origin,
                home_key: pins.home_key,
                origin_key: pins.origin_key,
                origin_attestor: pins.origin_attestor,
            };
            json_value(
                home.federation_accept(
                    &blob(&home_signature)?.0,
                    &blob(&origin_signature)?.0,
                    &pins,
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?,
            )
        }
        Command::Inspect {
            directory,
            agreement,
        } => {
            let (_, mut home) = open(&directory)?;
            json_value(
                home.federation_inspect(read(&agreement)?)
                    .map_err(failure)?,
            )
        }
        Command::Checkpoint {
            directory,
            agreement,
            account,
            output,
        } => {
            let (config, mut home) = open(&directory)?;
            let bytes = home
                .federation_checkpoint(
                    account,
                    read(&agreement)?,
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?;
            service::files::create(&output, &bytes.0).map_err(|_| "FederationOutputUnavailable")?;
            let key = VerifyingKey::from_bytes(config.descriptor.signing_key.as_bytes())
                .map_err(|_| "FederationConfigurationUnavailable")?;
            let checkpoint = verify_origin_identity_checkpoint(&bytes.0, &key)
                .map_err(|_| "FederationEvidenceInvalid")?;
            Ok(
                json!({"checkpoint":checkpoint.digest(),"anchor":checkpoint.value().anchor_digest,"head":checkpoint.value().head,"records":checkpoint.value().records}),
            )
        }
        Command::IdentityPage {
            directory,
            agreement,
            checkpoint,
            after,
            limit,
            output,
        } => {
            let (config, mut home) = open(&directory)?;
            let bytes = home
                .federation_identity_page(
                    read(&agreement)?,
                    checkpoint,
                    after,
                    limit,
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?;
            service::files::create(&output, &bytes.0).map_err(|_| "FederationOutputUnavailable")?;
            let key = VerifyingKey::from_bytes(config.descriptor.signing_key.as_bytes())
                .map_err(|_| "FederationConfigurationUnavailable")?;
            let page = verify_origin_identity_page(&bytes.0, &key)
                .map_err(|_| "FederationEvidenceInvalid")?;
            Ok(
                json!({"checkpoint":checkpoint,"next":page.value().next,"complete":page.value().complete}),
            )
        }
        Command::ImportIdentity {
            directory,
            agreement,
            checkpoint,
            page,
            trust_anchor,
            accept_legacy_anchor,
        } => {
            let (config, mut home) = open(&directory)?;
            let complete = home
                .federation_import_identity(
                    read(&agreement)?,
                    &IdentityImport {
                        checkpoint: blob(&checkpoint)?,
                        page: blob(&page)?,
                        trust_anchor: Some(TrustAnchor {
                            anchor: trust_anchor,
                            legacy: accept_legacy_anchor,
                        }),
                    },
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?;
            Ok(json!({"complete":complete}))
        }
        Command::Admit { directory, request } => {
            let (config, mut home) = open(&directory)?;
            json_value(
                home.federation_admit(
                    &read(&request)?,
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?,
            )
        }
        Command::Withdraw {
            directory,
            agreement,
            local_only,
        } => {
            let (config, mut home) = open(&directory)?;
            let reference = read(&agreement)?;
            let mut state = home
                .federation_withdraw(
                    reference,
                    config.clock.sample().map_err(|_| "ClockUnavailable")?,
                )
                .map_err(failure)?;
            drop(home);
            let mut notification_error = None;
            if state.barrier_position.is_none() && !local_only {
                match service::runtime::notify_federation_withdrawal(&directory, reference) {
                    Ok(acknowledged) => state = acknowledged,
                    Err(error) => notification_error = Some(error.code()),
                }
            }
            Ok(
                json!({"status":if state.barrier_position.is_some() { "HomeWithdrawalAcknowledged" } else { "StoppedLocally" },
                "agreement":state.reference,"homeBarrier":state.barrier_position,"notificationError":notification_error}),
            )
        }
        Command::WithdrawEndpoint {
            directory,
            admission,
        } => {
            let (config, mut home) = open(&directory)?;
            home.federation_withdraw_endpoint(
                read(&admission)?,
                config.clock.sample().map_err(|_| "ClockUnavailable")?,
            )
            .map_err(failure)?;
            Ok(json!({"status":"WithdrawnLocally"}))
        }
        Command::RoutesInstall {
            directory,
            configuration,
        } => {
            let count = service::federation::install(&directory, &configuration)
                .map_err(|_| "FederationRouteConfigurationUnavailable")?;
            Ok(json!({"routes":count,"status":"InstalledWhileStopped"}))
        }
    }
}
