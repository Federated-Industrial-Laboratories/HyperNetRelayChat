// SPDX-License-Identifier: Apache-2.0
//! Native-network creation, explicit consent review and saved host lifecycle.
use super::*;
use ops::network::{Configuration, Preview, Status};
pub(super) struct Form {
    config: Configuration,
    file: PathBuf,
    saved: Vec<PathBuf>,
    pub preview: Option<Preview>,
    pub status: Option<Status>,
    pub renewal: Option<Value>,
    renew_hours: u16,
    pub renew_until: u64,
    request: PathBuf,
    registration: PathBuf,
    agent: bool,
    operator: String,
    address: String,
    addresses: Vec<std::net::Ipv4Addr>,
    address_error: Option<String>,
}
impl Form {
    pub fn progress(&self) -> ops::Result<String> {
        ops::network::progress(&self.config).map_err(ops::failure)
    }
    pub fn installed(&mut self, value: &Value) {
        if let Some(path) = value["executable"].as_str() {
            match value["product"].as_str() {
                Some("HyperNet") => self.config.core = path.into(),
                Some("HyperNetSuite") => self.config.suite = path.into(),
                _ => {}
            }
        }
        if let Some(path) = value["publisher"].as_str() {
            self.config.publisher_key = path.into();
        }
        self.preview = None;
    }
    pub fn new() -> Self {
        let id = hrc::protocol::Id::random()
            .map(|v| v.as_hex()[..8].to_owned())
            .unwrap_or_else(|_| "network".into());
        let root = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/".into())
            .join(".hrc/n")
            .join(&id);
        let (addresses, address_error) = match ops::network::local_addresses() {
            Ok(addresses) => (addresses, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        Self {
            config: Configuration::at(root),
            file: ops::root().join("Networks").join(format!("{id}.json")),
            saved: ops::configurations("Networks").unwrap_or_default(),
            preview: None,
            status: None,
            renewal: None,
            renew_hours: 24,
            renew_until: 0,
            request: PathBuf::new(),
            registration: PathBuf::new(),
            agent: false,
            operator: String::new(),
            address: String::new(),
            addresses,
            address_error,
        }
    }
}
fn value<T: serde::Serialize>(v: T) -> ops::Result<Value> {
    serde_json::to_value(v).map_err(ops::failure)
}
impl Workspace {
    pub(super) fn network_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("HyperNets");
        ui.horizontal_wrapped(|ui| {
            if c::button(ui, "Join a HyperNet").clicked() {
                self.join_requested = true;
                self.visible = false;
            }
            if c::button(ui, "New HyperNet").clicked() {
                self.network = Form::new();
            }
            egui::ComboBox::from_id_salt("saved-networks")
                .selected_text("Saved networks")
                .show_ui(ui, |ui| {
                    for path in &self.network.saved {
                        if ui
                            .selectable_label(
                                false,
                                path.file_stem().unwrap_or_default().to_string_lossy(),
                            )
                            .clicked()
                        {
                            match ops::read_json::<Configuration>(path) {
                                Ok(config) => {
                                    self.network.address = config.advertised_address.to_string();
                                    self.network.config = config;
                                    self.network.file = path.clone();
                                    self.network.preview = None;
                                    self.network.status = None;
                                    self.network.renewal = None;
                                }
                                Err(error) => self.error = Some(error),
                            }
                        }
                    }
                });
        });
        ui.add_space(8.0);
        let before = serde_json::to_vec(&self.network.config).ok();
        let created = self.network.config.root.join("Hosting.json").exists();
        ui.add_enabled_ui(!created,|ui| {
        c::section(ui, "Network and owner", |ui| {
            field(ui, "Network name", &mut self.network.config.name);
            field(ui, "Your nickname", &mut self.network.config.nickname);
            path(
                ui,
                "Network folder",
                &mut self.network.config.root,
                &mut self.picker,
                "network-root",
                true,
            );
            path(
                ui,
                "Recovery folder",
                &mut self.network.config.recovery_directory,
                &mut self.picker,
                "network-recovery",
                true,
            );
            ui.checkbox(
                &mut self.network.config.same_organisation,
                "This computer operates both the relay and destination services",
            );
            c::muted_badge(
                ui,
                "Single host · 4 authority replicas · no host-failure redundancy",
            );
        });
        c::section(ui, "Native runtime", |ui| {
            path(
                ui,
                "Core 0.10.4",
                &mut self.network.config.core,
                &mut self.picker,
                "network-core",
                false,
            );
            path(
                ui,
                "Suite 0.10.3",
                &mut self.network.config.suite,
                &mut self.picker,
                "network-suite",
                false,
            );
            path(
                ui,
                "Publisher key",
                &mut self.network.config.publisher_key,
                &mut self.picker,
                "network-publisher",
                false,
            );
            path(
                ui,
                "chronyc",
                &mut self.network.config.chronyc,
                &mut self.picker,
                "network-chronyc",
                false,
            );
            path(
                ui,
                "Clock socket",
                &mut self.network.config.chrony_socket,
                &mut self.picker,
                "network-clock",
                false,
            );
        });
        c::section(ui, "Hosting consent", |ui| {
            c::field(ui, "Host interface", |ui| {
                ui.horizontal_wrapped(|ui| {
                    egui::ComboBox::from_id_salt("hosting-address")
                        .selected_text("Choose a host IPv4")
                        .width(240.0)
                        .show_ui(ui, |ui| {
                            for address in &self.network.addresses {
                                let value = address.to_string();
                                if ui.selectable_label(self.network.address == value, &value).clicked() {
                                    self.network.address = value;
                                }
                            }
                        });
                    if c::button(ui, "Refresh").clicked() {
                        match ops::network::local_addresses() {
                            Ok(addresses) => {
                                self.network.addresses = addresses;
                                self.network.address_error = None;
                            }
                            Err(error) => self.network.address_error = Some(error.to_string()),
                        }
                    }
                });
                if let Some(error) = &self.network.address_error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
            });
            field(ui, "Host IPv4", &mut self.network.address);
            if let Ok(address) = self.network.address.parse() {
                self.network.config.advertised_address = address;
                self.network.config.bind_address = address;
            }
            ui.horizontal(|ui| {
                ui.label("Relay port");
                ui.add(
                    egui::DragValue::new(&mut self.network.config.relay_port).range(1025..=65535),
                );
                ui.label("Hours");
                ui.add(
                    egui::DragValue::new(&mut self.network.config.lifetime_hours).range(1..=168),
                );
            });
            ui.small("Choose this host's reachable LAN or public IPv4. Isolated native containers cannot use loopback. Firewall and router settings remain operator-controlled.");
            ui.collapsing("Advanced limits", |ui| {
                ui.horizontal(|ui| {
                    ui.label("First authority port (four consecutive ports)");
                    ui.add(
                        egui::DragValue::new(&mut self.network.config.authority_first_port)
                            .range(1025..=65532),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("First private subnet 10.89.N.0");
                    ui.add(
                        egui::DragValue::new(&mut self.network.config.subnet_octet).range(0..=251),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Governance validity (days)");
                    ui.add(
                        egui::DragValue::new(&mut self.network.config.governance_days)
                            .range(7..=3650),
                    );
                });
                let r = &mut self.network.config.resources;
                ui.horizontal(|ui| {
                    ui.label("Memory per role (MiB)");
                    let mut mib = r.memory_bytes_per_role / 1048576;
                    if ui
                        .add(egui::DragValue::new(&mut mib).range(256..=8192))
                        .changed()
                    {
                        r.memory_bytes_per_role = mib * 1048576;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Storage per role (GiB)");
                    let mut gib = r.state_bytes_per_role / 1073741824;
                    if ui
                        .add(egui::DragValue::new(&mut gib).range(1..=1024))
                        .changed()
                    {
                        r.state_bytes_per_role = gib * 1073741824;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("CPU quota per role");
                    ui.add(egui::DragValue::new(&mut r.cpu_quota_per_role).range(10000..=800000));
                    ui.label("Processes");
                    ui.add(egui::DragValue::new(&mut r.pids_per_role).range(64..=1024));
                });
                ui.horizontal(|ui| {
                    ui.label("Endpoint streams");
                    ui.add(egui::DragValue::new(&mut r.endpoint_connections).range(1..=16));
                    ui.label("Relay streams");
                    ui.add(egui::DragValue::new(&mut r.relay_connections).range(2..=128));
                });
            });
        });
        });
        let valid_address = self
            .network
            .address
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(ops::network::valid_host_address);
        if !valid_address {
            ui.colored_label(
                ui.visuals().error_fg_color,
                "Choose a non-loopback LAN or public IPv4 assigned to this host before reviewing setup.",
            );
        }
        if before != serde_json::to_vec(&self.network.config).ok() || !valid_address {
            self.network.preview = None;
            self.network.renewal = None;
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    valid_address,
                    egui::Button::new("Save")
                        .min_size(egui::vec2(c::ACTION_WIDTH, c::CONTROL_HEIGHT)),
                )
                .clicked()
            {
                let config = self.network.config.clone();
                let file = self.network.file.clone();
                self.start(&ctx, "Save network", Completion::General, move |_| {
                    ops::private_json(&file, &config)?;
                    Ok(serde_json::json!({"status":"Saved","file":file}))
                });
                if !self.network.saved.contains(&self.network.file) {
                    self.network.saved.push(self.network.file.clone());
                }
            }
            if ui
                .add_enabled(
                    valid_address,
                    egui::Button::new("Review setup")
                        .min_size(egui::vec2(c::ACTION_WIDTH, c::CONTROL_HEIGHT)),
                )
                .clicked()
            {
                let config = self.network.config.clone();
                self.start(
                    &ctx,
                    "Check native hosting",
                    Completion::NetworkPreview,
                    move |cancel| {
                        value(ops::network::preview(&config, cancel).map_err(ops::failure)?)
                    },
                );
            }
            for (label, action) in [("Refresh", 0), ("Start", 1), ("Stop", 2)] {
                if c::button(ui, label).clicked() {
                    let config = self.network.config.clone();
                    self.start(&ctx, label, Completion::NetworkStatus, move |cancel| {
                        value(
                            match action {
                                0 => ops::network::status(&config, cancel),
                                1 => ops::network::start(&config, cancel),
                                _ => ops::network::stop(&config, cancel),
                            }
                            .map_err(ops::failure)?,
                        )
                    });
                }
            }
        });
        if let Some(preview) = self.network.preview.clone() {
            c::section(ui, "Review", |ui| {
                ui.horizontal_wrapped(|ui| {
                    c::readout(
                        ui,
                        "MEMORY",
                        &format!("{} MiB", preview.memory_admission_bytes / 1048576),
                    );
                    c::readout(
                        ui,
                        "STORAGE",
                        &format!("{} MiB", preview.storage_admission_bytes / 1048576),
                    );
                    c::readout(ui, "HOST REDUNDANCY", "None");
                });
                ui.label(&preview.privacy);
                for requirement in &preview.requirements {
                    ui.horizontal_wrapped(|ui| {
                        c::badge(
                            ui,
                            if requirement.ready {
                                "Ready"
                            } else {
                                "Required"
                            },
                            if requirement.ready {
                                egui::Color32::from_rgb(117, 201, 153)
                            } else {
                                ui.visuals().warn_fg_color
                            },
                        );
                        ui.strong(&requirement.component);
                        ui.label(&requirement.action);
                    });
                }
                if ui
                    .add_enabled(
                        preview.ready,
                        egui::Button::new("Approve and create")
                            .min_size(egui::vec2(c::ACTION_WIDTH, c::CONTROL_HEIGHT)),
                    )
                    .clicked()
                {
                    let config = self.network.config.clone();
                    let file = self.network.file.clone();
                    self.start(
                        &ctx,
                        "Create HyperNet",
                        Completion::NetworkStatus,
                        move |cancel| {
                            ops::private_json(&file, &config)?;
                            value(
                                ops::network::apply(&config, &preview.digest, cancel)
                                    .map_err(ops::failure)?,
                            )
                        },
                    );
                }
            });
        }
        if let Some(status) = self.network.status.clone() {
            c::section(ui, "Hosted network", |ui| {
                ui.horizontal_wrapped(|ui| {
                    c::readout(ui, "STATE", &status.state);
                    c::readout(
                        ui,
                        "QUORUM",
                        if status.quorum_verified {
                            "Verified"
                        } else {
                            "Unavailable"
                        },
                    );
                    c::readout(
                        ui,
                        "CLIENT",
                        if status.client_authenticated {
                            "Authenticated"
                        } else {
                            "Unavailable"
                        },
                    );
                });
                if c::primary(ui, "Open chat").clicked() {
                    self.open_profile = Some(status.profile.clone());
                }
            });
        }
        self.network_renewal(ui);
        self.network_admission(ui);
    }
    fn network_renewal(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.collapsing("Renew hosting consent", |ui| {
            if c::button(ui, "Resume renewal review").clicked() {
                let config = self.network.config.clone();
                self.start(&ctx, "Load retained renewal", Completion::RenewalPreview, move |cancel| {
                    value(ops::network::pending_renewal(&config, cancel).map_err(ops::failure)?)
                });
            }
            ui.horizontal(|ui| {
                ui.label("Requested hours from now");
                if ui
                    .add(egui::DragValue::new(&mut self.network.renew_hours).range(1..=168))
                    .changed()
                {
                    self.network.renewal = None;
                }
                if c::button(ui, "Review renewal").clicked() {
                    let until = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|v| v.as_millis() as u64)
                        .unwrap_or(0)
                        / 1000
                        * 1000
                        + u64::from(self.network.renew_hours) * 3600000;
                    self.network.renew_until = until;
                    let config = self.network.config.clone();
                    self.start(
                        &ctx,
                        "Review renewal",
                        Completion::RenewalPreview,
                        move |cancel| {
                            value(
                                ops::network::renewal_preview(&config, until, cancel)
                                    .map_err(ops::failure)?,
                            )
                        },
                    );
                }
            });
            if let Some(preview) = self.network.renewal.clone() {
                c::section(ui, "Renewal review", |ui| {
                    ui.label(format!("Hosting expires: {}", crate::display::timestamp(self.network.renew_until)));
                    if let Some(until) = preview["governanceExpiresMs"].as_u64() {
                        ui.label(format!("Governance expires: {}", crate::display::timestamp(until)));
                    }
                    c::muted_badge(ui, "Network, account and service identities preserved");
                    ui.label("Stop the host before renewal. Client route vouchers last at most 24 hours and may expire before hosting consent.");
                    if let Some(permissions) = preview["renewedPermissions"].as_array() {
                        for permission in permissions {
                            ui.separator();
                            let label = if permission["actions"] == serde_json::json!([29]) { "Manage service" } else { "Connect to service" };
                            ui.strong(label);
                            ui.label(format!("Principal: {}", permission["subject"].as_str().unwrap_or("Unavailable")));
                            ui.label(format!("Service: {}", permission["service"].as_str().unwrap_or("Unavailable")));
                        }
                    }
                    ui.collapsing("Native consent and artifact details", |ui| {
                        if let Ok(text) = serde_json::to_string_pretty(&preview) {
                            ui.add(egui::Label::new(egui::RichText::new(text).monospace()).wrap());
                        }
                    });
                });
                if let Some(digest) = preview
                    .get("digest")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    && c::primary(ui, "Approve renewal").clicked()
                {
                    let config = self.network.config.clone();
                    let until = self.network.renew_until;
                    self.start(
                        &ctx,
                        "Renew hosting",
                        Completion::NetworkStatus,
                        move |cancel| {
                            value(
                                ops::network::renew(&config, until, &digest, cancel)
                                    .map_err(ops::failure)?,
                            )
                        },
                    );
                }
            }
        });
    }
    fn network_admission(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        c::section(ui, "Invite a desktop or bot", |ui| {
            path(
                ui,
                "Network request",
                &mut self.network.request,
                &mut self.picker,
                "network-request",
                false,
            );
            ui.checkbox(&mut self.network.agent, "Agent account");
            if self.network.agent {
                field(ui, "Operator account", &mut self.network.operator);
            }
            ui.small("Admission briefly stops this HRC service, then restores it. Send the resulting bundle and fingerprint separately.");
            if c::primary(ui, "Create invitation").clicked() {
                let config = self.network.config.clone();
                let request = self.network.request.clone();
                let operator = self.network.agent.then(|| self.network.operator.clone());
                self.start(
                    &ctx,
                    "Create invitation",
                    Completion::General,
                    move |cancel| {
                        value(
                            ops::network::invite_client(
                                &config,
                                &request,
                                operator.as_deref(),
                                cancel,
                            )
                            .map_err(ops::failure)?,
                        )
                    },
                );
            }
            path(
                ui,
                "Registration",
                &mut self.network.registration,
                &mut self.picker,
                "network-registration",
                false,
            );
            if c::button(ui, "Activate account").clicked() {
                let config = self.network.config.clone();
                let registration = self.network.registration.clone();
                self.start(
                    &ctx,
                    "Activate account",
                    Completion::NetworkStatus,
                    move |cancel| {
                        value(
                            ops::network::enrol_client(&config, &registration, cancel)
                                .map_err(ops::failure)?,
                        )
                    },
                );
            }
        });
    }
}
