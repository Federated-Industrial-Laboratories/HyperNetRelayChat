// SPDX-License-Identifier: Apache-2.0
//! Export the optional external assistant without installing a model or granting authority.
#[path = "Assets.rs"]
mod assets;
#[path = "Installation.rs"]
mod installation;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Codex,
    Claude,
    Gemini,
    Copilot,
    Cursor,
}
impl Provider {
    pub const ALL: [Self; 5] = [
        Self::Codex,
        Self::Claude,
        Self::Gemini,
        Self::Copilot,
        Self::Cursor,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Copilot => "copilot",
            Self::Cursor => "cursor",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude Code",
            Self::Gemini => "Gemini CLI",
            Self::Copilot => "GitHub Copilot CLI",
            Self::Cursor => "Cursor",
        }
    }
    fn directories(self, scope: Scope) -> (&'static str, &'static str) {
        match (self, scope) {
            (Self::Codex, _) => (".agents/skills", ".codex/agents"),
            (Self::Claude, _) => (".claude/skills", ".claude/agents"),
            (Self::Gemini, _) => (".gemini/skills", ".gemini/agents"),
            (Self::Copilot, Scope::Workspace) => (".github/skills", ".github/agents"),
            (Self::Copilot, Scope::User) => (".copilot/skills", ".copilot/agents"),
            (Self::Cursor, _) => (".cursor/skills", ".cursor/agents"),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Workspace,
    User,
}

#[derive(clap::Args)]
pub struct Installation {
    #[arg(long, value_enum)]
    pub provider: Provider,
    /// Absolute workspace directory, or the user's home for user scope.
    #[arg(long)]
    pub destination: PathBuf,
    #[arg(long, value_enum, default_value = "workspace")]
    pub scope: Scope,
    /// Apply the displayed file plan; otherwise perform a read-only preview.
    #[arg(long)]
    pub apply: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// List provider formats, installation paths and qualification limits.
    Providers,
    /// Export skills and operator roles without changing shared provider settings.
    Install(Installation),
    /// Remove unchanged files owned by this harness; preserve edited files.
    Uninstall(Installation),
}

pub fn run(command: Command) -> Result<Value, &'static str> {
    match command {
        Command::Providers => Ok(providers()),
        Command::Install(options) => install_scoped(
            options.provider,
            options.scope,
            &options.destination,
            options.apply,
        ),
        Command::Uninstall(options) => uninstall_scoped(
            options.provider,
            options.scope,
            &options.destination,
            options.apply,
        ),
    }
}

pub fn providers() -> Value {
    let entries: Vec<_> = Provider::ALL
        .into_iter()
        .map(|provider| {
            let (skills, agents) = provider.directories(Scope::Workspace);
            let (user_skills, user_agents) = provider.directories(Scope::User);
            json!({"id": provider, "label": provider.label(),
            "workspace": {"skills": skills, "agents": agents},
            "user": {"skills": user_skills, "agents": user_agents}})
        })
        .collect();
    json!({"schema": 1, "providers": entries, "hooks": false,
        "compatibility": serde_json::from_str::<Value>(assets::COMPATIBILITY).ok()})
}

pub fn install_scoped(
    provider: Provider,
    scope: Scope,
    destination: &Path,
    apply: bool,
) -> Result<Value, &'static str> {
    installation::change(provider, scope, destination, apply, false)
}

pub fn uninstall_scoped(
    provider: Provider,
    scope: Scope,
    destination: &Path,
    apply: bool,
) -> Result<Value, &'static str> {
    installation::change(provider, scope, destination, apply, true)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Assistant/Installation.rs"]
mod tests;
