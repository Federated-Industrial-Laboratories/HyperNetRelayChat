// SPDX-License-Identifier: Apache-2.0
//! Persist explicit chat connection changes through the Suite owner.
use crate::onboarding::{self, simple};
use eframe::egui;
use std::path::{Path, PathBuf};
#[derive(Default)]
pub(super) struct Runtime {
    profile: Option<PathBuf>,
    online: bool,
    job: Option<simple::Job<()>>,
}
impl Runtime {
    pub fn opened(&mut self, profile: &Path, online: bool) {
        self.job = None;
        self.profile = Some(profile.into());
        self.online = online;
    }
    pub fn poll(&mut self, online: bool, ctx: &egui::Context) -> Option<Result<bool, String>> {
        let result = self.job.as_ref().and_then(simple::Job::result);
        let outcome = result.as_ref().filter(|_| online == self.online).map(|r| {
            r.as_ref()
                .map(|()| self.online)
                .map_err(ToString::to_string)
        });
        if result.is_some() {
            self.job = None;
        }
        if online != self.online {
            self.job = None;
            self.online = online;
            if let Some(profile) = self.profile.clone() {
                self.job = Some(simple::Job::start(ctx, move |cancel| {
                    if simple::load(&profile)?.is_some() {
                        onboarding::prepare_existing(&profile, !online, cancel)?;
                    }
                    Ok(())
                }));
            }
        }
        outcome
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/SimpleRuntime.rs"]
mod tests;
