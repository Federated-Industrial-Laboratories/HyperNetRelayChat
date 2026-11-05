// SPDX-License-Identifier: Apache-2.0
//! Bounded lifecycle propagation and exact-head freshness for foreign encrypted recipients.
use super::*;

pub(in crate::service::runtime) struct Maintenance {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
struct PendingTurns<'a>(&'a [OutboundRoute]);
impl Drop for PendingTurns<'_> {
    fn drop(&mut self) {
        for route in self.0 {
            route.admission.cancel_maintenance();
        }
    }
}
impl Maintenance {
    pub(in crate::service::runtime) fn start(shared: Arc<Shared>) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = if shared.federation_routes.is_empty() {
            None
        } else {
            Some(
                thread::Builder::new()
                    .name("hrc-origin-freshness".into())
                    .spawn(move || {
                        let _pending = PendingTurns(&shared.federation_routes);
                        while !flag.load(Ordering::Acquire) && !shared.stop.load(Ordering::Acquire)
                        {
                            for route in &shared.federation_routes {
                                if flag.load(Ordering::Acquire)
                                    || shared.stop.load(Ordering::Acquire)
                                {
                                    break;
                                }
                                let _turn = match route.admission.maintenance(|| {
                                    flag.load(Ordering::Acquire)
                                        || shared.stop.load(Ordering::Acquire)
                                }) {
                                    Ok(Some(turn)) => turn,
                                    Ok(None) => continue,
                                    Err(error) => {
                                        shared.report(
                                            "FederationFreshnessUnavailable",
                                            admission_error(error).code(),
                                        );
                                        continue;
                                    }
                                };
                                // Keep the connection exclusively owned through each complete reply.
                                let Ok(mut outbound) = route.outbound.try_lock() else {
                                    shared.report(
                                        "FederationFreshnessUnavailable",
                                        Error::State.code(),
                                    );
                                    continue;
                                };
                                if let Err(error) = tick(&shared, &mut outbound, &flag) {
                                    shared.report("FederationFreshnessUnavailable", error.code());
                                    outbound.failed(&error);
                                }
                            }
                            // Sleep is short and bounded; shutdown never waits for a fresh periodic cycle.
                            for _ in 0..10 {
                                if flag.load(Ordering::Acquire)
                                    || shared.stop.load(Ordering::Acquire)
                                {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(50));
                            }
                        }
                    })
                    .map_err(|_| Error::State)?,
            )
        };
        Ok(Self { stop, worker })
    }
}
impl Drop for Maintenance {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn tick(shared: &Shared, outbound: &mut Outbound, stop: &AtomicBool) -> Result<()> {
    if stop.load(Ordering::Acquire) || shared.stop.load(Ordering::Acquire) {
        return Err(Error::AuthorityAdmissionStopped);
    }
    let reference = outbound.route.agreement;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let (state, dirty, page) = {
        let mut home = shared
            .home
            .try_lock()
            .map_err(|_| Error::AuthorityAdmissionBusy)?;
        let state = home
            .federation_inspect(reference)
            .map_err(|_| Error::State)?;
        if state.withdrawn
            || !now.permits(state.agreement.not_before_ms, state.agreement.expires_ms)
        {
            return Ok(());
        }
        let dirty = home
            .federation_watched(reference, true, None, 4, now)
            .map_err(domain_error)?;
        let page = home
            .federation_watched(reference, false, outbound.watch_after, 32, now)
            .map_err(domain_error)?;
        (state, dirty, page)
    };
    if dirty.items.is_empty() && page.items.is_empty() {
        outbound.watch_after = None;
        return Ok(());
    }
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 4000;
    if stop.load(Ordering::Acquire) || shared.stop.load(Ordering::Acquire) {
        return Err(Error::AuthorityAdmissionStopped);
    }
    outbound.connect(shared, &state.agreement, end)?;
    for account in dirty.items.iter().map(|item| item.account) {
        if stop.load(Ordering::Acquire) || remaining(end)?.as_millis() < 200 {
            return Ok(());
        }
        if sync(shared, outbound, &state.agreement, account, end)?.is_none() {
            return Ok(());
        }
    }
    let mut references = Vec::new();
    for account in page.items.iter().map(|item| item.account) {
        if stop.load(Ordering::Acquire) || remaining(end)?.as_millis() < 200 {
            break;
        }
        if let Some(reference) = sync(shared, outbound, &state.agreement, account, end)? {
            references.push(reference);
        } else {
            break;
        }
    }
    references.sort_by_key(|reference| reference.account);
    if !references.is_empty() {
        renew(shared, outbound, &state.agreement, &references, end)?;
    }
    // If a large proof consumed the cycle, retain the page until it can be completed.
    if references.len() == page.items.len() {
        outbound.watch_after = page.next;
    }
    Ok(())
}

fn sync(
    shared: &Shared,
    outbound: &mut Outbound,
    agreement: &FederationAgreement,
    account: AccountId,
    end: u64,
) -> Result<Option<CheckpointRef>> {
    let signed = shared
        .home
        .try_lock()
        .map_err(|_| Error::AuthorityAdmissionBusy)?
        .federation_checkpoint(
            account,
            outbound.route.agreement,
            shared.config.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(domain_error)?;
    let checkpoint = verify_origin_identity_checkpoint(&signed.0, &shared.signer.verifying_key())
        .map_err(|_| Error::Authentication)?;
    let reference = CheckpointRef {
        account,
        checkpoint_digest: checkpoint.digest(),
    };
    if outbound.synchronized.get(&account) == Some(&checkpoint.digest()) {
        return Ok(Some(reference));
    }
    if outbound.synchronized.len() >= 256 && !outbound.synchronized.contains_key(&account) {
        return Err(Error::RateLimited);
    }
    let mut after = outbound
        .import_progress
        .get(&account)
        .filter(|(digest, _)| *digest == checkpoint.digest())
        .map_or(0, |(_, after)| *after);
    loop {
        if remaining(end)?.as_millis() < 200 {
            return Ok(None);
        }
        let page = shared
            .home
            .try_lock()
            .map_err(|_| Error::AuthorityAdmissionBusy)?
            .federation_identity_page(
                outbound.route.agreement,
                checkpoint.digest(),
                after,
                4,
                shared.config.clock.sample().map_err(|_| Error::Clock)?,
            )
            .map_err(domain_error)?;
        let verified = verify_origin_identity_page(&page.0, &shared.signer.verifying_key())
            .map_err(|_| Error::Authentication)?;
        let complete: bool = outbound.control(
            shared,
            agreement,
            Operation::FederationIdentityPage,
            &IdentityTransfer::Import {
                checkpoint: signed.clone(),
                page,
            },
            end,
        )?;
        if complete {
            shared
                .home
                .try_lock()
                .map_err(|_| Error::AuthorityAdmissionBusy)?
                .federation_acknowledge_identity(
                    outbound.route.agreement,
                    account,
                    checkpoint.digest(),
                    shared.config.clock.sample().map_err(|_| Error::Clock)?,
                )
                .map_err(domain_error)?;
            outbound.synchronized.insert(account, checkpoint.digest());
            outbound.import_progress.remove(&account);
            return Ok(Some(reference));
        }
        if verified.value().complete || verified.value().next <= after {
            return Err(Error::Frame);
        }
        after = verified.value().next;
        outbound
            .import_progress
            .insert(account, (checkpoint.digest(), after));
    }
}

pub(super) fn renew(
    shared: &Shared,
    outbound: &mut Outbound,
    agreement: &FederationAgreement,
    checkpoints: &[CheckpointRef],
    end: u64,
) -> Result<()> {
    let lease = shared
        .home
        .try_lock()
        .map_err(|_| Error::AuthorityAdmissionBusy)?
        .federation_freshness(
            outbound.route.agreement,
            checkpoints,
            shared.config.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(domain_error)?;
    outbound.control(
        shared,
        agreement,
        Operation::FederationIdentityPage,
        &IdentityTransfer::Freshness { lease },
        end,
    )
}
