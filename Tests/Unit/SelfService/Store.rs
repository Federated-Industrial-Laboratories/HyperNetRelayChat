// SPDX-License-Identifier: Apache-2.0
use super::*;

struct Fixture(Configuration);
impl Fixture {
    fn new(maximum: u16) -> Self {
        let root = std::env::temp_dir().join(format!("hrc-admission-store-{}", random().unwrap()));
        files::directory(&root, true).unwrap();
        files::directory(&root.join("Invitations"), true).unwrap();
        let ca = root.join("Authority.pem");
        files::create(&ca, b"test authority, not a TLS fixture").unwrap();
        let path = root.join("unused");
        let route = backend::RouteConfig {
            service: "01".repeat(32),
            profile: path.clone(),
        };
        let cap = now_ms().unwrap() + 3_600_000;
        let configuration = Configuration {
            format: "HrcAdmissionHost/1".into(),
            name: "Test host".into(),
            directory: root,
            address: "127.0.0.1:25444".parse().unwrap(),
            certificate_authority: ca,
            certificate: path.clone(),
            private_key: path.clone(),
            certificate_sha256: "02".repeat(32),
            maximum_invitations: maximum,
            route_seconds: 120,
            backend: backend::Config {
                core: path.clone(),
                suite: path.clone(),
                publisher_key: path.clone(),
                bootstrap: path.clone(),
                operator_directory: path.clone(),
                operator_key: path.clone(),
                operator_lock: path.clone(),
                authority_control_directory: path.clone(),
                clock_directory: path.clone(),
                clock_metadata: path.clone(),
                image: format!("sha256:{}", "03".repeat(32)),
                home_config: path,
                relay: route.clone(),
                authority: route.clone(),
                application: route,
                reader: None,
                access_expires_ms: cap,
            },
            metadata: NetworkMetadata {
                bootstrap: Artifact::from_bytes(b"test bootstrap").unwrap(),
                bootstrap_fingerprint: "04".repeat(32),
                network: "05".repeat(32),
                incarnation: "06".repeat(32),
                application_service: "07".repeat(32),
                reader_available: false,
                access_expires_ms: cap,
            },
        };
        write(
            &configuration.directory.join("Control.json"),
            &Control {
                configuration_sha256: configuration.pin().unwrap(),
                enabled: false,
            },
        )
        .unwrap();
        Self(configuration)
    }
    fn store(&self) -> Locked {
        Locked::open(&self.0).unwrap()
    }
    fn issue(&self) -> Invitation {
        let store = self.store();
        store.enable(true).unwrap();
        store
            .issue("Recipient", now_ms().unwrap() + 60_000)
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0.directory);
    }
}
fn request(i: &Invitation, key: u8, action: Action) -> RequestData {
    RequestData {
        invitation_id: i.id.clone(),
        authentication_key: format!("{key:02x}").repeat(32),
        action,
    }
}
fn redeem(i: &Invitation, content: &[u8]) -> Action {
    Action::Redeem {
        secret: i.secret.clone(),
        chat_request: Artifact::from_bytes(content).unwrap(),
        reader_request: None,
    }
}

#[test]
fn disabled_by_default_and_single_recipient_claim_is_durable() {
    let fixture = Fixture::new(2);
    assert!(matches!(
        fixture
            .store()
            .issue("Recipient", now_ms().unwrap() + 60_000),
        Err(Error::Busy)
    ));
    let invitation = fixture.issue();
    let bytes = files::read(
        &fixture
            .0
            .record_directory(&invitation.id)
            .unwrap()
            .join("Record.json"),
        16384,
    )
    .unwrap();
    assert!(
        !String::from_utf8(bytes)
            .unwrap()
            .contains(&invitation.secret)
    );
    let store = fixture.store();
    assert!(matches!(
        store.request(request(
            &invitation,
            1,
            Action::Inspect {
                secret: "00".repeat(32)
            }
        )),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        store.request(request(
            &invitation,
            1,
            redeem(&invitation, b"signed chat request")
        )),
        Ok(Response::Pending { .. })
    ));
    drop(store);
    let store = fixture.store();
    assert!(
        store
            .request(request(
                &invitation,
                1,
                redeem(&invitation, b"signed chat request")
            ))
            .is_ok()
    );
    assert!(matches!(
        store.request(request(
            &invitation,
            2,
            redeem(&invitation, b"signed chat request")
        )),
        Err(Error::Bound)
    ));
    assert!(matches!(
        store.request(request(
            &invitation,
            1,
            redeem(&invitation, b"different request")
        )),
        Err(Error::Bound)
    ));
    assert!(matches!(
        store.request(request(&invitation, 2, Action::Status)),
        Err(Error::Bound)
    ));
    assert_eq!(store.records().unwrap().len(), 1);
}

#[test]
fn redemption_expiry_does_not_expire_bound_resume_but_revocation_does() {
    let fixture = Fixture::new(2);
    let invitation = fixture.issue();
    let store = fixture.store();
    let mut record = store.load(&invitation.id).unwrap();
    record.expires_ms = now_ms().unwrap() - 1;
    store.save(&record).unwrap();
    assert!(matches!(
        store.request(request(&invitation, 1, redeem(&invitation, b"request"))),
        Err(Error::Expired)
    ));
    record.expires_ms = now_ms().unwrap() + 60_000;
    store.save(&record).unwrap();
    store
        .request(request(&invitation, 1, redeem(&invitation, b"request")))
        .unwrap();
    record = store.load(&invitation.id).unwrap();
    record.expires_ms = now_ms().unwrap() - 1;
    store.save(&record).unwrap();
    assert!(
        store
            .request(request(&invitation, 1, redeem(&invitation, b"request")))
            .is_ok()
    );
    store.enable(false).unwrap();
    assert!(matches!(
        store.request(request(&invitation, 1, Action::Status)),
        Err(Error::Busy)
    ));
    store.revoke(&invitation.id).unwrap();
    store.enable(true).unwrap();
    assert!(matches!(
        store.request(request(&invitation, 1, Action::Status)),
        Err(Error::Expired)
    ));
    assert_eq!(store.load(&invitation.id).unwrap().phase, Phase::Revoking);
}

#[test]
fn capacity_and_private_lock_serialize_claims_and_issuance() {
    let fixture = Fixture::new(1);
    fixture.issue();
    let store = fixture.store();
    assert!(matches!(Locked::open(&fixture.0), Err(Error::Busy)));
    assert!(matches!(
        store.issue("Second", now_ms().unwrap() + 60_000),
        Err(Error::Busy)
    ));
    // Interrupted exports must not hide later committed invitations.
    for _ in 0..66 {
        files::directory(
            &fixture
                .0
                .directory
                .join("Invitations")
                .join(format!(".issuing-{}", random().unwrap())),
            true,
        )
        .unwrap();
    }
    assert_eq!(store.records().unwrap().len(), 1);
    assert!(matches!(
        store.issue("Second", now_ms().unwrap() + 60_000),
        Err(Error::Busy)
    ));
    drop(store);
    assert!(Locked::open(&fixture.0).is_ok());
}

#[test]
fn durable_registration_rejects_substitution_and_bound_access_cap() {
    let fixture = Fixture::new(1);
    let invitation = fixture.issue();
    let store = fixture.store();
    store
        .request(request(&invitation, 1, redeem(&invitation, b"request")))
        .unwrap();
    let mut record = store.load(&invitation.id).unwrap();
    record.phase = Phase::Ready;
    store.save(&record).unwrap();
    let enrol = || Action::Enrol {
        registration: Artifact::from_bytes(b"signed registration").unwrap(),
    };
    assert!(store.request(request(&invitation, 1, enrol())).is_ok());
    assert!(store.request(request(&invitation, 1, enrol())).is_ok());
    assert!(matches!(
        store.request(request(
            &invitation,
            1,
            Action::Enrol {
                registration: Artifact::from_bytes(b"replacement").unwrap()
            }
        )),
        Err(Error::Bound)
    ));
    record = store.load(&invitation.id).unwrap();
    record.access_expires_ms = now_ms().unwrap() - 1;
    record.expires_ms = record.access_expires_ms;
    store.save(&record).unwrap();
    assert!(matches!(
        store.request(request(&invitation, 1, Action::Status)),
        Err(Error::Expired)
    ));
}
