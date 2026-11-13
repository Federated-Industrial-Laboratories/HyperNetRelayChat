// SPDX-License-Identifier: Apache-2.0
//! Interrupted local exports retain one credential and never widen or revive its binding.
use super::*;
use crate::integration::Error;
use crate::service::files;
fn scope() -> Scope {
    Scope {
        rooms: vec![room()],
        initiate: false,
        history: false,
        agent_replies: false,
    }
}
fn retained_intent(config: &PathBuf, output: &PathBuf, credential: &Credential, scope: &Scope) {
    let c = Configuration::load(config).unwrap();
    files::create_json(
        &config.with_file_name("Issuance.json"),
        &json!({
            "configuration":config,"profile":c.profile,"account":c.account,"endpoint":c.endpoint,
            "output":output,"scope":scope,"credential":credential,
        }),
    )
    .unwrap();
}
#[test]
fn interrupted_credential_export_and_commit_reuse_exact_token_and_scope() {
    let f = Fixture::new();
    let config = f.profile();
    let output = config.with_file_name("Client.json");
    let credential = Credential {
        version: 1,
        id: id(45),
        secret: id(46).as_hex(),
    };
    retained_intent(&config, &output, &credential, &scope());
    // Crash before export: resume uses the already-retained token.
    assert_eq!(issue(&config, scope(), &output).unwrap(), credential.id);
    let exported = Credential::load(&output).unwrap();
    assert_eq!(exported.secret, credential.secret);
    let pin = Configuration::load(&config).unwrap().credentials[0].digest;
    retained_intent(&config, &output, &credential, &scope()); // Config commit succeeded, result/cleanup was lost.
    assert_eq!(issue(&config, scope(), &output).unwrap(), credential.id);
    assert_eq!(Configuration::load(&config).unwrap().credentials.len(), 1);
    assert_eq!(
        Configuration::load(&config).unwrap().credentials[0].digest,
        pin
    );
    assert!(!config.with_file_name("Issuance.json").exists());
    assert_eq!(
        initialise(&f.path, &f.path.join("Integration")).unwrap(),
        config
    );
    assert_eq!(Configuration::load(&config).unwrap().credentials.len(), 1);
    let mut wider = scope();
    wider.initiate = true;
    assert!(matches!(
        issue(&config, wider, &output),
        Err(Error::Conflict)
    ));
    assert!(
        !Configuration::load(&config).unwrap().credentials[0]
            .scope
            .initiate
    );
    revoke(&config, credential.id).unwrap();
    assert!(matches!(
        issue(&config, scope(), &output),
        Err(Error::Denied)
    ));
    assert!(!Configuration::load(&config).unwrap().credentials[0].enabled);
}
#[test]
fn exported_but_uncommitted_credential_recovers_and_pending_revocation_is_terminal() {
    let f = Fixture::new();
    let config = f.profile();
    let output = config.with_file_name("Client.json");
    let credential = Credential {
        version: 1,
        id: id(47),
        secret: id(48).as_hex(),
    };
    retained_intent(&config, &output, &credential, &scope());
    files::create_json(&output, &credential).unwrap();
    let exact = files::read(&output, 16384).unwrap();
    let mut changed = scope();
    changed.history = true;
    assert!(matches!(
        issue(&config, changed, &output),
        Err(Error::Conflict)
    ));
    assert!(Configuration::load(&config).unwrap().credentials.is_empty());
    assert_eq!(issue(&config, scope(), &output).unwrap(), credential.id);
    assert_eq!(files::read(&output, 16384).unwrap(), exact);
    retained_intent(&config, &output, &credential, &scope());
    revoke(&config, credential.id).unwrap();
    assert!(!config.with_file_name("Issuance.json").exists());
    assert!(issue(&config, scope(), &output).is_err());
    assert_eq!(files::read(&output, 16384).unwrap(), exact);
}
#[test]
fn partial_export_recovers_exact_bytes_and_cancelled_uncommitted_token_stays_disabled() {
    let f = Fixture::new();
    let config = f.profile();
    let output = config.with_file_name("Client.json");
    let credential = Credential {
        version: 1,
        id: id(49),
        secret: id(50).as_hex(),
    };
    retained_intent(&config, &output, &credential, &scope());
    let expected = serde_json::to_vec(&credential).unwrap();
    files::create(&output, &expected[..expected.len() / 2]).unwrap();
    assert_eq!(issue(&config, scope(), &output).unwrap(), credential.id);
    assert_eq!(files::read(&output, 16384).unwrap(), expected);
    let second = config.with_file_name("Second.json");
    let cancelled = Credential {
        version: 1,
        id: id(51),
        secret: id(52).as_hex(),
    };
    retained_intent(&config, &second, &cancelled, &scope());
    files::create_json(&second, &cancelled).unwrap();
    revoke(&config, cancelled.id).unwrap();
    assert!(issue(&config, scope(), &second).is_err());
    assert_eq!(Configuration::load(&config).unwrap().credentials.len(), 1);
    let other = Fixture::new();
    let _ = other.profile();
    assert!(matches!(
        initialise(&other.path, &f.path.join("Integration")),
        Err(Error::Conflict)
    ));
}
