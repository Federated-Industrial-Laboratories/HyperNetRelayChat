// SPDX-License-Identifier: Apache-2.0
//! Crash recovery binds invitations and original registrations without admitting another identity.
use super::*;

#[test]
fn exact_invitation_survives_reopen_without_new_authority() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let expires = TimeBounds::test_now().lower_ms + 60_000;
    let first = home
        .issue_invitation_exact(
            id(80),
            id(81),
            AccountClass::Human,
            expires,
            TimeBounds::test_now(),
        )
        .unwrap();
    drop(home);
    let mut home = fixture.open();
    let before = home.usage().unwrap().commit_counter;
    let retry = home
        .issue_invitation_exact(
            id(80),
            id(81),
            AccountClass::Human,
            expires,
            TimeBounds::test_now(),
        )
        .unwrap();
    assert_eq!(encode(&first).unwrap(), encode(&retry).unwrap());
    assert_eq!(home.usage().unwrap().commit_counter, before);
    assert!(
        home.issue_invitation_exact(
            id(80),
            id(82),
            AccountClass::Human,
            expires,
            TimeBounds::test_now()
        )
        .is_err()
    );
    assert!(
        home.issue_invitation_exact(
            id(80),
            id(81),
            AccountClass::Human,
            expires + 1,
            TimeBounds::test_now()
        )
        .is_err()
    );
}

#[test]
fn original_registration_recovery_is_exact_and_read_only() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let key = SigningKey::from_bytes(&[85; 32]);
    let invitation = home
        .issue_invitation(id(86), AccountClass::Human, TimeBounds::test_now())
        .unwrap();
    let mut request = AccountRegistration {
        home: service(),
        account: AccountId {
            origin: service().network,
            local: id(87),
        },
        endpoint: id(88),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: id(86),
        recovery_key: Id::from_bytes(SigningKey::from_bytes(&[89; 32]).verifying_key().to_bytes()),
        classification: AccountClass::Human,
        invitation: invitation.id,
    };
    let signed = verify_registration_request(&sign_registration(&request, &key).unwrap()).unwrap();
    assert!(home.registration_outcome(&signed).unwrap().is_none());
    let original = home
        .accept_registration(&signed, TimeBounds::test_now())
        .unwrap()
        .acting;
    drop(home);
    let mut home = fixture.open();
    let before = home.usage().unwrap().commit_counter;
    assert_eq!(home.registration_outcome(&signed).unwrap(), Some(original));
    assert_eq!(home.usage().unwrap().commit_counter, before);
    assert!(
        home.accept_registration(&signed, TimeBounds::test_now())
            .is_err()
    );
    request.invitation = id(90);
    let changed = verify_registration_request(&sign_registration(&request, &key).unwrap()).unwrap();
    assert!(home.registration_outcome(&changed).is_err());
}
