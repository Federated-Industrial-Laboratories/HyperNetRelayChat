use super::*;

#[test]
fn bot_arguments_keep_selected_scope_and_memory_boundaries() {
    let mut config = Config::new().unwrap();
    config.profile = "/private/bot with spaces".into();
    config.grant = Some(Id::from_bytes([7; 32]));
    config.memory_days = 12;
    config.memory_bytes = 32768;
    let model = models::Config::new().unwrap().local_model("!ask", false);
    let args = arguments(&config, Some(&model), false).unwrap();
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--profile", "/private/bot with spaces"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--grant", &Id::from_bytes([7; 32]).as_hex()])
    );
    assert!(args.windows(2).any(|pair| pair == ["--memory-days", "12"]));
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--memory-bytes", "32768"])
    );
    assert!(!args.contains(&"--resynchronise".into()));
    config.memory_enabled = false;
    let args = arguments(&config, Some(&model), true).unwrap();
    assert!(args.contains(&"--no-memory".into()));
    assert!(args.contains(&"--resynchronise".into()));
    assert!(!args.contains(&"--memory-days".into()));
}

#[test]
fn rejected_and_unknown_setup_operations_are_not_reported_as_committed() {
    assert!(committed(&Outcome::Unknown).is_err());
    assert!(committed(&Outcome::Absent).is_err());
    assert!(
        committed(&Outcome::Rejected {
            code: hrc::protocol::ErrorCode::Denied,
            detail: "Membership".into()
        })
        .is_err()
    );
    assert!(
        committed(&Outcome::Committed {
            event: None,
            position: 1,
            body: hrc::protocol::Value::Null
        })
        .is_ok()
    );
}
