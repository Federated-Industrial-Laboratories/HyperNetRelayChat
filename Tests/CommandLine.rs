use super::*;

#[test]
fn diagnostic_admission_requires_exact_principal_and_bounded_waits() {
    let base = [
        "hrc",
        "transport",
        "probe-serve",
        "--companion",
        "/private/agent",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    for invalid in [
        "0".repeat(64),
        "A".repeat(64),
        "f".repeat(63),
        "\u{1b}".repeat(64),
    ] {
        let mut args = base.to_vec();
        args.extend(["--allow-principal", &invalid]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let principal = "ab".repeat(32);
    for bound in ["99", "60001"] {
        let mut args = base.to_vec();
        args.extend(["--allow-principal", &principal, "--timeout-ms", bound]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut args = base.to_vec();
    args.extend(["--allow-principal", &principal]);
    assert!(Cli::try_parse_from(args).is_ok());
}
