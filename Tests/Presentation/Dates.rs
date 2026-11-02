use super::*;
#[test]
fn date_filters_preserve_utc_bounds_and_reject_invalid_calendar_values() {
    assert_eq!(date_bound("1970-01-01").unwrap(), Some(0));
    assert_eq!(
        date_bound("2026-11-01T12:00:00Z").unwrap(),
        date_bound("2026-11-01T13:00:00+01:00").unwrap()
    );
    assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
    assert!(date_bound("2100-02-29").is_err());
    assert!(date_bound("2000-02-29").is_ok());
    assert!(date_bound("1969-12-31").is_err());
    assert!(date_bound("1969-12-31T23:59:59.999999999Z").is_err());
}
