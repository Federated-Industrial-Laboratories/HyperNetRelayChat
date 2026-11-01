use super::*;
#[test]
fn text_preserves_graphemes_and_neutralizes_terminal_controls() {
    assert!(message(&"e\u{301}".repeat(2000)).is_ok());
    assert!(message(&"e\u{301}".repeat(2001)).is_err());
    assert!(message("hello\nworld\t👩‍🚀").is_ok());
    assert!(message("\x1b[31m").is_err());
    assert_eq!(terminal("\x1b[31m"), "\\u{1b}[31m");
    assert!(identity_display("a\u{202e}b").contains("\\u{202e}"));
    assert!(handle("two\nlines").is_err());
}

#[test]
fn lookup_has_full_default_folding_and_search_keeps_short_terms() {
    assert_eq!(lookup("Straße", 32768).unwrap(), "strasse");
    assert_eq!(
        lookup("É", 32768).unwrap(),
        lookup("E\u{301}", 32768).unwrap()
    );
    assert_ne!(lookup("é", 32768).unwrap(), lookup("e", 32768).unwrap());
    assert_eq!(lookup("İIı", 32768).unwrap(), "i\u{307}iı");
    assert!(lookup("ß", 1).is_err());
    let terms = query(&["a".into(), "Hello \"world\"".into()]).unwrap();
    assert_eq!(
        match_expression(&terms),
        Some("\"hello \"\"world\"\"\"".into())
    );
    assert_eq!(match_expression(&["中文".into()]), None);
}
