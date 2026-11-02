use super::*;

#[test]
fn clipping_preserves_clusters_and_neutralises_terminal_controls() {
    assert_eq!(clip("e\u{301}👩‍🚀x", 3, false), "e\u{301}👩‍🚀");
    let text = clip("\u{1b}]52;c;payload\u{7}", 100, false);
    assert!(!text.contains('\u{1b}'));
    assert!(!text.contains('\u{7}'));
    assert!(text.contains("\\u{1b}"));
    let lines = wrap(&"漢".repeat(1000), 7, 3, false);
    assert_eq!(lines.len(), 3);
    assert!(lines.iter().all(|line| width(line, false) <= 7));
}
