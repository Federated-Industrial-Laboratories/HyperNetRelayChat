use super::*;

#[test]
fn editing_moves_and_deletes_whole_graphemes() {
    let mut editor = Editor::new("e\u{301}👩‍🚀🇯🇵").unwrap();
    editor.left(false);
    assert_eq!(&editor.text()[editor.cursor()..], "🇯🇵");
    editor.backspace();
    assert_eq!(editor.text(), "e\u{301}🇯🇵");
    editor.undo();
    assert_eq!(editor.text(), "e\u{301}👩‍🚀🇯🇵");
    editor.home(false, true);
    editor.right(true);
    assert_eq!(editor.selected(), "e\u{301}");
    editor.insert("A").unwrap();
    assert_eq!(editor.text(), "A👩‍🚀🇯🇵");
    editor.delete();
    assert_eq!(editor.text(), "A🇯🇵");
}

#[test]
fn invalid_paste_is_atomic_and_restoring_a_room_clears_undo() {
    let mut editor = Editor::new("draft").unwrap();
    editor.select_all();
    assert!(editor.insert(&"x".repeat(8193)).is_err());
    assert!(editor.insert("\u{1b}[2J").is_err());
    assert_eq!(editor.text(), "draft");
    editor.insert("new").unwrap();
    editor.reset("other room").unwrap();
    editor.undo();
    assert_eq!(editor.text(), "other room");
    editor.reset("").unwrap();
    editor.insert("e").unwrap();
    editor.insert("\u{301}").unwrap();
    editor.backspace();
    assert_eq!(editor.text(), "");
}

#[test]
fn selected_mentions_keep_identity_until_edited_and_same_text_completion_is_undoable() {
    use crate::protocol::{Id, NetworkId};
    let account = AccountId {
        origin: NetworkId {
            network: Id::from_bytes([1; 32]),
            incarnation: Id::from_bytes([2; 32]),
        },
        local: Id::from_bytes([3; 32]),
    };
    let mut editor = Editor::new("@Alice ").unwrap();
    editor.complete_mention(0..7, account, "Alice").unwrap();
    assert_eq!(editor.mentions().len(), 1);
    editor.complete_mention(0..7, account, "Alice").unwrap();
    assert_eq!(editor.mentions().len(), 1);
    editor.undo();
    assert_eq!(editor.mentions().len(), 1);
    editor.undo();
    assert!(editor.mentions().is_empty());
    editor.redo();
    editor.select(3, 3);
    editor.insert("x").unwrap();
    assert!(editor.mentions().is_empty());
    editor.undo();
    assert_eq!(editor.mentions()[0].account, account);
}
