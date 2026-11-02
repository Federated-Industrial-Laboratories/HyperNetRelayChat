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

#[test]
fn completion_after_unicode_spaces_keeps_valid_byte_boundaries_in_restored_drafts() {
    use crate::protocol::{Id, NetworkId};
    let account = AccountId {
        origin: NetworkId {
            network: Id::from_bytes([1; 32]),
            incarnation: Id::from_bytes([2; 32]),
        },
        local: Id::from_bytes([3; 32]),
    };
    for space in ['\u{a0}', '\u{2003}'] {
        let prefix = format!("e\u{301}👩‍🚀{space}");
        let text = format!("{prefix}@Al tail");
        let mut editor = Editor::new(&text).unwrap();
        editor.select(prefix.len(), prefix.len());
        assert_eq!(&editor.text()[editor.completion_range()], "");
        editor.select(prefix.len() + 3, prefix.len() + 3);
        assert_eq!(&editor.text()[editor.completion_range()], "@Al");
        editor
            .complete_mention(editor.completion_range(), account, "Alice")
            .unwrap();
        assert_eq!(editor.text(), format!("{prefix}@Alice  tail"));
        assert_eq!(editor.mentions()[0].start as usize, prefix.len());

        let text = format!("{prefix}@Al");
        editor.reset_draft(&text, &[]).unwrap();
        assert_eq!(&editor.text()[editor.completion_range()], "@Al");
        editor
            .complete_mention(editor.completion_range(), account, "Alice")
            .unwrap();
        let mut reopened = Editor::default();
        reopened
            .reset_draft(editor.text(), editor.mentions())
            .unwrap();
        reopened.left(false);
        assert_eq!(&reopened.text()[reopened.completion_range()], "@Alice");
    }
}
