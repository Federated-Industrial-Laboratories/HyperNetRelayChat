// SPDX-License-Identifier: Apache-2.0
// Native Page links use the Suite grammar and preserve original message byte ranges.
use super::*;

fn uri() -> String {
    format!(
        "hypernet://{}/{}/News/{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    )
}
#[test]
fn page_addresses_match_canonical_suite_grammar() {
    let valid = uri();
    assert!(Address::parse(&valid).is_some());
    for invalid in [
        valid.to_uppercase(),
        valid.replace("/News/", "/1News/"),
        valid.replace("/News/", "/Some_News/"),
        valid.replace("/News/", "/Ne%77s/"),
        valid.replace("/News/", &format!("/{}/", "a".repeat(33))),
        valid.replace("hypernet://", "https://"),
        format!("{valid}/extra"),
        format!("{valid}?token=secret"),
        format!("{valid}#part"),
        format!("{valid}@host"),
        format!("{}$(command)", &valid[..valid.len() - 1]),
    ] {
        assert!(Address::parse(&invalid).is_none(), "{invalid}");
    }
    assert!(Address::parse(&valid[..valid.len() - 1]).is_none());
}
#[test]
fn page_link_ranges_preserve_unicode_punctuation_and_full_addresses() {
    let uri = uri();
    let text = format!("Before 中文 ({uri}).\nAfter <{uri}>!");
    let links = ranges(&text);
    assert_eq!(links.len(), 2);
    let mut copied = String::new();
    let mut start = 0;
    for range in links {
        assert_eq!(&text[range.clone()], uri);
        copied.push_str(&text[start..range.end]);
        start = range.end;
    }
    copied.push_str(&text[start..]);
    assert_eq!(copied, text);
    for text in [
        format!("x{uri}"),
        format!("{uri}/more"),
        format!("{uri}?query"),
        format!("{uri}.invalid"),
    ] {
        assert!(ranges(&text).is_empty());
    }
}
#[test]
fn page_link_work_and_label_size_are_bounded() {
    let uri = uri();
    let text = vec![uri.as_str(); 24].join(" ");
    assert_eq!(ranges(&text).len(), MAX_LINKS);
    assert!(ranges(&"x".repeat(MAX_MESSAGE + 1)).is_empty());
    let address = Address::parse(&uri).unwrap();
    assert!(address.label().len() < 64);
    assert_eq!(address.page.len(), 32);
}

#[test]
fn page_link_fits_narrow_column_and_never_opens_system_browser() {
    let uri = uri().replace("/News/", &format!("/{}/", "N".repeat(32)));
    let address = Address::parse(&uri).unwrap();
    let context = egui::Context::default();
    let mut position = egui::Pos2::ZERO;
    let mut clicked = false;
    for pass in 0..3 {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(320.0, 480.0),
            )),
            ..Default::default()
        };
        if pass > 0 {
            input.events = vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: pass == 1,
                    modifiers: egui::Modifiers::NONE,
                },
            ];
        }
        let mut output = context.run_ui(input, |ui| {
            ui.set_max_width(84.0);
            ui.horizontal_wrapped(|ui| {
                let response = link(ui, &uri, &address);
                assert!(response.rect.width() <= 84.0);
                assert!(response.rect.height() < 40.0);
                position = response.rect.center();
                clicked |= response.clicked();
            });
        });
        assert!(
            !output
                .platform_output
                .commands
                .iter()
                .any(|command| matches!(command, egui::OutputCommand::OpenUrl(_)))
        );
        // This geometry/input check has no renderer to consume font textures.
        output.textures_delta.clear();
    }
    assert!(clicked);
    assert_eq!(Address::parse(&uri).unwrap().namespace.len(), 32);
}
