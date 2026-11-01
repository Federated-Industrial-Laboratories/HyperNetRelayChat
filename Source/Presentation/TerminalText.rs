// SPDX-License-Identifier: Apache-2.0
//! Terminal text never supplies control sequences; clipping retains complete graphemes.
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

fn bounded_safe(text: &str) -> String {
    let prefix = if text.len() <= 8192 {
        text
    } else {
        let end = text.floor_char_boundary(8192);
        let prefix = &text[..end];
        let last = prefix
            .grapheme_indices(true)
            .next_back()
            .map_or(0, |(i, _)| i);
        &prefix[..last]
    };
    crate::text::terminal(prefix)
}

pub fn width(text: &str, ambiguous_wide: bool) -> usize {
    if ambiguous_wide {
        text.width_cjk()
    } else {
        text.width()
    }
}
pub fn clip(text: &str, columns: usize, ambiguous_wide: bool) -> String {
    let safe = bounded_safe(text);
    let mut result = String::new();
    let mut used = 0;
    for grapheme in safe.graphemes(true) {
        let displayed = match grapheme {
            "\n" | "\r" => " ",
            "\t" => "    ",
            other => other,
        };
        let size = width(displayed, ambiguous_wide).max(1);
        if used + size > columns {
            break;
        }
        if width(displayed, ambiguous_wide) == 0 {
            result.push('◌');
        }
        result.push_str(displayed);
        used += size;
    }
    result
}
pub fn wrap(text: &str, columns: usize, maximum_lines: usize, ambiguous_wide: bool) -> Vec<String> {
    let columns = columns.clamp(1, 300);
    let maximum_lines = maximum_lines.min(120);
    if maximum_lines == 0 {
        return Vec::new();
    }
    let safe = bounded_safe(text);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for grapheme in safe.graphemes(true) {
        if grapheme == "\n" {
            lines.push(std::mem::take(&mut line));
            used = 0;
            if lines.len() == maximum_lines {
                return lines;
            }
            continue;
        }
        let displayed = if grapheme == "\t" { "    " } else { grapheme };
        let size = width(displayed, ambiguous_wide).max(1);
        if used + size > columns && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
            used = 0;
            if lines.len() == maximum_lines {
                return lines;
            }
        }
        if size > columns {
            line.push('�');
            used += 1;
        } else {
            if width(displayed, ambiguous_wide) == 0 {
                line.push('◌');
            }
            line.push_str(displayed);
            used += size;
        }
    }
    if lines.len() < maximum_lines {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
#[path = "../../Tests/Presentation/TerminalText.rs"]
mod tests;
