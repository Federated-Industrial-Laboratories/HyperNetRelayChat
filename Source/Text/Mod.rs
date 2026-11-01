// SPDX-License-Identifier: Apache-2.0
//! Shared Unicode input and safe presentation rules.
use unicode_segmentation::UnicodeSegmentation;
#[derive(Debug, thiserror::Error)]
#[error("text exceeds its limit or contains unsupported controls")]
pub struct InvalidText;
pub type Result<T> = std::result::Result<T, InvalidText>;
pub const PROFILE: &str = "unicode-17.0.0-hrc-1";
fn forbidden(c: char) -> bool {
    c.is_control() && !matches!(c, '\n' | '\t')
}
pub fn message(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 8192
        || s.chars().any(forbidden)
        || s.graphemes(true).take(2001).count() > 2000
    {
        Err(InvalidText)
    } else {
        Ok(())
    }
}
pub fn handle(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 64
        || s.chars().any(char::is_control)
        || s.graphemes(true).take(33).count() > 32
    {
        Err(InvalidText)
    } else {
        Ok(())
    }
}
pub fn terminal(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if (c.is_control() && !matches!(c, '\n' | '\t')) || sensitive(c) {
                c.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn sensitive(c: char) -> bool {
    matches!(c,'\u{061c}'|'\u{200b}'|'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2060}'..='\u{206f}'|'\u{feff}')
}
pub fn identity_display(s: &str) -> String {
    terminal(s)
}

/// Unicode17 NFC(DefaultFullCaseFold(NFD(text))), with bounded intermediate output.
pub fn lookup(s: &str, maximum: usize) -> Result<String> {
    use icu_normalizer::{ComposingNormalizer, DecomposingNormalizer};
    use std::fmt::Write;
    use writeable::Writeable;
    struct Bounded {
        text: String,
        maximum: usize,
    }
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            if self
                .text
                .len()
                .checked_add(s.len())
                .is_none_or(|n| n > self.maximum)
            {
                return Err(std::fmt::Error);
            }
            self.text.push_str(s);
            Ok(())
        }
    }
    if s.len() > 32768 || maximum > 32768 {
        return Err(InvalidText);
    }
    let mut decomposed = Bounded {
        text: String::new(),
        maximum: 32768,
    };
    for c in DecomposingNormalizer::new_nfd().normalize_iter(s.chars()) {
        decomposed.write_char(c).map_err(|_| InvalidText)?;
    }
    let mut folded = Bounded {
        text: String::new(),
        maximum: 32768,
    };
    icu_casemap::CaseMapper::new()
        .fold(&decomposed.text)
        .write_to(&mut folded)
        .map_err(|_| InvalidText)?;
    let mut composed = Bounded {
        text: String::new(),
        maximum,
    };
    for c in ComposingNormalizer::new_nfc().normalize_iter(folded.text.chars()) {
        composed.write_char(c).map_err(|_| InvalidText)?;
    }
    Ok(composed.text)
}

pub fn query(terms: &[String]) -> Result<Vec<String>> {
    if terms.len() > 16
        || terms.iter().map(String::len).sum::<usize>() > 1024
        || terms.iter().any(String::is_empty)
    {
        return Err(InvalidText);
    }
    let mut remaining = 4096;
    let mut result = Vec::new();
    for term in terms {
        let text = lookup(term, remaining)?;
        remaining -= text.len();
        result.push(text);
    }
    Ok(result)
}
/// Only literal phrases of three or more scalars enter FTS5's trigram grammar.
pub fn match_expression(normalized: &[String]) -> Option<String> {
    let phrases: Vec<_> = normalized
        .iter()
        .filter(|s| s.chars().count() >= 3)
        .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
        .collect();
    (!phrases.is_empty()).then(|| phrases.join(" AND "))
}

#[cfg(test)]
#[path = "../../Tests/Text/UnicodeVectors.rs"]
mod conformance;
#[cfg(test)]
#[path = "../../Tests/Text/Text.rs"]
mod tests;
