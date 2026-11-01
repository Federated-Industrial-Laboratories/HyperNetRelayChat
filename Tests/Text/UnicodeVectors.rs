// SPDX-License-Identifier: Apache-2.0
// Upstream data is distributed under Tests/Vectors/UNICODE-LICENSE.txt.
use super::*;
use icu_normalizer::{ComposingNormalizer, DecomposingNormalizer};
fn scalars(field: &str) -> String {
    field
        .split_whitespace()
        .map(|code| char::from_u32(u32::from_str_radix(code, 16).unwrap()).unwrap())
        .collect()
}
#[test]
fn unicode17_normalization_conformance() {
    let nfc = ComposingNormalizer::new_nfc();
    let nfd = DecomposingNormalizer::new_nfd();
    let mut count = 0;
    for line in include_str!("../Vectors/NormalizationTest.txt").lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() || line.starts_with('@') {
            continue;
        }
        let fields: Vec<_> = line.split(';').take(5).map(scalars).collect();
        assert_eq!(fields.len(), 5);
        for i in 0..3 {
            assert_eq!(nfc.normalize(&fields[i]), fields[1]);
            assert_eq!(nfd.normalize(&fields[i]), fields[2]);
        }
        for i in 3..5 {
            assert_eq!(nfc.normalize(&fields[i]), fields[3]);
            assert_eq!(nfd.normalize(&fields[i]), fields[4]);
        }
        count += 1;
    }
    assert!(count > 19000);
}
#[test]
fn unicode17_default_full_casefold_conformance() {
    let nfc = ComposingNormalizer::new_nfc();
    let mut count = 0;
    for line in include_str!("../Vectors/CaseFolding.txt").lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<_> = line.split(';').collect();
        if !matches!(f[1].trim(), "C" | "F") {
            continue;
        }
        assert_eq!(
            lookup(&scalars(f[0]), 32768).unwrap(),
            nfc.normalize(&scalars(f[2]))
        );
        count += 1;
    }
    assert!(count > 1500);
}
#[test]
fn unicode17_extended_grapheme_conformance() {
    let mut count = 0;
    for line in include_str!("../Vectors/GraphemeBreakTest.txt").lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let mut text = String::new();
        let mut expected = Vec::new();
        for token in line.split_whitespace() {
            match token {
                "÷" => expected.push(text.len()),
                "×" => (),
                code => text.push(char::from_u32(u32::from_str_radix(code, 16).unwrap()).unwrap()),
            }
        }
        let actual: Vec<_> = text
            .grapheme_indices(true)
            .map(|(offset, _)| offset)
            .chain(std::iter::once(text.len()))
            .collect();
        assert_eq!(actual, expected, "{line}");
        count += 1;
    }
    assert!(count > 700);
}
