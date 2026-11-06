// SPDX-License-Identifier: Apache-2.0
//! Bounded, opaque colour data; themes cannot select code, files or authority settings.
use eframe::egui::Color32;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAX_BYTES: usize = 16 * 1024;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Dark,
    Light,
}
impl Mode {
    pub fn theme(self) -> hrc::client::Theme {
        match self {
            Self::Dark => hrc::client::Theme::Dark,
            Self::Light => hrc::client::Theme::Light,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Colour([u8; 3]);
impl Colour {
    pub fn colour(self) -> Color32 {
        Color32::from_rgb(self.0[0], self.0[1], self.0[2])
    }
    fn luminance(self) -> f64 {
        let linear = self.0.map(|v| {
            let v = f64::from(v) / 255.0;
            if v <= 0.04045 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        });
        linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
    }
    pub fn contrast(self, other: Self) -> f64 {
        let a = self.luminance();
        let b = other.luminance();
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }
}
impl Serialize for Colour {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!(
            "#{:02X}{:02X}{:02X}",
            self.0[0], self.0[1], self.0[2]
        ))
    }
}
impl<'de> Deserialize<'de> for Colour {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut rgb = [0; 3];
        if text.len() != 7
            || !text.starts_with('#')
            || hex::decode_to_slice(&text[1..], &mut rgb).is_err()
        {
            return Err(serde::de::Error::custom("expected opaque #RRGGBB colour"));
        }
        Ok(Self(rgb))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Colours {
    pub panel: Colour,
    pub surface: Colour,
    pub window: Colour,
    pub input: Colour,
    pub faint: Colour,
    pub text: Colour,
    pub muted: Colour,
    pub accent: Colour,
    pub selection: Colour,
    pub selection_text: Colour,
    pub border: Colour,
    pub button: Colour,
    pub hover: Colour,
    pub pressed: Colour,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Display {
    pub corner_cut: f32,
    pub outline_width: f32,
}
impl Default for Display {
    fn default() -> Self {
        Self {
            corner_cut: 5.0,
            outline_width: 1.0,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Palette {
    pub version: u32,
    pub name: String,
    pub mode: Mode,
    pub colors: Colours,
    #[serde(default)]
    pub display: Display,
}
impl Palette {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err("Theme exceeds the 16 KiB limit.");
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| "Theme JSON has an unknown field, repeated field or invalid value.")?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err("Unsupported theme version.");
        }
        if self.name.is_empty()
            || self.name.len() > 48
            || self.name.trim() != self.name
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" -_".contains(&b))
        {
            return Err("Theme names need 1–48 letters, digits, spaces, hyphens or underscores.");
        }
        if !self.display.corner_cut.is_finite()
            || !(0.0..=8.0).contains(&self.display.corner_cut)
            || !self.display.outline_width.is_finite()
            || !(0.5..=2.0).contains(&self.display.outline_width)
        {
            return Err("Theme outline settings exceed their supported range.");
        }
        let c = &self.colors;
        let backgrounds = [c.panel, c.surface, c.window, c.input, c.faint];
        if backgrounds.iter().any(|v| match self.mode {
            Mode::Dark => v.luminance() > 0.1,
            Mode::Light => v.luminance() < 0.5,
        }) {
            return Err("Theme backgrounds do not match its light or dark mode.");
        }
        if backgrounds
            .into_iter()
            .chain([c.button, c.hover, c.pressed, c.selection])
            .any(|v| c.text.contrast(v) < 4.5)
            || c.selection_text.contrast(c.selection) < 4.5
        {
            return Err("Theme text needs at least 4.5:1 contrast against its backgrounds.");
        }
        if backgrounds.iter().any(|v| c.muted.contrast(*v) < 3.0)
            || [c.panel, c.surface, c.window]
                .iter()
                .any(|v| c.accent.contrast(*v) < 3.0)
        {
            return Err("Theme secondary text and accents need at least 3:1 contrast.");
        }
        Ok(())
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|_| "Theme could not be encoded.")
    }
}
