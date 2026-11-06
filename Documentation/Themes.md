# Desktop themes

[Documentation](ReadMe.md) | [Interfaces](Interfaces.md)

Open **Settings → Appearance → Theme** to choose a palette. The original
HyperNet Dark and HyperNet Light remain the defaults. Ocean, Forest, Ember,
Plum, Slate and Sand each provide another light and dark palette.

Theme selection is saved with the current chat profile. Conversation layout,
density and text size stay separate controls. The TUI uses the selected light
or dark mode; custom desktop colours do not change terminal configuration.

## Import a theme

Choose **Import JSON**, browse to a local `.json` file and select it. Inspect the
palette preview, then choose **Import and use**. HRC validates and copies the
theme into its private theme folder; it does not keep loading the original file.
An imported palette can be removed through the same Appearance controls.

Imported themes are stored under `$XDG_CONFIG_HOME/HyperNetRelayChat/Themes`,
or `$HOME/.config/HyperNetRelayChat/Themes` when XDG_CONFIG_HOME is unset.
Files use a content-derived name. Importing the same content again reuses it;
an edited or unrelated destination is never overwritten. At most 64 imported
themes are retained, with a 16 KiB limit per JSON file.

If an imported file is missing, corrupt or no longer privately owned, HRC uses
that profile's HyperNet Light or HyperNet Dark default and reports the problem
in Appearance. Chat history, identity and permissions are unaffected.

## JSON format

Start from one of the [supplied palettes](../Themes/). A theme contains only a
version, display name, mode, colours and two bounded outline settings. For example:

```json
{
  "version": 1,
  "name": "Ocean Dark",
  "mode": "dark",
  "colors": {
    "panel": "#101D2B",
    "surface": "#182A3B",
    "window": "#162535",
    "input": "#0B1622",
    "faint": "#1B2E40",
    "text": "#E5F0FA",
    "muted": "#A7BECE",
    "accent": "#7ECDE7",
    "selection": "#24495D",
    "selectionText": "#D3F3FF",
    "border": "#395166",
    "button": "#22394C",
    "hover": "#2B485D",
    "pressed": "#24495D"
  },
  "display": { "cornerCut": 5, "outlineWidth": 1 }
}
```

All colour fields are required, opaque `#RRGGBB` values. Mode is `light` or
`dark`. Names contain up to 48 letters, digits, spaces, hyphens or underscores.
`cornerCut` ranges from 0 to 8 pixels; `outlineWidth` ranges from 0.5 to 2 pixels.
The optional `display` object defaults to 5 and 1 respectively.

Unknown or repeated fields, unsupported versions, malformed colours, oversized
files and insufficient text contrast are rejected. Primary and selection text
require at least 4.5:1 contrast against their backgrounds. Muted text and accents
also have minimum contrast checks. Warning, error and connection-state colours
retain their semantic roles and cannot be supplied by a theme.
Main backgrounds must have relative luminance at most 0.1 in dark mode, or at
least 0.5 in light mode, so the fixed status colours remain distinct.

Themes cannot contain scripts, shell commands, URLs, asset paths, fonts or plugin
code. They do not change window placement, keyboard shortcuts, message contents,
network settings or permission controls.
