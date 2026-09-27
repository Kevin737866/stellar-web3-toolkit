//! Terminal colour theming for the toolkit CLI.
//!
//! # Reading of "Wallet UI dark mode"
//!
//! This crate is a CLI plus libraries — there is no web UI — so the honest
//! reading of a "dark mode" issue here is **terminal colour theming**, the
//! closest equivalent a terminal program has. A light/dark choice matters for
//! exactly the reason it matters in a GUI: a colour that is legible on a dark
//! background (bright black, dim cyan) is illegible on a light one, and the
//! toolkit's `wallet` command prints long hex secrets and account ids that are
//! much easier to misread when they disappear into the background.
//!
//! The half of a dark mode that is an *accessibility* requirement rather than
//! an aesthetic one is `off`: when a user has asked for no colour, this module
//! emits **no escape sequences at all**, so piped output stays byte-identical
//! to the plain text and remains safe to `grep`, `diff`, `cut` and hash.
//!
//! # Modes
//!
//! | Mode | Behaviour |
//! |---|---|
//! | [`ThemeMode::Dark`] | dark-background palette, colour only on a TTY |
//! | [`ThemeMode::Light`] | light-background palette, colour only on a TTY |
//! | [`ThemeMode::Auto`] | dark palette if stdout is a TTY, otherwise no colour |
//! | [`ThemeMode::Off`] | never any escape sequences |
//!
//! # Resolution order
//!
//! [`Theme::resolve`] is a pure function of a mode and a [`ThemeEnv`], so every
//! branch below is unit-testable without a terminal. The first matching rule
//! wins:
//!
//! 1. `Off` (or its alias `never`) — always off. An explicit request for no
//!    colour outranks every environment variable, including `CLICOLOR_FORCE`.
//! 2. `NO_COLOR` set to any value — off (<https://no-color.org>). Per that
//!    convention the *presence* of the variable is what counts, not its value.
//!    `NO_COLOR` deliberately outranks `CLICOLOR_FORCE`: the opt-out is the
//!    safety-oriented signal and should not be defeated by a force flag that a
//!    CI harness may set globally.
//! 3. `CLICOLOR_FORCE` set to anything other than `0` — on, even when stdout
//!    is redirected, because that is the variable's whole purpose.
//! 4. Otherwise — on only if stdout is a TTY.
//!
//! Rule 4 applies to the explicit `Dark` and `Light` modes too. Choosing a
//! palette is not the same as asking for colour, and a user who pipes
//! `stellar-toolkit wallet generate` into a file almost certainly wants the
//! bytes, not escape codes. `CLICOLOR_FORCE` is the documented way to override.
//!
//! # Usage
//!
//! ```
//! use stellar_toolkit::theme::{Style, Theme, ThemeEnv, ThemeMode};
//!
//! let theme = Theme::resolve(ThemeMode::Auto, ThemeEnv::default());
//! assert_eq!(theme.paint(Style::Heading, "Wallet"), "Wallet"); // not a TTY here
//! ```

use std::io::IsTerminal;

/// Colour palette the terminal is assumed to have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeMode {
    /// Terminal has a dark (or unknown, generally dark) background.
    Dark,
    /// Terminal has a light background.
    Light,
    /// Dark when stdout is a TTY, no colour otherwise.
    Auto,
    /// Never emit escape sequences.
    Off,
}

impl ThemeMode {
    /// Canonical lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
            ThemeMode::Auto => "auto",
            ThemeMode::Off => "off",
        }
    }

    /// Parse a mode name, case-insensitively. `never` is an accepted alias for
    /// `off` because that is the spelling most users reach for.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(ThemeMode::Dark),
            "light" => Some(ThemeMode::Light),
            "auto" | "" => Some(ThemeMode::Auto),
            "off" | "never" | "none" => Some(ThemeMode::Off),
            _ => None,
        }
    }
}

/// The semantic roles the CLI paints.
///
/// Callers pick a role, never a raw code: that is what lets the palette swap
/// underneath them, and it keeps "which colour is a secret" in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// Section headings.
    Heading,
    /// The label of a field, e.g. `Account (G)`.
    Key,
    /// A value that is safe to display.
    Value,
    /// Secondary information, de-emphasised.
    Muted,
    /// A field the user must treat as dangerous — e.g. a secret key.
    Secret,
    /// A successful outcome.
    Success,
    /// A recoverable problem.
    Warning,
    /// A failure.
    Error,
}

impl Style {
    /// The SGR parameter string for this role on the given palette.
    ///
    /// Empty means "terminal default" and still needs no escape sequence.
    fn sgr(self, dark: bool) -> &'static str {
        match (self, dark) {
            // Cyan reads well on dark backgrounds; blue reads better on light
            // ones, where cyan is low-contrast.
            (Style::Heading, true) => "1;36",
            (Style::Heading, false) => "1;34",
            (Style::Key, _) => "1",
            (Style::Value, _) => "",
            // Bright black is legible on dark; dim is the light-background
            // equivalent (and is unreadable on dark, hence the split).
            (Style::Muted, true) => "90",
            (Style::Muted, false) => "2",
            // Magenta marks the secret/secret boundary in both palettes: it is
            // the one role that must never be confused with a normal value.
            (Style::Secret, _) => "1;35",
            (Style::Success, _) => "32",
            // Yellow is poor on white; bold makes it readable on light.
            (Style::Warning, true) => "33",
            (Style::Warning, false) => "33;1",
            (Style::Error, _) => "31",
        }
    }
}

/// The inputs to [`Theme::resolve`], injected so it stays a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThemeEnv {
    /// `NO_COLOR` is set to a non-empty value.
    pub no_color: bool,
    /// `CLICOLOR_FORCE` is set to something other than `0`.
    pub clicolor_force: bool,
    /// stdout is a terminal.
    pub stdout_is_tty: bool,
}

impl ThemeEnv {
    /// Read the conventional environment variables and detect a TTY.
    pub fn detect() -> Self {
        let is_set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        let forced = std::env::var("CLICOLOR_FORCE").is_ok_and(|v| v != "0");
        Self {
            no_color: is_set("NO_COLOR"),
            clicolor_force: forced,
            stdout_is_tty: std::io::stdout().is_terminal(),
        }
    }
}

/// A resolved, ready-to-use theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    mode: ThemeMode,
    dark: bool,
    enabled: bool,
}

impl Default for Theme {
    /// The default is `auto`, which under `cargo test` means "no colour", so
    /// test output stays clean.
    fn default() -> Self {
        Self::resolve(ThemeMode::Auto, ThemeEnv::default())
    }
}

impl Theme {
    /// Resolve a mode against an environment snapshot. Pure.
    pub fn resolve(mode: ThemeMode, env: ThemeEnv) -> Self {
        if mode == ThemeMode::Off {
            return Self {
                mode,
                dark: true,
                enabled: false,
            };
        }
        if env.no_color {
            return Self {
                mode,
                dark: true,
                enabled: false,
            };
        }
        if env.clicolor_force {
            let dark = mode != ThemeMode::Light;
            return Self {
                mode,
                dark,
                enabled: true,
            };
        }
        let dark = match mode {
            ThemeMode::Dark => true,
            ThemeMode::Light => false,
            ThemeMode::Auto => true,
            ThemeMode::Off => true,
        };
        Self {
            mode,
            dark,
            enabled: env.stdout_is_tty,
        }
    }

    /// Resolve using the real process environment and the
    /// `STELLAR_TOOLKIT_THEME` variable (falling back to `auto`).
    pub fn from_env() -> Self {
        let raw = std::env::var("STELLAR_TOOLKIT_THEME").unwrap_or_default();
        let mode = ThemeMode::parse(&raw).unwrap_or(ThemeMode::Auto);
        Self::resolve(mode, ThemeEnv::detect())
    }

    /// Whether escape sequences will be emitted.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The requested mode, before resolution.
    pub fn mode(&self) -> ThemeMode {
        self.mode
    }

    /// Whether the dark palette is in use.
    pub fn is_dark(&self) -> bool {
        self.dark
    }

    /// Wrap `text` in this theme's escape sequences for `style`.
    ///
    /// When colour is disabled this returns `text` unchanged and emits no
    /// escape sequence whatsoever.
    pub fn paint(&self, style: Style, text: &str) -> String {
        let sgr = style.sgr(self.dark);
        if !self.enabled || sgr.is_empty() {
            return text.to_string();
        }
        format!("\x1b[{sgr}m{text}\x1b[0m")
    }

    /// Paint a field label, e.g. `Account (G)`.
    pub fn key(&self, label: &str) -> String {
        self.paint(Style::Key, label)
    }

    /// Paint a section heading.
    pub fn heading(&self, text: &str) -> String {
        self.paint(Style::Heading, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTY: ThemeEnv = ThemeEnv {
        no_color: false,
        clicolor_force: false,
        stdout_is_tty: true,
    };
    const PIPE: ThemeEnv = ThemeEnv {
        no_color: false,
        clicolor_force: false,
        stdout_is_tty: false,
    };

    #[test]
    fn mode_parsing_is_case_insensitive_and_accepts_never() {
        assert_eq!(ThemeMode::parse("dark"), Some(ThemeMode::Dark));
        assert_eq!(ThemeMode::parse("LIGHT"), Some(ThemeMode::Light));
        assert_eq!(ThemeMode::parse(" Auto "), Some(ThemeMode::Auto));
        assert_eq!(ThemeMode::parse(""), Some(ThemeMode::Auto));
        assert_eq!(ThemeMode::parse("off"), Some(ThemeMode::Off));
        assert_eq!(ThemeMode::parse("never"), Some(ThemeMode::Off));
        assert_eq!(ThemeMode::parse("chartreuse"), None);
        assert_eq!(ThemeMode::Off.as_str(), "off");
    }

    #[test]
    fn auto_on_a_tty_is_dark_and_enabled() {
        let t = Theme::resolve(ThemeMode::Auto, TTY);
        assert!(t.enabled());
        assert!(t.is_dark());
        assert_eq!(t.mode(), ThemeMode::Auto);
    }

    #[test]
    fn auto_off_a_tty_is_disabled() {
        let t = Theme::resolve(ThemeMode::Auto, PIPE);
        assert!(!t.enabled());
    }

    #[test]
    fn dark_and_light_select_the_palette() {
        let dark = Theme::resolve(ThemeMode::Dark, TTY);
        assert!(dark.enabled() && dark.is_dark());
        let light = Theme::resolve(ThemeMode::Light, TTY);
        assert!(light.enabled() && !light.is_dark());
        // ...and the palettes genuinely differ, otherwise the mode is a no-op.
        assert_ne!(
            dark.paint(Style::Heading, "x"),
            light.paint(Style::Heading, "x")
        );
    }

    #[test]
    fn explicit_palette_still_suppresses_colour_when_piped() {
        assert!(!Theme::resolve(ThemeMode::Dark, PIPE).enabled());
        assert!(!Theme::resolve(ThemeMode::Light, PIPE).enabled());
    }

    #[test]
    fn no_color_disables_colour_even_on_a_tty() {
        let env = ThemeEnv {
            no_color: true,
            ..TTY
        };
        for mode in [
            ThemeMode::Dark,
            ThemeMode::Light,
            ThemeMode::Auto,
            ThemeMode::Off,
        ] {
            let t = Theme::resolve(mode, env);
            assert!(!t.enabled(), "{mode:?} must respect NO_COLOR");
        }
        assert!(!Theme::resolve(ThemeMode::Auto, env)
            .paint(Style::Heading, "x")
            .contains('\x1b'));
    }

    #[test]
    fn clicolor_force_enables_colour_off_a_tty() {
        let env = ThemeEnv {
            clicolor_force: true,
            ..PIPE
        };
        let t = Theme::resolve(ThemeMode::Auto, env);
        assert!(t.enabled());
        assert!(t.paint(Style::Key, "x").contains('\x1b'));
        // Forced colour honours the requested palette rather than assuming dark.
        assert!(!Theme::resolve(ThemeMode::Light, env).is_dark());
    }

    #[test]
    fn no_color_outranks_clicolor_force() {
        let env = ThemeEnv {
            no_color: true,
            clicolor_force: true,
            stdout_is_tty: false,
        };
        assert!(!Theme::resolve(ThemeMode::Auto, env).enabled());
    }

    #[test]
    fn off_emits_no_escape_sequences_at_all() {
        for env in [TTY, PIPE] {
            let t = Theme::resolve(ThemeMode::Off, env);
            assert!(!t.enabled());
            for style in [
                Style::Heading,
                Style::Key,
                Style::Value,
                Style::Muted,
                Style::Secret,
                Style::Success,
                Style::Warning,
                Style::Error,
            ] {
                let painted = t.paint(style, "SENTINEL");
                assert_eq!(painted, "SENTINEL", "{style:?} must be verbatim");
                assert!(!painted.contains('\x1b'));
                assert!(!painted.contains("\x1b"));
            }
        }
    }

    #[test]
    fn off_outranks_every_environment_variable() {
        let env = ThemeEnv {
            no_color: false,
            clicolor_force: true,
            stdout_is_tty: true,
        };
        assert!(!Theme::resolve(ThemeMode::Off, env).enabled());
    }

    #[test]
    fn plain_value_never_gets_wrapped_even_when_enabled() {
        let t = Theme::resolve(ThemeMode::Dark, TTY);
        assert_eq!(t.paint(Style::Value, "1000000"), "1000000");
    }

    #[test]
    fn enabled_paint_wraps_and_resets() {
        let t = Theme::resolve(ThemeMode::Dark, TTY);
        let painted = t.paint(Style::Error, "boom");
        assert!(painted.starts_with("\x1b["));
        assert!(painted.ends_with("\x1b[0m"));
        assert!(painted.contains("boom"));
        // A secret is flagged, never dimmed: the danger must be legible.
        assert!(t.paint(Style::Secret, "S...").contains("\x1b[1;35m"));
    }

    #[test]
    fn default_theme_is_disabled_under_test() {
        assert!(!Theme::default().enabled());
        assert_eq!(Theme::default().paint(Style::Heading, "h"), "h");
    }

    #[test]
    fn detect_reads_the_conventional_variables() {
        // `detect` reads the process environment; in the test harness neither
        // variable is set, so the only thing asserted here is that it does not
        // panic and returns a coherent snapshot.
        let env = ThemeEnv::detect();
        assert_eq!(
            env.no_color,
            std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
        );
    }
}
