//! Color follows the destination.
//!
//! A terminal gets the richest color it advertises. A pipe gets none,
//! so a redirected record or help page carries no styling bytes. The
//! environment can override both ways: `NO_COLOR` turns color off
//! everywhere, and `CLICOLOR_FORCE` turns it on for a pipe at the
//! 16-color level.

use std::io::IsTerminal;

/// How much color a destination takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    /// No styling bytes at all.
    Plain,
    /// The 16 ANSI colors.
    Ansi,
    /// The 256-color palette.
    Ansi256,
    /// 24-bit color.
    TrueColor,
}

impl Profile {
    /// The profile for the process's stdout.
    pub fn stdout() -> Self {
        detect(std::io::stdout().is_terminal(), &|name| {
            std::env::var(name).ok()
        })
    }

    /// The profile for the process's stderr.
    pub fn stderr() -> Self {
        detect(std::io::stderr().is_terminal(), &|name| {
            std::env::var(name).ok()
        })
    }

    pub fn is_plain(self) -> bool {
        self == Self::Plain
    }

    /// Wraps `text` in the SGR parameters `sgr` and a reset, or returns
    /// it untouched for a plain destination. Styling is always the last
    /// step: nothing may compute a width on styled text.
    pub fn paint(self, sgr: &str, text: &str) -> String {
        if self.is_plain() {
            text.to_owned()
        } else {
            format!("\x1b[{sgr}m{text}\x1b[0m")
        }
    }
}

/// Decides the profile from whether the destination is a terminal and
/// from the environment, read through `env`.
pub fn detect(is_terminal: bool, env: &dyn Fn(&str) -> Option<String>) -> Profile {
    let var = |name: &str| env(name).unwrap_or_default();

    let forced = !matches!(var("CLICOLOR_FORCE").as_str(), "" | "0");

    if !var("NO_COLOR").is_empty() || (var("CLICOLOR") == "0" && !forced) {
        return Profile::Plain;
    }

    let advertised = if is_terminal {
        advertised_by_terminal(&var("TERM"), &var("COLORTERM"), &var("TERM_PROGRAM"))
    } else {
        Profile::Plain
    };

    if forced && advertised.is_plain() {
        Profile::Ansi
    } else {
        advertised
    }
}

fn advertised_by_terminal(term: &str, color_term: &str, term_program: &str) -> Profile {
    match color_term.to_ascii_lowercase().as_str() {
        "24bit" | "truecolor" => {
            // screen passes 24-bit sequences through only under tmux.
            return if term.starts_with("screen") && term_program != "tmux" {
                Profile::Ansi256
            } else {
                Profile::TrueColor
            };
        }
        "yes" | "true" => return Profile::Ansi256,
        _ => {}
    }

    match term {
        "alacritty" | "contour" | "rio" | "wezterm" | "xterm-ghostty" | "xterm-kitty" => {
            Profile::TrueColor
        }
        "linux" | "xterm" => Profile::Ansi,
        _ if term.contains("256color") => Profile::Ansi256,
        _ if term.contains("color") || term.contains("ansi") => Profile::Ansi,
        _ => Profile::Plain,
    }
}

#[cfg(test)]
mod tests {
    use super::{Profile, detect};

    fn profile(is_terminal: bool, vars: &[(&str, &str)]) -> Profile {
        detect(is_terminal, &|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn a_pipe_gets_no_color() {
        assert_eq!(profile(false, &[]), Profile::Plain);
        assert_eq!(
            profile(
                false,
                &[("COLORTERM", "truecolor"), ("TERM", "xterm-256color")]
            ),
            Profile::Plain
        );
    }

    #[test]
    fn a_terminal_gets_what_it_advertises() {
        assert_eq!(
            profile(true, &[("COLORTERM", "truecolor")]),
            Profile::TrueColor
        );
        assert_eq!(
            profile(true, &[("COLORTERM", "truecolor"), ("TERM", "dumb")]),
            Profile::TrueColor
        );
        assert_eq!(
            profile(true, &[("TERM", "xterm-256color")]),
            Profile::Ansi256
        );
        assert_eq!(profile(true, &[("TERM", "xterm")]), Profile::Ansi);
        assert_eq!(
            profile(true, &[("TERM", "xterm-kitty")]),
            Profile::TrueColor
        );
        assert_eq!(profile(true, &[("TERM", "dumb")]), Profile::Plain);
        assert_eq!(profile(true, &[]), Profile::Plain);
    }

    #[test]
    fn screen_takes_truecolor_only_under_tmux() {
        let screen = [("COLORTERM", "truecolor"), ("TERM", "screen-256color")];

        assert_eq!(profile(true, &screen), Profile::Ansi256);
        assert_eq!(
            profile(true, &[screen[0], screen[1], ("TERM_PROGRAM", "tmux")]),
            Profile::TrueColor
        );
    }

    #[test]
    fn forced_color_reaches_a_pipe_at_sixteen_colors() {
        assert_eq!(profile(false, &[("CLICOLOR_FORCE", "1")]), Profile::Ansi);
        assert_eq!(
            profile(
                false,
                &[
                    ("CLICOLOR_FORCE", "1"),
                    ("COLORTERM", "truecolor"),
                    ("TERM", "xterm-256color")
                ]
            ),
            Profile::Ansi
        );
        assert_eq!(profile(false, &[("CLICOLOR_FORCE", "0")]), Profile::Plain);
    }

    #[test]
    fn forced_color_does_not_lower_a_terminal() {
        assert_eq!(
            profile(true, &[("CLICOLOR_FORCE", "1"), ("COLORTERM", "truecolor")]),
            Profile::TrueColor
        );
    }

    #[test]
    fn no_color_beats_everything() {
        assert_eq!(
            profile(true, &[("NO_COLOR", "1"), ("COLORTERM", "truecolor")]),
            Profile::Plain
        );
        assert_eq!(
            profile(false, &[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")]),
            Profile::Plain
        );
        assert_eq!(
            profile(true, &[("NO_COLOR", ""), ("TERM", "xterm")]),
            Profile::Ansi
        );
    }

    #[test]
    fn clicolor_zero_turns_color_off_unless_forced() {
        assert_eq!(
            profile(true, &[("CLICOLOR", "0"), ("TERM", "xterm")]),
            Profile::Plain
        );
        assert_eq!(
            profile(
                true,
                &[
                    ("CLICOLOR", "0"),
                    ("CLICOLOR_FORCE", "1"),
                    ("TERM", "xterm")
                ]
            ),
            Profile::Ansi
        );
    }

    #[test]
    fn paint_leaves_a_plain_destination_untouched() {
        assert_eq!(Profile::Plain.paint("1;93", "WARN"), "WARN");
        assert_eq!(Profile::Ansi.paint("1;93", "WARN"), "\x1b[1;93mWARN\x1b[0m");
    }
}
