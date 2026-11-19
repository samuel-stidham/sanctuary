//! Help pages.
//!
//! The pages are laid out here rather than by the argument parser, so
//! color follows the destination the same way the logs do, and the
//! root page can carry the banner.

use std::fmt::Write as _;

use clap::{Arg, Command};

use super::cli::VERSION;
use crate::color::Profile;

/// The figlet "small" rendering of SANCTUARY, the font the Go original
/// uses for its own name. Pure ASCII on purpose: these glyphs render
/// evenly in every monospace font.
const WORDMARK: [&str; 4] = [
    r" ___   _   _  _  ___ _____ _   _  _   _____   __",
    r"/ __| /_\ | \| |/ __|_   _| | | |/_\ | _ \ \ / /",
    r"\__ \/ _ \| .` | (__  | | | |_| / _ \|   /\ V /",
    r"|___/_/ \_\_|\_|\___| |_|  \___/_/ \_\_|_\ |_|",
];

/// The name under the banner. The Go original shows its own name
/// there, so a person who runs `sanctuary` sees Sanctuary.
const DISPLAY_NAME: &str = "Sanctuary";

/// One gradient stop of the banner: the color itself, and the nearest
/// color in each smaller palette.
struct Stop {
    rgb: (u8, u8, u8),
    palette: u8,
    ansi: u8,
}

/// One stop per wordmark row, magenta at the top ramping to orange at
/// the bottom. Red is held at 255 so the ramp never dips through muddy
/// browns, and green and blue move in equal steps so four rows band
/// evenly.
const STOPS: [Stop; 4] = [
    Stop {
        rgb: (255, 95, 210),
        palette: 206,
        ansi: 95,
    },
    Stop {
        rgb: (255, 108, 171),
        palette: 205,
        ansi: 95,
    },
    Stop {
        rgb: (255, 121, 133),
        palette: 211,
        ansi: 91,
    },
    Stop {
        rgb: (255, 135, 94),
        palette: 209,
        ansi: 91,
    },
];

/// Headings are bold yellow, command names and flag specs green. Both
/// are palette indexes, so a themed terminal keeps its own gold and
/// green.
const HEADING: &str = "1;33";
const ITEM: &str = "32";

impl Stop {
    fn style(&self, profile: Profile) -> String {
        match profile {
            Profile::Plain => String::new(),
            Profile::Ansi => self.ansi.to_string(),
            Profile::Ansi256 => format!("38;5;{}", self.palette),
            Profile::TrueColor => {
                let (red, green, blue) = self.rgb;

                format!("38;2;{red};{green};{blue}")
            }
        }
    }
}

/// The wordmark with each row tinted by its gradient stop.
fn banner(profile: Profile) -> String {
    WORDMARK
        .iter()
        .zip(&STOPS)
        .map(|(row, stop)| profile.paint(&stop.style(profile), row))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders the help page of `command`, which `path` names from the
/// root down. The root page alone carries the banner and the version.
pub fn render(command: &Command, path: &[&str], profile: Profile) -> String {
    let mut page = String::new();
    let is_root = path.len() == 1;
    let invocation = path.join(" ");

    if is_root {
        writeln!(page, "{}\n\n{DISPLAY_NAME} {VERSION}\n", banner(profile))
            .expect("write to a String");
    }

    let about = command.get_long_about().or_else(|| command.get_about());

    if let Some(about) = about {
        writeln!(page, "{}\n", about.to_string().trim_end()).expect("write to a String");
    }

    let positionals: Vec<&Arg> = command
        .get_positionals()
        .filter(|arg| !arg.is_hide_set())
        .collect();
    let subcommands: Vec<&Command> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .collect();
    let (global, local): (Vec<&Arg>, Vec<&Arg>) = command
        .get_arguments()
        .filter(|arg| !arg.is_positional() && !arg.is_hide_set())
        .partition(|arg| arg.is_global_set() && !is_root);

    let mut usage = format!("{invocation} [OPTIONS]");

    for positional in &positionals {
        usage.push(' ');
        usage.push_str(&positional_spec(positional));
    }

    if !subcommands.is_empty() {
        usage.push_str(" <COMMAND>");
    }

    writeln!(page, "{}\n  {usage}", profile.paint(HEADING, "Usage:")).expect("write to a String");

    let rows = |entries: Vec<(String, String)>| {
        let width = entries
            .iter()
            .map(|(cell, _)| cell.chars().count())
            .max()
            .unwrap_or(0);
        let mut block = String::new();

        for (cell, about) in entries {
            // Pad on the plain text and style last: styling bytes count
            // toward a string's length and take up no columns.
            let indent = cell.len() - cell.trim_start().len();
            let padding = " ".repeat(width - cell.chars().count());

            writeln!(
                block,
                "  {}{}{padding}   {about}",
                &cell[..indent],
                profile.paint(ITEM, &cell[indent..]),
            )
            .expect("write to a String");
        }

        block
    };

    if !subcommands.is_empty() {
        let entries = subcommands
            .iter()
            .map(|sub| {
                let about = sub.get_about().map(ToString::to_string).unwrap_or_default();

                (sub.get_name().to_owned(), about)
            })
            .collect();

        write!(
            page,
            "\n{}\n{}",
            profile.paint(HEADING, "Commands:"),
            rows(entries)
        )
        .expect("write to a String");
    }

    let flag_rows = |args: Vec<&Arg>| {
        rows(
            args.into_iter()
                .map(|arg| (flag_spec(arg), flag_help(arg)))
                .collect(),
        )
    };

    if !local.is_empty() {
        write!(
            page,
            "\n{}\n{}",
            profile.paint(HEADING, "Options:"),
            flag_rows(local)
        )
        .expect("write to a String");
    }

    if !global.is_empty() {
        write!(
            page,
            "\n{}\n{}",
            profile.paint(HEADING, "Global Options:"),
            flag_rows(global)
        )
        .expect("write to a String");
    }

    if !subcommands.is_empty() {
        writeln!(
            page,
            "\nUse \"{invocation} <COMMAND> --help\" for more information about a command."
        )
        .expect("write to a String");
    }

    page
}

/// How a positional argument reads in a usage line.
fn positional_spec(arg: &Arg) -> String {
    let name = value_name(arg);
    let many = arg
        .get_num_args()
        .is_some_and(|range| range.max_values() > 1);
    let ellipsis = if many { "..." } else { "" };

    if arg.is_required_set() {
        format!("<{name}>{ellipsis}")
    } else {
        format!("[{name}]{ellipsis}")
    }
}

/// How a flag reads in an options block: `-v, --verbose` or
/// `    --vault <PATH>`. A switch shows no value, though it accepts one.
fn flag_spec(arg: &Arg) -> String {
    let mut spec = match arg.get_short() {
        Some(short) => format!("-{short}, "),
        None => "    ".to_owned(),
    };

    if let Some(long) = arg.get_long() {
        spec.push_str("--");
        spec.push_str(long);
    }

    if arg.get_action().takes_values() && !arg.is_require_equals_set() {
        write!(spec, " <{}>", value_name(arg)).expect("write to a String");
    }

    spec
}

/// What a flag's row says. The parser words its own help flag
/// differently for a command with a long description, so that one row
/// is worded here.
fn flag_help(arg: &Arg) -> String {
    if arg.get_id() == "help" {
        return "Print help".to_owned();
    }

    arg.get_help().map(ToString::to_string).unwrap_or_default()
}

fn value_name(arg: &Arg) -> String {
    arg.get_value_names()
        .and_then(|names| names.first())
        .map_or_else(|| arg.get_id().as_str().to_uppercase(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use clap::{Command, CommandFactory};

    use super::{STOPS, WORDMARK, banner, render};
    use crate::cmd::cli::Cli;
    use crate::color::Profile;

    fn root() -> Command {
        let mut root = Cli::command();
        root.build();

        root
    }

    fn page(path: &[&str], profile: Profile) -> String {
        let root = root();
        let command = path[1..].iter().fold(&root, |at, name| {
            at.find_subcommand(name).expect("a command")
        });

        render(command, path, profile)
    }

    // Go: TestBannerGradientOrder, TestBannerGradientRampDirection
    //
    // One stop per row, red held, green strictly climbing, blue
    // strictly falling.
    #[test]
    fn banner_gradient_ramps_from_magenta_to_orange() {
        assert_eq!(WORDMARK.len(), STOPS.len());

        for pair in STOPS.windows(2) {
            assert_eq!(pair[0].rgb.0, 255);
            assert!(
                pair[1].rgb.1 > pair[0].rgb.1,
                "green must climb toward orange"
            );
            assert!(
                pair[1].rgb.2 < pair[0].rgb.2,
                "blue must fall toward orange"
            );
        }

        let rows: Vec<String> = banner(Profile::TrueColor)
            .lines()
            .map(str::to_owned)
            .collect();

        assert_eq!(
            rows[0],
            format!("\x1b[38;2;255;95;210m{}\x1b[0m", WORDMARK[0])
        );
        assert_eq!(
            rows[3],
            format!("\x1b[38;2;255;135;94m{}\x1b[0m", WORDMARK[3])
        );
    }

    #[test]
    fn banner_falls_back_to_the_nearest_smaller_palette() {
        let palette: Vec<String> = banner(Profile::Ansi256)
            .lines()
            .map(str::to_owned)
            .collect();
        let ansi: Vec<String> = banner(Profile::Ansi).lines().map(str::to_owned).collect();

        assert!(palette[0].starts_with("\x1b[38;5;206m"));
        assert!(palette[3].starts_with("\x1b[38;5;209m"));
        assert!(ansi[0].starts_with("\x1b[95m") && ansi[1].starts_with("\x1b[95m"));
        assert!(ansi[2].starts_with("\x1b[91m") && ansi[3].starts_with("\x1b[91m"));
        assert_eq!(banner(Profile::Plain), WORDMARK.join("\n"));
    }

    // Go: TestRootHelpShowsBannerPlain
    #[test]
    fn root_page_carries_the_banner_and_every_command() {
        let page = page(&["sanctuary"], Profile::Plain);

        assert!(page.starts_with(WORDMARK[0]));
        assert!(page.contains("\n\nSanctuary 0."));
        assert!(page.contains("(Rust, compatible with safetybox v"));
        assert!(page.contains("Usage:\n  sanctuary [OPTIONS] <COMMAND>\n"));
        assert!(page.contains("  reveal       Deliberately print secrets' plaintext values\n"));
        assert!(page.contains("  -v, --verbose                  enable debug logging\n"));
        assert!(page.contains("      --vault <PATH>             path to the vault database"));
        assert!(page.ends_with(
            "\nUse \"sanctuary <COMMAND> --help\" for more information about a command.\n"
        ));
        assert!(!page.contains('\x1b'));
        assert!(!page.contains("Global Options:"));
    }

    // Go: TestSubcommandHelpPlain
    #[test]
    fn verb_page_has_no_banner_and_lists_global_options() {
        let page = page(&["sanctuary", "set"], Profile::Plain);

        assert!(page.starts_with("set reads the value from stdin"));
        assert!(page.contains("Usage:\n  sanctuary set [OPTIONS] <NAME>\n"));
        assert!(page.contains("\nOptions:\n      --env-name <NAME>"));
        assert!(page.contains("      --revoke-previous   disable all older enabled versions\n"));
        assert!(page.contains("  -h, --help              Print help\n"));
        assert!(page.contains("\nGlobal Options:\n      --vault <PATH>"));
        assert!(!page.contains(WORDMARK[0]));
    }

    #[test]
    fn usage_line_shows_each_positional_shape() {
        assert!(
            page(&["sanctuary", "list"], Profile::Plain)
                .contains("  sanctuary list [OPTIONS] [PREFIX]\n")
        );
        assert!(
            page(&["sanctuary", "exec"], Profile::Plain)
                .contains("  sanctuary exec [OPTIONS] <COMMAND>...\n")
        );
        assert!(
            page(&["sanctuary", "reveal"], Profile::Plain)
                .contains("  sanctuary reveal [OPTIONS] [NAME]...\n")
        );
        assert!(
            page(&["sanctuary", "disable"], Profile::Plain)
                .contains("  sanctuary disable [OPTIONS] <NAME> <VERSION>\n")
        );
        assert!(
            page(&["sanctuary", "completion", "zsh"], Profile::Plain)
                .contains("  sanctuary completion zsh [OPTIONS]\n")
        );
    }

    // Go: TestHelpColorForced, TestFlagBlockStylesOnlyTheSpec
    //
    // Only the heading, the command name, and the flag spec are
    // styled, never an indent, the padding, or a description.
    #[test]
    fn styling_covers_only_headings_names_and_specs() {
        let page = page(&["sanctuary", "set"], Profile::Ansi);

        assert!(page.contains("\x1b[1;33mUsage:\x1b[0m\n"));
        assert!(page.contains("\x1b[1;33mOptions:\x1b[0m\n"));
        assert!(page.contains(
            "      \x1b[32m--env-name <NAME>\x1b[0m   environment variable name used by exec\n"
        ));
        assert!(page.contains("  \x1b[32m-v, --verbose\x1b[0m "));

        let root = super::render(&root(), &["sanctuary"], Profile::Ansi);

        assert!(root.contains("  \x1b[32mrekey\x1b[0m        Rotate the identity"));
    }
}
