//! A read of the command line that cannot fail.
//!
//! The logger must exist before the real parse runs, because the real
//! parse is what reports a malformed invocation. Without this scan, a
//! caller who asked for JSON logs would get the parse error as text in
//! a stream they asked to keep JSON. The scan reads the arguments the
//! way the real parse will: it walks the same command tree, so every
//! flag's arity holds, and it stops where exec hands the rest of the
//! line to the child.

use std::ffi::OsString;

use clap::Command;

/// What the scan learned.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Whether the line asks for JSON logs.
    pub log_json: bool,
    /// The commands the line names, outermost first.
    pub path: Vec<String>,
}

/// Scans `args`, the command line without the program name, against
/// the built command tree `root`.
pub fn scan(root: &Command, args: &[OsString]) -> Scan {
    let mut found = Scan::default();
    let mut current = root;
    let mut args = args.iter().map(|arg| arg.to_string_lossy());

    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }

        if let Some(flag) = arg.strip_prefix("--") {
            let (name, value) = match flag.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (flag, None),
            };

            // An unknown flag is the real parse's to report. The scan
            // carries on past it, so a JSON request after it counts.
            let Some(known) = current
                .get_arguments()
                .find(|arg| arg.get_long() == Some(name))
            else {
                continue;
            };

            let is_switch = known.is_require_equals_set() || !known.get_action().takes_values();

            if name == "log-json" {
                match value {
                    None => found.log_json = true,
                    Some("1" | "t" | "T" | "true" | "TRUE" | "True") => found.log_json = true,
                    Some("0" | "f" | "F" | "false" | "FALSE" | "False") => found.log_json = false,
                    // The real parse stops here, with what came before
                    // already decided.
                    Some(_) => break,
                }
            } else if !is_switch && value.is_none() {
                // The next argument is this flag's value, whatever it
                // looks like.
                args.next();
            }

            continue;
        }

        if arg.len() > 1 && arg.starts_with('-') {
            // No short flag takes a value.
            continue;
        }

        if let Some(sub) = current.find_subcommand(arg.as_ref()) {
            found.path.push(sub.get_name().to_owned());
            current = sub;

            continue;
        }

        if current.is_trailing_var_arg_set()
            || current
                .get_positionals()
                .any(clap::Arg::is_trailing_var_arg_set)
        {
            // Everything from here on belongs to the child command.
            break;
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use clap::CommandFactory;

    use super::scan;
    use crate::cmd::cli::Cli;

    fn scanned(args: &[&str]) -> super::Scan {
        let mut root = Cli::command();
        root.build();

        scan(&root, &args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    // Go: TestLogJSONRequested
    #[test]
    fn log_json_is_read_the_way_the_real_parse_reads_it() {
        let cases: [(&str, &[&str], bool); 17] = [
            ("no args", &[], false),
            ("plain verb", &["list"], false),
            ("before a bad flag", &["--log-json", "--bogusflag"], true),
            (
                "after a bad flag",
                &["--bogusflag", "--log-json", "list"],
                true,
            ),
            ("explicit true", &["--log-json=true", "--bogusflag"], true),
            ("explicit false", &["--log-json=false", "list"], false),
            ("last one wins", &["--log-json", "--log-json=false"], false),
            (
                "garbage value stops the parse",
                &["--log-json=garbage", "--log-json"],
                false,
            ),
            (
                "garbage after a request",
                &["--log-json", "--log-json=garbage"],
                true,
            ),
            (
                "after the verb",
                &["list", "--log-json", "--bogusflag"],
                true,
            ),
            ("before an unknown verb", &["--log-json", "bogusverb"], true),
            ("before the exec verb", &["--log-json", "exec", "app"], true),
            ("exec own flag region", &["exec", "--log-json", "app"], true),
            (
                "exec child arg without separator",
                &["exec", "app", "--log-json"],
                false,
            ),
            (
                "exec child arg behind the separator",
                &["exec", "--", "app", "--log-json"],
                false,
            ),
            ("behind a separator", &["list", "--", "--log-json"], false),
            (
                "a string flag's value",
                &["--passphrase-file", "--log-json", "list"],
                false,
            ),
        ];

        for (name, args, want) in cases {
            assert_eq!(scanned(args).log_json, want, "{name}: {args:?}");
        }
    }

    #[test]
    fn a_flag_value_written_with_equals_consumes_nothing() {
        assert!(scanned(&["--vault=/fake/path", "--log-json"]).log_json);
        assert!(scanned(&["set", "--env-name", "--log-json", "--log-json"]).log_json);
        assert!(!scanned(&["set", "--env-name", "--log-json"]).log_json);
    }

    #[test]
    fn the_path_names_the_commands_on_the_line() {
        assert_eq!(scanned(&[]).path, Vec::<String>::new());
        assert_eq!(scanned(&["--json", "set", "--help"]).path, ["set"]);
        assert_eq!(scanned(&["--vault", "set", "list"]).path, ["list"]);
        assert_eq!(
            scanned(&["completion", "bash", "-h"]).path,
            ["completion", "bash"]
        );
        assert_eq!(scanned(&["exec", "list"]).path, ["exec"]);
        assert_eq!(scanned(&["bogusverb", "set"]).path, ["set"]);
    }
}
