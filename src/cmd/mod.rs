//! The command line interface.
//!
//! Boundary rule: this module translates errors from the rest of the
//! crate into user-facing messages that say what to do. The other
//! modules never print. They return errors.

mod cli;
mod decrypt;
mod envname;
mod exec;
mod get;
mod help;
mod hint;
mod init;
mod lifecycle;
mod list;
mod lock;
mod migrate;
mod passphrase;
mod passwd;
pub mod paths;
mod prompt;
mod recipient;
mod rekey;
mod reveal;
mod scan;
mod set;
mod show;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::error::{ContextKind, ErrorKind};
use clap::{Command, CommandFactory, Parser};
use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction, signal};

use self::cli::{Cli, Globals, NAME, Shell, VERSION, Verb};
use crate::color::Profile;
use crate::json::{Json, Layout};
use crate::logging::{self, Options};
use crate::vault::{self, Vault};

/// Why a command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The child that exec ran exited with this code. It is propagated
    /// as is, with no error line, because the child already reported
    /// its own failure.
    #[error("command exited with code {0}")]
    ChildExit(u8),

    /// The command line could not be understood.
    #[error("{0}")]
    Usage(String),

    #[error("resolve {what} path: $HOME is not defined")]
    NoHome { what: &'static str },

    /// A failure already worded for the person at the terminal.
    #[error("{0}")]
    Message(String),

    /// Standard output could not be written.
    #[error("write output: write /dev/stdout: {}", crate::sys::describe(.0))]
    Output(#[from] io::Error),
}

/// Runs the command line `args`, program name first. A child exit code
/// from exec is propagated, and any other failure is logged and exits 1.
pub fn run(args: Vec<OsString>) -> ExitCode {
    disable_core_dumps();
    die_on_broken_pipe();
    exit_on_interrupt();

    let mut root = Cli::command();

    // Building resolves the tree: the help flags exist and every verb
    // carries the global flags.
    root.build();

    // A parse failure surfaces before the flag-driven logger exists, so
    // a logger must already be installed for its record. The scan
    // recovers --log-json first: without it, a malformed invocation
    // would report its own error as text in a stream the caller asked
    // to keep JSON.
    let scanned = scan::scan(&root, args.get(1..).unwrap_or_default());

    logging::setup(Options {
        verbose: false,
        json: scanned.log_json,
    });

    let outcome = match Cli::try_parse_from(&args) {
        Ok(cli) => {
            logging::setup(Options {
                verbose: cli.globals.verbose,
                json: cli.globals.log_json,
            });

            dispatch(&root, cli)
        }
        Err(err) => parse_failure(&root, &scanned.path, &err),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::ChildExit(code)) => ExitCode::from(code),
        Err(err) => {
            crate::error!(&err.to_string());

            ExitCode::FAILURE
        }
    }
}

/// Keeps a crash from writing process memory, and any key in it, to a
/// core file. The limit carries over to the child that exec runs, as
/// it does in the Go original.
fn disable_core_dumps() {
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
}

/// Puts SIGPIPE back to its default action, which ends the process.
///
/// The Rust runtime starts every program with SIGPIPE ignored, so a
/// write to a closed pipe comes back as an error. A filter such as
/// `reveal ... | head` would then end with exit code 1 and an error
/// record. The Go original ends by the signal, silently, as shell
/// tools do, and a script that expects that sees the same here.
fn die_on_broken_pipe() {
    // SAFETY: restoring the default action installs no handler, so
    // nothing of this program runs in signal context.
    let _ = unsafe { signal(Signal::SIGPIPE, SigHandler::SigDfl) };
}

/// Ends the process with exit code 1 on SIGINT, at any point in any
/// verb. The Go original does the same through its locked-memory
/// library. During exec that means the child is not waited for.
fn exit_on_interrupt() {
    extern "C" fn exit_now(_signal: nix::libc::c_int) {
        // SAFETY: _exit is async-signal-safe and never returns.
        unsafe { nix::libc::_exit(1) }
    }

    let action = SigAction::new(
        SigHandler::Handler(exit_now),
        SaFlags::empty(),
        SigSet::empty(),
    );

    // SAFETY: the handler only calls an async-signal-safe function.
    let _ = unsafe { sigaction(Signal::SIGINT, &action) };
}

/// Runs the parsed command line.
fn dispatch(root: &Command, cli: Cli) -> Result<(), Error> {
    let Some(verb) = cli.verb else {
        return print_help(root, &[]);
    };

    warn_loose_vault_permissions(&cli.globals);

    match verb {
        Verb::Help { command } => print_help(root, &command),
        Verb::Exec { command } => exec::run(&cli.globals, &command),
        Verb::Get { name } => get::run(&cli.globals, &name),
        Verb::Init => init::run(&cli.globals),
        Verb::List { prefix } => list::run(&cli.globals, prefix.as_deref().unwrap_or_default()),
        Verb::Disable { name, version } => lifecycle::disable(&cli.globals, &name, &version),
        Verb::Delete { name } => lifecycle::delete(&cli.globals, &name),
        Verb::Migrate => migrate::run(&cli.globals),
        Verb::Passwd {
            new_passphrase_file,
        } => passwd::run(&cli.globals, new_passphrase_file.as_deref()),
        Verb::Purge { name, yes } => lifecycle::purge(&cli.globals, &name, yes),
        Verb::Rekey => rekey::run(&cli.globals),
        Verb::Reveal {
            names,
            env,
            prefix,
            format,
        } => reveal::run(
            &cli.globals,
            &names,
            &reveal::Flags {
                env,
                prefix: prefix.as_deref().unwrap_or_default(),
                format: format.as_deref().unwrap_or(reveal::FORMAT_JSON),
            },
        ),
        Verb::Stale => list::run_stale(&cli.globals),
        Verb::Show { name } => show::run(&cli.globals, &name),
        Verb::Set {
            name,
            env_name,
            expires,
            revoke_previous,
        } => set::run(
            &cli.globals,
            &name,
            &set::Flags {
                env_name: env_name.as_deref(),
                expires: expires.as_deref(),
                revoke_previous,
            },
        ),
        Verb::Completion { shell: None } => print_help(root, &["completion".to_owned()]),
        Verb::Completion { shell: Some(shell) } => print_completion(shell),
    }
}

/// Warns when the vault file, its directory, or its WAL siblings grant
/// group or world access. It runs before every verb, including the ones
/// that never open the vault. A path that cannot be resolved is left
/// for the verb to report, and a missing vault, the normal case before
/// init, produces no warning.
fn warn_loose_vault_permissions(globals: &Globals) {
    let Ok(path) = paths::vault(globals.vault.as_deref(), &paths::process_env) else {
        return;
    };

    for loose in vault::loose_permissions(&path) {
        crate::warn!(
            "group or world can access a vault path, run chmod on it",
            "label" => loose.label,
            "loose_path" => loose.path.to_string_lossy().as_ref(),
            "mode" => format!("{:04o}", loose.mode).as_str(),
            "chmod" => format!("{:04o}", loose.recommend).as_str(),
        );
    }
}

/// Resolves the vault path and opens the vault, with advice when that
/// fails.
fn open_vault(globals: &Globals) -> Result<Vault, Error> {
    let path = paths::vault(globals.vault.as_deref(), &paths::process_env)?;
    let vault = Vault::open(&path).map_err(hint::vault)?;

    crate::debug!("vault opened", "vault_path" => path.to_string_lossy().as_ref());

    Ok(vault)
}

/// Prints `payload` as pretty JSON, or as compact JSON under `--json`.
///
/// A write error is reported, never dropped. Dropping it would let a
/// full disk or a broken pipe exit 0 with truncated output, which a
/// consuming script reads as success.
fn print_json(globals: &Globals, payload: &Json) -> Result<(), Error> {
    let layout = if globals.json {
        Layout::Compact
    } else {
        Layout::Pretty
    };

    print(&format!("{}\n", payload.render(layout)))
}

/// Turns what the argument parser refused into help, the version, or a
/// one-line usage error.
fn parse_failure(root: &Command, path: &[String], err: &clap::Error) -> Result<(), Error> {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            print_help(root, path)
        }
        ErrorKind::DisplayVersion => print(&format!("{NAME} {VERSION}\n")),
        // `completion` with a shell it does not know shows its own
        // help and succeeds, as the Go original does.
        ErrorKind::InvalidSubcommand if path == ["completion"] => print_help(root, path),
        _ => Err(Error::Usage(usage_message(root, path, err))),
    }
}

/// The parser's complaint as one line, with no usage block.
///
/// A stray argument is never repeated. Someone who types a value where
/// only a name belongs must not find it copied into the error line and
/// from there into scrollback or a log shipper. The message says how
/// many arguments the command takes.
fn usage_message(root: &Command, path: &[String], err: &clap::Error) -> String {
    if err.kind() == ErrorKind::UnknownArgument
        && let Some(stray) = err.get(ContextKind::InvalidArg)
        && !stray.to_string().starts_with('-')
    {
        return too_many_arguments(root, path);
    }

    if err.kind() == ErrorKind::MissingRequiredArgument
        && let Some(missing) = err.get(ContextKind::InvalidArg)
    {
        return format!("missing required argument: {missing}")
            .lines()
            .collect::<Vec<_>>()
            .join(" ");
    }

    let rendered = err.render().to_string();
    let first = rendered.lines().next().unwrap_or_default();

    first.strip_prefix("error: ").unwrap_or(first).to_owned()
}

/// Says how many arguments the command at `path` takes, for a command
/// line that carried one too many.
fn too_many_arguments(root: &Command, path: &[String]) -> String {
    let command = path
        .iter()
        .try_fold(root, |command, name| command.find_subcommand(name))
        .unwrap_or(root);

    let accepted = match command.get_positionals().count() {
        0 => "no arguments".to_owned(),
        1 => "1 argument".to_owned(),
        count => format!("{count} arguments"),
    };

    format!(
        "too many arguments: {} accepts {accepted}",
        command.get_name()
    )
}

/// Prints the help page of the command `path` names under the root.
///
/// The path is followed as far as it names commands, and what is left
/// over is ignored, so `help list extra` shows the page for `list`. A
/// first word that names no command is an unknown topic. That goes to
/// stderr with the root page and still succeeds. Both are what the Go
/// original does, and a script may depend on the exit code.
fn print_help(root: &Command, path: &[String]) -> Result<(), Error> {
    let mut command = root;
    let mut names = vec![NAME];

    for name in path {
        let Some(found) = command.find_subcommand(name) else {
            break;
        };

        command = found;
        names.push(command.get_name());
    }

    if names.len() == 1 && !path.is_empty() {
        let topic: Vec<String> = path.iter().map(|word| format!("`{word}`")).collect();

        let mut stderr = io::stderr().lock();

        let _ = write!(
            stderr,
            "Unknown help topic [{}]\n{}",
            topic.join(" "),
            help::render(root, &names, Profile::stderr())
        );

        return Ok(());
    }

    print(&help::render(command, &names, Profile::stdout()))
}

/// Prints the completion script for `shell`.
fn print_completion(shell: Shell) -> Result<(), Error> {
    let mut script = Vec::new();

    clap_complete::generate(
        clap_complete::Shell::from(shell),
        &mut Cli::command(),
        NAME,
        &mut script,
    );

    let mut stdout = io::stdout().lock();

    stdout.write_all(&script)?;
    stdout.flush()?;

    Ok(())
}

fn print(text: &str) -> Result<(), Error> {
    let mut stdout = io::stdout().lock();

    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::cli::Cli;
    use super::{scan, usage_message};

    /// The usage error for the command line `args`.
    fn refusal(args: &[&str]) -> String {
        let mut root = Cli::command();

        root.build();

        let line: Vec<String> = std::iter::once("sanctuary")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect();

        let os_line: Vec<std::ffi::OsString> = line.iter().map(Into::into).collect();
        let scanned = scan::scan(&root, &os_line[1..]);
        let err = Cli::try_parse_from(&line).expect_err("a usage error");

        usage_message(&root, &scanned.path, &err)
    }

    #[test]
    fn a_stray_argument_is_never_repeated() {
        for (args, want) in [
            (
                vec!["set", "api/one", "FAKE-STRAY-ARG"],
                "too many arguments: set accepts 1 argument",
            ),
            (
                vec!["get", "api/one", "FAKE-STRAY-ARG"],
                "too many arguments: get accepts 1 argument",
            ),
            (
                vec!["disable", "api/one", "1", "FAKE-STRAY-ARG"],
                "too many arguments: disable accepts 2 arguments",
            ),
            (
                vec!["list", "api", "FAKE-STRAY-ARG"],
                "too many arguments: list accepts 1 argument",
            ),
            (
                vec!["rekey", "FAKE-STRAY-ARG"],
                "too many arguments: rekey accepts no arguments",
            ),
            (
                vec!["--json", "passwd", "FAKE-STRAY-ARG"],
                "too many arguments: passwd accepts no arguments",
            ),
        ] {
            assert_eq!(refusal(&args), want, "{args:?}");
        }
    }

    #[test]
    fn other_usage_errors_keep_their_wording() {
        assert_eq!(
            refusal(&["set", "api/one", "--bogus=FAKE-STRAY-ARG"]),
            "unexpected argument '--bogus' found"
        );
        assert_eq!(refusal(&["set"]), "missing required argument: <NAME>");
    }
}
