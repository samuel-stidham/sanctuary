//! The command line: every verb, flag, and line of help text.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::builder::{OsStringValueParser, TypedValueParser};
use clap::{ArgAction, Args, Parser, Subcommand};

/// The command name. The Go original is `safetybox`. The port goes by a
/// name of its own so both can sit on one PATH.
pub const NAME: &str = "sanctuary";

/// What follows the command name on the version line: this build's
/// own version, and the release of the Go original it behaves like.
/// `reference` names that release.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (Rust, compatible with safetybox ",
    crate::reference::tag!(),
    ")"
);

/// Parses the value of a switch written as `--flag=value`, accepting
/// the spellings the Go original accepts.
fn switch_value(text: &str) -> Result<bool, String> {
    match text {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err("want true or false".to_owned()),
    }
}

#[derive(Debug, Parser)]
#[command(
    name = NAME,
    version = VERSION,
    about = "A single-user, versioned secrets vault",
    long_about = "Safetybox is a CLI-first secrets manager. Values are sealed in age envelopes. \
                  Metadata lives in SQLite.",
    disable_version_flag = true,
    args_override_self = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub globals: Globals,

    /// Print version
    #[arg(long, action = ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    pub verb: Option<Verb>,
}

/// The flags every verb accepts.
///
/// Reads a path flag exactly as given, the empty string included.
///
/// The stock path parser refuses an empty value. The Go original takes
/// one and treats the flag as not passed, so a script that writes
/// `--vault "$UNSET"` falls back to the environment and the default.
fn any_path() -> impl TypedValueParser<Value = PathBuf> {
    OsStringValueParser::new().map(PathBuf::from)
}

/// A switch may be written bare or as `--flag=true` and `--flag=false`,
/// and a path may start with a dash, both as in the Go original.
#[derive(Debug, Args)]
pub struct Globals {
    /// path to the vault database (default $XDG_DATA_HOME/safetybox/vault.db)
    #[arg(long, global = true, value_name = "PATH", allow_hyphen_values = true, value_parser = any_path())]
    pub vault: Option<PathBuf>,

    /// path to the identity file (default $XDG_CONFIG_HOME/safetybox/identity.age)
    #[arg(long, global = true, value_name = "PATH", allow_hyphen_values = true, value_parser = any_path())]
    pub identity: Option<PathBuf>,

    /// read the identity passphrase from this file instead of prompting
    #[arg(long, global = true, value_name = "PATH", allow_hyphen_values = true, value_parser = any_path())]
    pub passphrase_file: Option<PathBuf>,

    /// emit compact JSON for pipes instead of pretty JSON
    #[arg(
        long,
        global = true,
        num_args = 0..=1,
        require_equals = true,
        default_value = "false",
        default_missing_value = "true",
        value_parser = switch_value
    )]
    pub json: bool,

    /// enable debug logging
    #[arg(
        short,
        long,
        global = true,
        num_args = 0..=1,
        require_equals = true,
        default_value = "false",
        default_missing_value = "true",
        value_parser = switch_value
    )]
    pub verbose: bool,

    /// emit logs as JSON
    #[arg(
        long,
        global = true,
        num_args = 0..=1,
        require_equals = true,
        default_value = "false",
        default_missing_value = "true",
        value_parser = switch_value
    )]
    pub log_json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Verb {
    /// Generate a shell completion script
    #[command(
        long_about = "Generate the completion script for sanctuary for the specified shell. \
                      See each shell's help for how to use the generated script."
    )]
    Completion {
        #[command(subcommand)]
        shell: Option<Shell>,
    },

    /// Soft-delete a secret
    #[command(
        long_about = "delete hides the secret from list and get. Versions and envelopes stay \
                      intact. set revives it, purge destroys it."
    )]
    Delete { name: String },

    /// Disable a secret version
    #[command(
        long_about = "disable takes one version out of resolution without touching its envelope. \
                      get resolves the newest remaining enabled version."
    )]
    Disable { name: String, version: String },

    /// Run a command with secrets injected into its environment
    #[command(
        long_about = "exec resolves every secret that has an env name, decrypts its newest \
                      enabled version, and runs the command with those variables added to the \
                      environment. The child's exit code is propagated.\n\n\
                      sanctuary's own flags must come before the command. Everything from the command \
                      name onward belongs to the child, so a child flag never changes which vault \
                      or identity sanctuary reads."
    )]
    Exec {
        /// the command to run, and its arguments
        #[arg(required = true, trailing_var_arg = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },

    /// Fetch and verify the newest enabled version of a secret
    #[command(
        long_about = "get decrypts the newest enabled version, verifies its address binding, and \
                      prints metadata with the value redacted. Use reveal to display the \
                      plaintext."
    )]
    Get { name: String },

    /// Help about any command
    Help {
        #[arg(value_name = "COMMAND")]
        command: Vec<String>,
    },

    /// Create a new identity and vault
    #[command(
        long_about = "init generates an X25519 identity, encrypts it with a passphrase, creates \
                      the vault, and runs a seal/open self-test."
    )]
    Init,

    /// List secrets, optionally under a name prefix
    #[command(
        long_about = "list prints metadata for every non-deleted secret. Names are plaintext \
                      columns in the MVP, so no identity is needed."
    )]
    List { prefix: Option<String> },

    /// Upgrade an older vault to the current format
    #[command(
        long_about = "migrate re-seals every secret into the current envelope format, which \
                      binds the env name and expiry into each value so a later metadata edit is \
                      detectable on read. It needs your passphrase, because re-sealing decrypts \
                      each value. The identity and the recipient do not change. Back up the vault \
                      file first."
    )]
    Migrate,

    /// Change the identity passphrase
    #[command(
        long_about = "passwd decrypts the identity with the current passphrase and re-encrypts \
                      it with a new one. The key itself does not change, so the vault is \
                      untouched."
    )]
    Passwd {
        /// read the new passphrase from this file instead of prompting
        #[arg(long, value_name = "PATH", allow_hyphen_values = true, value_parser = any_path())]
        new_passphrase_file: Option<PathBuf>,
    },

    /// Destroy a secret's envelopes forever
    #[command(
        long_about = "purge erases every envelope of the secret and marks all versions \
                      destroyed. The values are gone forever. Rows and history remain, so the \
                      secret name stays readable in the vault forever, even after purge. It \
                      requires --yes."
    )]
    Purge {
        name: String,

        /// confirm the irreversible destruction
        #[arg(
            long,
            num_args = 0..=1,
            require_equals = true,
            default_value = "false",
            default_missing_value = "true",
            value_parser = switch_value
        )]
        yes: bool,
    },

    /// Rotate the identity and re-encrypt every live version
    #[command(
        long_about = "rekey generates a new identity, re-encrypts every non-destroyed version to \
                      it inside one transaction, and swaps the identity file. The old identity \
                      is kept as a .bak sibling. The passphrase stays the same, use passwd to \
                      change it."
    )]
    Rekey,

    /// Deliberately print secrets' plaintext values
    #[command(
        long_about = "reveal is the single verb that displays plaintext. Everything else \
                      redacts. One name prints one JSON object. Several names, --env, or --prefix \
                      select a batch that decrypts with a single passphrase read. --format sh or \
                      fish emits assignment lines ready to source into a shell session."
    )]
    Reveal {
        #[arg(value_name = "NAME")]
        names: Vec<String>,

        /// select every secret that has an env name
        #[arg(
            long,
            num_args = 0..=1,
            require_equals = true,
            default_value = "false",
            default_missing_value = "true",
            value_parser = switch_value
        )]
        env: bool,

        /// select every secret under a name prefix
        #[arg(long, value_name = "PREFIX", allow_hyphen_values = true)]
        prefix: Option<String>,

        /// output format: json, sh, or fish (default json)
        #[arg(long, value_name = "FORMAT", allow_hyphen_values = true)]
        format: Option<String>,
    },

    /// Store a new version of a secret
    #[command(
        long_about = "set reads the value from stdin, or from a no-echo prompt on a terminal, \
                      and appends it as a new enabled version. Values never come from arguments. \
                      Prior versions stay enabled unless --revoke-previous is passed."
    )]
    Set {
        name: String,

        /// environment variable name used by exec
        #[arg(long, value_name = "NAME", allow_hyphen_values = true)]
        env_name: Option<String>,

        /// expiry as RFC3339 or YYYY-MM-DD (staleness flag, never deletion)
        #[arg(long, value_name = "WHEN", allow_hyphen_values = true)]
        expires: Option<String>,

        /// disable all older enabled versions
        #[arg(
            long,
            num_args = 0..=1,
            require_equals = true,
            default_value = "false",
            default_missing_value = "true",
            value_parser = switch_value
        )]
        revoke_previous: bool,
    },

    /// Print a secret's metadata, never its value
    #[command(
        long_about = "show prints existence, timestamps, expiry state, and version history. It \
                      needs no identity and decrypts nothing."
    )]
    Show { name: String },

    /// List secrets past their expiry
    #[command(
        long_about = "stale lists secrets whose expiry has passed. They still resolve. Expiry is \
                      a staleness flag, never a deletion trigger."
    )]
    Stale,
}

/// The shells a completion script can be generated for.
#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Shell {
    /// Generate the completion script for bash
    Bash,
    /// Generate the completion script for fish
    Fish,
    /// Generate the completion script for powershell
    Powershell,
    /// Generate the completion script for zsh
    Zsh,
}

impl From<Shell> for clap_complete::Shell {
    fn from(shell: Shell) -> Self {
        match shell {
            Shell::Bash => Self::Bash,
            Shell::Fish => Self::Fish,
            Shell::Powershell => Self::PowerShell,
            Shell::Zsh => Self::Zsh,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, VERSION, switch_value};

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn the_version_names_the_implementation_and_the_reference_release() {
        let (own, reference) = VERSION.split_once(' ').expect("two parts");

        assert_eq!(own, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            reference,
            format!(
                "(Rust, compatible with safetybox {})",
                crate::reference::TAG
            )
        );
    }

    #[test]
    fn switch_values_follow_the_reference_spellings() {
        for yes in ["1", "t", "T", "true", "TRUE", "True"] {
            assert_eq!(switch_value(yes), Ok(true));
        }

        for no in ["0", "f", "F", "false", "FALSE", "False"] {
            assert_eq!(switch_value(no), Ok(false));
        }

        for bad in ["", "yes", "tRuE", "garbage"] {
            assert!(switch_value(bad).is_err());
        }
    }
}
