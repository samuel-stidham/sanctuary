//! The command line itself: path resolution, the version, the early
//! --log-json scan, and help. Ports `cmd/root_internal_test.go` and
//! `cmd/style_internal_test.go`.
//!
//! Presentation is the one place the port may differ from the
//! reference. The port has its own command name and version line, and
//! its help and usage errors are laid out by a Rust argument parser
//! rather than cobra. So these tests pin what a page says for both
//! binaries, and pin the reference's exact bytes for the reference alone.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::support::{Run, command_name, is_reference, msg, pty, run, sandboxed};

/// What one verb's help page must say, whatever lays it out.
struct Page {
    command: &'static str,
    /// The one-line summary the root help lists beside the command.
    summary: &'static str,
    /// The description and flag help the command's own page carries.
    says: &'static [&'static str],
}

const PAGES: [Page; 14] = [
    Page {
        command: "delete",
        summary: "Soft-delete a secret",
        says: &[
            "delete hides the secret from list and get. Versions and envelopes stay intact. \
             set revives it, purge destroys it.",
        ],
    },
    Page {
        command: "disable",
        summary: "Disable a secret version",
        says: &[
            "disable takes one version out of resolution without touching its envelope. \
             get resolves the newest remaining enabled version.",
        ],
    },
    Page {
        command: "exec",
        summary: "Run a command with secrets injected into its environment",
        says: &[
            "exec resolves every secret that has an env name, decrypts its newest enabled \
             version, and runs the command with those variables added to the environment. \
             The child's exit code is propagated.",
            "own flags must come before the command. Everything from the command name onward \
             belongs to the child, so a child flag never changes which vault or identity",
        ],
    },
    Page {
        command: "get",
        summary: "Fetch and verify the newest enabled version of a secret",
        says: &[
            "get decrypts the newest enabled version, verifies its address binding, and prints \
             metadata with the value redacted. Use reveal to display the plaintext.",
        ],
    },
    Page {
        command: "init",
        summary: "Create a new identity and vault",
        says: &[
            "init generates an X25519 identity, encrypts it with a passphrase, creates the \
             vault, and runs a seal/open self-test.",
        ],
    },
    Page {
        command: "list",
        summary: "List secrets, optionally under a name prefix",
        says: &[
            "list prints metadata for every non-deleted secret. Names are plaintext columns in \
             the MVP, so no identity is needed.",
        ],
    },
    Page {
        command: "migrate",
        summary: "Upgrade an older vault to the current format",
        says: &[
            "migrate re-seals every secret into the current envelope format, which binds the \
             env name and expiry into each value so a later metadata edit is detectable on \
             read. It needs your passphrase, because re-sealing decrypts each value. The \
             identity and the recipient do not change. Back up the vault file first.",
        ],
    },
    Page {
        command: "passwd",
        summary: "Change the identity passphrase",
        says: &[
            "passwd decrypts the identity with the current passphrase and re-encrypts it with \
             a new one. The key itself does not change, so the vault is untouched.",
            "--new-passphrase-file",
            "read the new passphrase from this file instead of prompting",
        ],
    },
    Page {
        command: "purge",
        summary: "Destroy a secret's envelopes forever",
        says: &[
            "purge erases every envelope of the secret and marks all versions destroyed. The \
             values are gone forever. Rows and history remain, so the secret name stays \
             readable in the vault forever, even after purge. It requires --yes.",
            "--yes",
            "confirm the irreversible destruction",
        ],
    },
    Page {
        command: "rekey",
        summary: "Rotate the identity and re-encrypt every live version",
        says: &[
            "rekey generates a new identity, re-encrypts every non-destroyed version to it \
             inside one transaction, and swaps the identity file. The old identity is kept as \
             a .bak sibling. The passphrase stays the same, use passwd to change it.",
        ],
    },
    Page {
        command: "reveal",
        summary: "Deliberately print secrets' plaintext values",
        says: &[
            "reveal is the single verb that displays plaintext. Everything else redacts. One \
             name prints one JSON object. Several names, --env, or --prefix select a batch \
             that decrypts with a single passphrase read. --format sh or fish emits assignment \
             lines ready to source into a shell session.",
            "--env",
            "select every secret that has an env name",
            "--prefix",
            "select every secret under a name prefix",
            "--format",
            "output format: json, sh, or fish",
        ],
    },
    Page {
        command: "set",
        summary: "Store a new version of a secret",
        says: &[
            "set reads the value from stdin, or from a no-echo prompt on a terminal, and \
             appends it as a new enabled version. Values never come from arguments. Prior \
             versions stay enabled unless --revoke-previous is passed.",
            "--env-name",
            "environment variable name used by exec",
            "--expires",
            "expiry as RFC3339 or YYYY-MM-DD (staleness flag, never deletion)",
            "--revoke-previous",
            "disable all older enabled versions",
        ],
    },
    Page {
        command: "show",
        summary: "Print a secret's metadata, never its value",
        says: &[
            "show prints existence, timestamps, expiry state, and version history. It needs no \
             identity and decrypts nothing.",
        ],
    },
    Page {
        command: "stale",
        summary: "List secrets past their expiry",
        says: &[
            "stale lists secrets whose expiry has passed. They still resolve. Expiry is a \
             staleness flag, never a deletion trigger.",
        ],
    },
];

/// The flags every verb accepts, with the help each carries.
const GLOBAL_FLAGS: [(&str, &str); 6] = [
    (
        "--vault",
        "path to the vault database (default $XDG_DATA_HOME/safetybox/vault.db)",
    ),
    (
        "--identity",
        "path to the identity file (default $XDG_CONFIG_HOME/safetybox/identity.age)",
    ),
    (
        "--passphrase-file",
        "read the identity passphrase from this file instead of prompting",
    ),
    (
        "--json",
        "emit compact JSON for pipes instead of pretty JSON",
    ),
    ("-v, --verbose", "enable debug logging"),
    ("--log-json", "emit logs as JSON"),
];

/// The description under the banner.
const ABOUT: &str = "Safetybox is a CLI-first secrets manager. Values are sealed in age envelopes. \
                     Metadata lives in SQLite.";

/// Every page the reference serves, cobra's own `completion` and `help`
/// included. The snapshots are named after these.
const REFERENCE_COMMANDS: [&str; 16] = [
    "completion",
    "delete",
    "disable",
    "exec",
    "get",
    "help",
    "init",
    "list",
    "migrate",
    "passwd",
    "purge",
    "rekey",
    "reveal",
    "set",
    "show",
    "stale",
];

/// The first and last rows of the figlet wordmark.
const ART_ROW_ONE: &str = r" ___   _   ___ ___ _______   _____  _____  __";
const ART_ROW_FOUR: &str = r"|___/_/ \_\_| |___| |_|   |_| |___/\___/_/\_\";

/// Runs the binary with no fixture: a bare home directory and `args`.
fn bare(home: &TempDir, args: &[&str]) -> Run {
    let mut command = sandboxed(home.path());
    command.args(args);

    run(command, "")
}

fn home() -> TempDir {
    TempDir::new().expect("create a home directory")
}

/// The line `--version` prints, without its newline.
fn version_line(home: &TempDir) -> String {
    let printed = bare(home, &["--version"]).assert_ok();

    assert!(printed.stderr.is_empty(), "the version goes to stdout only");

    printed
        .stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("unexpected --version output: {:?}", printed.stdout))
        .to_owned()
}

// Go: TestResolveVaultPathPrecedence
//
// Flag, then environment, then the XDG default, then the home
// fallback. The resolved path is observable in the not-found error.
#[test]
fn vault_path_precedence() {
    struct Case {
        name: &'static str,
        flag: Option<&'static str>,
        env: &'static str,
        xdg_data: &'static str,
        want: fn(&Path) -> PathBuf,
    }

    let cases = [
        Case {
            name: "flag wins over env and xdg",
            flag: Some("/from/flag/vault.db"),
            env: "/from/env/vault.db",
            xdg_data: "/from/xdg",
            want: |_| PathBuf::from("/from/flag/vault.db"),
        },
        Case {
            name: "env wins over xdg",
            flag: None,
            env: "/from/env/vault.db",
            xdg_data: "/from/xdg",
            want: |_| PathBuf::from("/from/env/vault.db"),
        },
        Case {
            name: "xdg data home",
            flag: None,
            env: "",
            xdg_data: "/from/xdg",
            want: |_| PathBuf::from("/from/xdg/safetybox/vault.db"),
        },
        Case {
            name: "home fallback",
            flag: None,
            env: "",
            xdg_data: "",
            want: |home| home.join(".local/share/safetybox/vault.db"),
        },
    ];

    for case in cases {
        let home = home();
        let mut command = sandboxed(home.path());

        // An empty variable counts as unset, exactly as in the Go suite.
        command
            .env("SAFETYBOX_VAULT", case.env)
            .env("XDG_DATA_HOME", case.xdg_data);

        if let Some(flag) = case.flag {
            command.args(["--vault", flag]);
        }

        command.arg("list");

        let want = (case.want)(home.path());

        run(command, "").assert_fails().assert_stderr(&format!(
            "open {}: {}: {}",
            want.display(),
            msg::VAULT_NOT_FOUND,
            msg::init_hint()
        ));

        assert!(
            !want.exists(),
            "{}: a failed open must create nothing",
            case.name
        );
    }
}

// Go: TestResolveIdentityPathPrecedence
#[test]
fn identity_path_precedence() {
    struct Case {
        name: &'static str,
        flag: Option<&'static str>,
        env: &'static str,
        xdg_config: &'static str,
        want: fn(&Path) -> PathBuf,
    }

    let cases = [
        Case {
            name: "flag wins over env and xdg",
            flag: Some("/from/flag/identity.age"),
            env: "/from/env/identity.age",
            xdg_config: "/from/xdg",
            want: |_| PathBuf::from("/from/flag/identity.age"),
        },
        Case {
            name: "env wins over xdg",
            flag: None,
            env: "/from/env/identity.age",
            xdg_config: "/from/xdg",
            want: |_| PathBuf::from("/from/env/identity.age"),
        },
        Case {
            name: "xdg config home",
            flag: None,
            env: "",
            xdg_config: "/from/xdg",
            want: |_| PathBuf::from("/from/xdg/safetybox/identity.age"),
        },
        Case {
            name: "home fallback",
            flag: None,
            env: "",
            xdg_config: "",
            want: |home| home.join(".config/safetybox/identity.age"),
        },
    ];

    for case in cases {
        let home = home();
        let mut command = sandboxed(home.path());

        command
            .env("SAFETYBOX_IDENTITY", case.env)
            .env("XDG_CONFIG_HOME", case.xdg_config);

        if let Some(flag) = case.flag {
            command.args(["--identity", flag]);
        }

        // passwd names the resolved identity path when it is missing.
        command.arg("passwd");

        let want = (case.want)(home.path());

        run(command, "").assert_fails().assert_stderr(&format!(
            "{}: {}: {}",
            want.display(),
            msg::IDENTITY_NOT_FOUND,
            msg::init_hint()
        ));

        assert!(
            !want.exists(),
            "{}: a failed load must create nothing",
            case.name
        );
    }
}

// Go: TestVersionIsWiredToCobra
//
// One plain line that opens with the command name. The port also says
// which implementation it is and which reference release it matches,
// so the two are never mistaken for each other on one machine.
#[test]
fn version_flag_prints_one_plain_line() {
    let home = home();
    let line = version_line(&home);

    assert!(!line.contains(['\n', '\x1b']), "one plain line: {line:?}");
    assert!(
        line.starts_with(&format!("{} ", command_name())),
        "the version line opens with the command name: {line:?}"
    );

    if is_reference() {
        assert!(line.starts_with("safetybox version v"), "{line:?}");
    } else {
        assert!(
            line.contains("(Rust, compatible with safetybox v"),
            "the port names its implementation and its reference release: {line:?}"
        );
    }
}

// Go: TestLogJSONRequested
//
// The early logger installs before flags are parsed, so the pre-parse
// --log-json scan is what keeps a requested JSON stream JSON when the
// parse itself fails. The exec cases guard the interspersion rule:
// everything from the child command onward belongs to the child, so a
// child --log-json must never switch safetybox's own logs.
//
// Every case here fails, because no vault exists, and the format of the
// one error record on stderr shows what the scan decided.
#[test]
fn log_json_is_recognized_before_the_command_line_parses() {
    let cases: [(&str, &[&str], bool); 12] = [
        ("plain verb", &["list"], false),
        ("before a bad flag", &["--log-json", "--bogusflag"], true),
        (
            "after a bad flag",
            &["--bogusflag", "--log-json", "list"],
            true,
        ),
        (
            "explicit true before a bad flag",
            &["--log-json=true", "--bogusflag"],
            true,
        ),
        ("explicit false", &["--log-json=false", "list"], false),
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
        (
            "consumed as a string flag's value",
            &["--passphrase-file", "--log-json", "list"],
            false,
        ),
    ];

    for (name, args, want_json) in cases {
        let home = home();
        let failed = bare(&home, args).assert_fails();

        let record = failed
            .stderr
            .lines()
            .last()
            .unwrap_or_else(|| panic!("{name}: no record"));
        let is_json = serde_json::from_str::<serde_json::Value>(record)
            .is_ok_and(|parsed| parsed["level"] == "ERROR");

        assert_eq!(is_json, want_json, "{name}: {args:?} logged {record:?}");

        if !want_json {
            assert!(
                record.starts_with("ERRO "),
                "{name}: {args:?} logged {record:?}"
            );
        }
    }
}

// Go: TestLogJSONRequested ("no args")
//
// With nothing to run there is nothing to log: help goes to stdout.
#[test]
fn no_arguments_log_nothing() {
    let home = home();
    let helped = bare(&home, &[]).assert_ok();

    assert!(helped.stderr.is_empty());
}

// A usage error is one error record on stderr with exit 1, and nothing
// on stdout. The wording belongs to each binary's argument parser, so
// it is pinned for the reference alone.
#[test]
fn usage_errors_are_one_error_record() {
    let home = home();

    let cases: [(&[&str], &str); 7] = [
        (&["--bogusflag"], "ERRO unknown flag: --bogusflag\n"),
        (
            &["bogusverb"],
            "ERRO unknown command \"bogusverb\" for \"safetybox\"\n",
        ),
        (&["set"], "ERRO accepts 1 arg(s), received 0\n"),
        (&["get", "a", "b"], "ERRO accepts 1 arg(s), received 2\n"),
        (
            &["disable", "only-a-name"],
            "ERRO accepts 2 arg(s), received 1\n",
        ),
        (
            &["list", "a", "b"],
            "ERRO accepts at most 1 arg(s), received 2\n",
        ),
        (
            &["init", "extra"],
            "ERRO unknown command \"extra\" for \"safetybox init\"\n",
        ),
    ];

    for (args, reference_wording) in cases {
        let failed = bare(&home, args).assert_fails();

        assert!(
            failed.stdout.is_empty(),
            "{args:?} must print nothing on stdout"
        );
        assert!(
            failed.stderr.starts_with("ERRO ") && failed.stderr.ends_with('\n'),
            "{args:?} must log one error record: {:?}",
            failed.stderr
        );
        assert_eq!(
            failed.stderr.lines().count(),
            1,
            "{args:?} must log one line and no usage block: {:?}",
            failed.stderr
        );

        if is_reference() {
            assert_eq!(failed.stderr, reference_wording, "{args:?}");
        }
    }
}

/// Where the reference's help snapshots live.
fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/conformance/golden")
        .join(format!("{name}.txt"))
}

/// Compares the reference's output with its snapshot, so a change in
/// the Go binary's help is noticed. The port lays help out its own way
/// and is not held to these bytes. `UPDATE_GOLDEN=1` rewrites the
/// snapshot.
#[track_caller]
fn assert_reference_golden(name: &str, actual: &str) {
    if !is_reference() {
        return;
    }

    let path = golden_path(name);

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().expect("golden dir")).expect("create golden dir");
        fs::write(&path, actual).expect("write golden");

        return;
    }

    let want = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", path.display()));

    assert_eq!(
        actual,
        want,
        "output differs from the reference snapshot {}",
        path.display()
    );
}

/// Help output, with the reference's version replaced so its snapshot
/// holds across releases.
fn help(home: &TempDir, args: &[&str], color: bool) -> String {
    let mut command = sandboxed(home.path());
    command.args(args);

    if color {
        // CLICOLOR_FORCE colors a writer that is not a terminal, at the
        // 16-color ANSI profile.
        command
            .env("CLICOLOR_FORCE", "1")
            .env("COLORTERM", "truecolor")
            .env("TERM", "xterm-256color");
    }

    let helped = run(command, "").assert_ok();

    assert!(
        helped.stderr.is_empty(),
        "help goes to stdout only: {}",
        helped.stderr
    );

    match version_line(home).strip_prefix("safetybox version ") {
        Some(version) => helped
            .stdout
            .replace(&format!("Safetybox {version}\n"), "Safetybox <VERSION>\n"),
        None => helped.stdout,
    }
}

/// Asserts `page` says `fragment`, ignoring how the layout wrapped it.
#[track_caller]
fn assert_says(page: &str, fragment: &str, context: &str) {
    let flatten = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");

    assert!(
        flatten(page).contains(&flatten(fragment)),
        "{context} must say {fragment:?}\n{page}"
    );
}

// Go: TestRootHelpShowsBannerPlain, TestDisplayName
//
// The root page carries the banner, the product name with the version,
// the description, every verb with its summary, and every global flag.
#[test]
fn root_help_shows_banner_plain() {
    let home = home();
    let out = help(&home, &["--help"], false);

    assert!(
        out.starts_with(ART_ROW_ONE),
        "the banner opens the root help"
    );
    assert!(out.contains(ART_ROW_FOUR));
    assert!(!out.contains('\x1b'), "piped help carries no styling bytes");

    assert_says(&out, ABOUT, "root help");

    for page in &PAGES {
        assert_says(
            &out,
            &format!("{} {}", page.command, page.summary),
            "root help",
        );
    }

    for command in ["completion", "help"] {
        assert_says(&out, command, "root help");
    }

    for (flag, says) in GLOBAL_FLAGS {
        assert_says(&out, flag, "root help");
        assert_says(&out, says, "root help");
    }

    if is_reference() {
        assert_says(&out, "Safetybox <VERSION>", "root help");
    } else {
        // The header names the product, then repeats what --version says
        // after the command name.
        let line = version_line(&home);
        let version = line
            .strip_prefix(&format!("{} ", command_name()))
            .expect("the version line opens with the command name");

        assert_says(&out, &format!("Safetybox {version}"), "root help");
    }

    assert_reference_golden("help/root", &out);
}

// Go: TestBareRootPrintsHelp
#[test]
fn bare_root_prints_help() {
    let home = home();

    assert_eq!(help(&home, &[], false), help(&home, &["--help"], false));
}

// Go: TestSubcommandHelpPlain, TestSubcommandHelpMatchesStockCobra
//
// Each verb's page carries its description, its own flags, and the
// global flags, with no banner and no styling when piped. The Go suite
// also pins byte parity with stock cobra. That holds for the reference
// through its snapshots, and does not apply to the port.
#[test]
fn subcommand_help_says_what_the_reference_says() {
    let home = home();

    for page in &PAGES {
        let command = page.command;
        let out = help(&home, &[command, "--help"], false);

        assert!(
            !out.contains(ART_ROW_ONE),
            "{command} help must not carry the banner"
        );
        assert!(
            !out.contains('\x1b'),
            "{command} help must be plain when piped"
        );
        assert_says(&out, &format!("{} {command}", command_name()), command);

        for fragment in page.says {
            assert_says(&out, fragment, command);
        }

        for (flag, says) in GLOBAL_FLAGS {
            assert_says(&out, flag, command);
            assert_says(&out, says, command);
        }

        // `help <command>` and `<command> --help` are the same page.
        assert_eq!(
            help(&home, &["help", command], false),
            out,
            "help {command}"
        );
    }

    for command in REFERENCE_COMMANDS {
        if is_reference() {
            assert_reference_golden(
                &format!("help/{command}"),
                &help(&home, &[command, "--help"], false),
            );
        }
    }
}

// Each completion generator has its own help page and emits a script
// that names the command it completes.
#[test]
fn completion_generates_a_script_for_each_shell() {
    let home = home();

    for shell in ["bash", "fish", "powershell", "zsh"] {
        let page = help(&home, &["completion", shell, "--help"], false);

        assert_says(&page, shell, "completion help");
        assert_reference_golden(&format!("help/completion-{shell}"), &page);

        let script = bare(&home, &["completion", shell]).assert_ok();

        assert!(script.stderr.is_empty());
        assert!(
            script.stdout.contains(&command_name()),
            "the {shell} script must complete this command"
        );
    }
}

// Go: TestHelpColorForced, TestBannerGradientOrder,
// TestFlagBlockStylesOnlyTheSpec
//
// Under forced color the banner rows carry the gradient in order. At
// the 16-color profile the four gradient stops land on two codes: rows
// one and two on bright magenta, rows three and four on bright red.
// The rest of the page is styled too. How headings and flags are
// styled is the parser's layout, pinned for the reference alone:
// headings bold yellow, and only the spec segment of a flag line
// styled, never its indent or description.
#[test]
fn forced_color_help_carries_the_banner_gradient() {
    let home = home();

    let root = help(&home, &["--help"], true);
    let banner: Vec<&str> = root.lines().take(4).collect();

    assert_eq!(banner[0], format!("\x1b[95m{ART_ROW_ONE}\x1b[0m"));
    assert!(banner[1].starts_with("\x1b[95m") && banner[1].ends_with("\x1b[0m"));
    assert!(banner[2].starts_with("\x1b[91m") && banner[2].ends_with("\x1b[0m"));
    assert_eq!(banner[3], format!("\x1b[91m{ART_ROW_FOUR}\x1b[0m"));

    let below_banner = root.lines().skip(4).collect::<Vec<_>>().join("\n");

    assert!(
        below_banner.contains("\x1b["),
        "forced color must reach the page below the banner"
    );

    let set = help(&home, &["set", "--help"], true);

    assert!(
        set.contains("\x1b["),
        "forced color must reach a verb's help"
    );

    if is_reference() {
        assert!(set.contains("\x1b[1;33mFlags:\x1b[0m\n"));
        assert!(
            set.contains(
                "      \x1b[32m--env-name string\x1b[0m                environment variable name used by exec\n"
            ),
            "only the spec segment of a flag line is styled"
        );
        assert!(
            set.contains("  \x1b[32m-v, --verbose[=true|false]\x1b[0m     enable debug logging\n")
        );
    }

    assert_reference_golden("help/root.color", &root);
    assert_reference_golden("help/set.color", &set);
}

// NO_COLOR beats CLICOLOR_FORCE, so a forced-color request in an
// environment that opted out stays plain.
#[test]
fn no_color_beats_forced_color() {
    let home = home();

    let mut command = sandboxed(home.path());
    command
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1")
        .arg("--help");

    let helped = run(command, "").assert_ok();

    assert!(!helped.stdout.contains('\x1b'));
}

// Go: TestBannerGradientRampDirection
//
// On a terminal that takes 24-bit color the banner carries the full
// gradient, one stop per row, magenta at the top ramping to orange at
// the bottom: red held at 255, green strictly climbing, blue strictly
// falling. The stops are pinned as the reference renders them.
#[test]
fn terminal_help_carries_the_truecolor_gradient() {
    let home = home();

    let mut command = sandboxed(home.path());

    // TERM=dumb keeps the reference from probing the terminal for its
    // colors, which a test pseudo-terminal never answers.
    command
        .env("COLORTERM", "truecolor")
        .env("TERM", "dumb")
        .arg("--help");

    let (displayed, status) = pty::capture_on_terminal(command);

    assert!(status.success());

    let stops: Vec<(u32, u32, u32)> = displayed
        .lines()
        .take(4)
        .map(|row| {
            let channels: Vec<u32> = row
                .strip_prefix("\x1b[38;2;")
                .and_then(|rest| rest.split_once('m'))
                .unwrap_or_else(|| panic!("banner row must open with a 24-bit color: {row:?}"))
                .0
                .split(';')
                .map(|channel| channel.parse().expect("a color channel"))
                .collect();

            assert!(
                row.ends_with("\x1b[0m"),
                "banner row must reset its color: {row:?}"
            );

            (channels[0], channels[1], channels[2])
        })
        .collect();

    assert_eq!(
        stops,
        [
            (255, 95, 210),
            (255, 108, 171),
            (255, 121, 133),
            (255, 135, 94)
        ]
    );

    for pair in stops.windows(2) {
        assert!(pair[1].1 > pair[0].1, "green must climb toward orange");
        assert!(pair[1].2 < pair[0].2, "blue must fall toward orange");
    }

    // The page below the banner is styled on a terminal too. The
    // reference keeps its palette colors for headings and flag specs.
    let below_banner = displayed.lines().skip(4).collect::<Vec<_>>().join("\n");

    assert!(below_banner.contains("\x1b["));

    if is_reference() {
        assert!(displayed.contains("\x1b[1;33mUsage:\x1b[0m\n"));
        assert!(displayed.contains("  \x1b[32m-h, --help[=true|false]\x1b[0m"));
    }
}

// A terminal that opted out of color gets plain help.
#[test]
fn terminal_help_honors_no_color() {
    let home = home();

    let mut command = sandboxed(home.path());
    command
        .env("NO_COLOR", "1")
        .env("COLORTERM", "truecolor")
        .env("TERM", "dumb")
        .arg("--help");

    let (displayed, status) = pty::capture_on_terminal(command);

    assert!(status.success());
    assert!(!displayed.contains('\x1b'));
    assert!(displayed.contains(ART_ROW_ONE));
}

// A path flag passed empty counts as not passed. A script that writes
// `--vault "$UNSET"` falls back to the environment and the default.
#[test]
fn an_empty_path_flag_counts_as_not_passed() {
    let home = TempDir::new().expect("temp dir");
    let passphrase = home.path().join("passphrase");

    fs::write(&passphrase, "fake-passphrase\n").expect("write");
    fs::set_permissions(&passphrase, fs::Permissions::from_mode(0o600)).expect("chmod");

    let passphrase = passphrase.to_str().expect("utf-8 path");

    bare(&home, &["--passphrase-file", passphrase, "init"]).assert_ok();

    for args in [
        &["--vault", "", "list", "--json"][..],
        &["--vault=", "list", "--json"],
        &["--identity", "", "list", "--json"],
        &["--identity=", "list", "--json"],
        &["--passphrase-file", "", "list", "--json"],
        &["--passphrase-file=", "list", "--json"],
    ] {
        assert_eq!(bare(&home, args).assert_ok().stdout, "[]\n", "{args:?}");
    }

    // The empty identity flag still reaches the default identity.
    bare(
        &home,
        &["--identity=", "--passphrase-file", passphrase, "rekey"],
    )
    .assert_ok();
}

// Help never fails, whatever it is asked about. A topic that names no
// command is reported on stderr. Words after a command are ignored.
// `completion` with a shell it does not know shows its own help.
#[test]
fn help_and_completion_succeed_on_what_they_do_not_know() {
    let home = TempDir::new().expect("temp dir");

    let unknown = bare(&home, &["help", "fake-topic"]).assert_ok();

    assert_eq!(unknown.stdout, "");
    assert!(
        unknown
            .stderr
            .starts_with("Unknown help topic [`fake-topic`]\n"),
        "{}",
        unknown.stderr
    );

    let listed = bare(&home, &["help", "list"]).assert_ok();

    assert_eq!(
        bare(&home, &["help", "list", "fake-extra"])
            .assert_ok()
            .stdout,
        listed.stdout
    );

    let completion = bare(&home, &["help", "completion"]).assert_ok();
    let odd_shell = bare(&home, &["completion", "fake-shell"]).assert_ok();

    assert_eq!(odd_shell.stdout, completion.stdout);
    assert_eq!(odd_shell.stderr, "");
}
