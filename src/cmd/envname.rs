//! Which environment variable names a secret may carry.

/// Reports whether `name` can be a shell variable name: letters,
/// digits, and underscores, not starting with a digit.
pub fn is_shell_identifier(name: &str) -> bool {
    let starts_with_digit = name
        .bytes()
        .next()
        .is_none_or(|first| first.is_ascii_digit());

    !starts_with_digit
        && name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Reports whether injecting `name` would hand over control of the
/// child, where a secret should only pass it data.
///
/// Every name here is a valid identifier, so this is the only thing
/// standing between a vault row and code execution. exec starts from
/// the caller's environment and adds to it, so an injected PATH
/// replaces the real one for the child. `reveal --format sh` emits
/// assignments that a shell sourcing them applies to the whole session.
///
/// The comparison is case-sensitive, because environment variables
/// are: a lowercase `path` is a different variable and carries none of
/// this meaning.
pub fn is_reserved(name: &str) -> bool {
    // The shell finds commands through PATH and splits words on IFS.
    // sh and bash execute ENV and BASH_ENV at startup. bash executes
    // PROMPT_COMMAND and PS4 as commands. The rest change how the
    // shell itself behaves.
    const RESERVED: [&str; 11] = [
        "PATH",
        "IFS",
        "ENV",
        "BASH_ENV",
        "PROMPT_COMMAND",
        "PS4",
        "SHELL",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
    ];

    // The dynamic loader reads these before a program's own code runs.
    // LD_PRELOAD and DYLD_INSERT_LIBRARIES load an arbitrary shared
    // object into every child.
    RESERVED.contains(&name) || name.starts_with("LD_") || name.starts_with("DYLD_")
}

#[cfg(test)]
mod tests {
    use super::{is_reserved, is_shell_identifier};

    #[test]
    fn shell_identifiers() {
        for name in ["A", "a", "_", "_A1", "API_KEY", "a1b2", "path"] {
            assert!(is_shell_identifier(name), "{name:?}");
        }

        for name in [
            "",
            "1A",
            "A-B",
            "A B",
            "A.B",
            "A=B",
            "caf\u{e9}",
            "A\n",
            "$A",
        ] {
            assert!(!is_shell_identifier(name), "{name:?}");
        }
    }

    #[test]
    fn reserved_names() {
        for name in [
            "PATH",
            "IFS",
            "ENV",
            "BASH_ENV",
            "PROMPT_COMMAND",
            "PS4",
            "SHELL",
            "SHELLOPTS",
            "BASHOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(is_reserved(name), "{name:?}");
        }

        for name in [
            "path",
            "Path",
            "MY_PATH",
            "PATHS",
            "LD",
            "ld_preload",
            "DYLD",
            "",
            "API_KEY",
        ] {
            assert!(!is_reserved(name), "{name:?}");
        }
    }
}
