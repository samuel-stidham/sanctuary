//! Reserved env names. Ports `cmd/envname_internal_test.go`.

use crate::support::Fixture;

/// Names a shell or the dynamic loader reads to decide what code runs.
/// Each is a valid shell identifier, which is why a denylist is needed.
const RESERVED: [&str; 16] = [
    "PATH",
    "IFS",
    "ENV",
    "BASH_ENV",
    "SHELL",
    "PS4",
    "SHELLOPTS",
    "BASHOPTS",
    "CDPATH",
    "GLOBIGNORE",
    "PROMPT_COMMAND",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

/// Names that are data. Environment variables are case-sensitive, so a
/// lowercase spelling is a different variable with none of the meaning,
/// and a name that merely mentions a reserved one is still data.
const ALLOWED: [&str; 10] = [
    "FAKE_API_KEY",
    "DATABASE_URL",
    "AWS_ACCESS_KEY_ID",
    "STRIPE_SECRET",
    "path",
    "Ld_Preload",
    "ifs",
    "MY_PATH",
    "PATH_TO_CERT",
    "OLD_SHELL",
];

// Go: TestIsReservedEnvName, TestSetRefusesReservedEnvName
//
// set is the gate where the message can reach the person typing the
// command.
#[test]
fn set_refuses_reserved_env_names() {
    let fixture = Fixture::new();

    for reserved in RESERVED {
        let name = format!("evil/{}", reserved.to_lowercase());

        fixture
            .fail("fake-value\n", &["set", &name, "--env-name", reserved])
            .assert_stderr(&format!("--env-name {reserved:?} is reserved"));
    }

    // Nothing was stored by any refusal.
    assert_eq!(fixture.ok("", &["list", "--json"]).stdout, "[]\n");
}

// Go: TestIsReservedEnvName, TestSetStillAcceptsOrdinaryEnvNames
//
// Guards against the denylist growing teeth it should not have.
#[test]
fn set_still_accepts_ordinary_env_names() {
    let fixture = Fixture::new();

    for allowed in ALLOWED {
        let name = format!("ok/{}", allowed.to_lowercase());
        let stored = fixture.set(&name, "fake-value", &["--env-name", allowed]);

        assert_eq!(
            stored.json()["envName"],
            allowed,
            "{allowed} is data and must be allowed"
        );
    }
}

// Go: TestExecSkipsAForgedReservedEnvName
//
// A row carrying PATH would otherwise replace the child's real PATH.
// Skipping is the safe outcome rather than an error: the child keeps
// the PATH it inherited, so a forged row cannot deny the run either.
#[test]
fn exec_skips_a_forged_reserved_env_name() {
    let fixture = Fixture::new();

    fixture.set(
        "api/legit",
        "fake-real-value",
        &["--env-name", "FAKE_LEGIT"],
    );
    fixture.set(
        "api/poison",
        "/tmp/attacker/bin",
        &["--env-name", "FAKE_POISON"],
    );

    fixture.forge_env_name("api/poison", "PATH");

    let ran = fixture.ok(
        "",
        &[
            "exec",
            "--",
            "sh",
            "-c",
            r#"printf '%s|%s' "$PATH" "$FAKE_LEGIT""#,
        ],
    );

    let (path, legit) = ran
        .stdout
        .split_once('|')
        .expect("child prints both variables");

    assert_ne!(
        path, "/tmp/attacker/bin",
        "the vault must not decide the child's PATH"
    );
    assert_eq!(
        legit, "fake-real-value",
        "an unrelated secret must still be delivered"
    );
    assert!(ran.stderr.contains("reserved"));

    // The forged row must pass the binding check, or this would be
    // testing metadata binding instead of the denylist.
    assert!(!ran.stderr.contains("does not match the sealed value"));
}

// Go: TestRevealSkipsAForgedReservedEnvName
//
// A sourced .envrc or secrets.fish applies these assignments to the
// whole shell session, so an emitted line is worse than an injected one.
#[test]
fn reveal_skips_a_forged_reserved_env_name() {
    let fixture = Fixture::new();

    fixture.set(
        "api/legit",
        "fake-real-value",
        &["--env-name", "FAKE_LEGIT"],
    );
    fixture.set(
        "api/poison",
        "/tmp/attacker/evil.so",
        &["--env-name", "FAKE_POISON"],
    );

    fixture.forge_env_name("api/poison", "LD_PRELOAD");

    let revealed = fixture.ok("", &["reveal", "--env", "--format", "sh"]);

    assert!(
        !revealed.stdout.contains("LD_PRELOAD"),
        "no assignment may set a variable the loader reads"
    );
    assert!(!revealed.stdout.contains("/tmp/attacker/evil.so"));
    assert!(
        revealed.stdout.contains("FAKE_LEGIT"),
        "an unrelated secret must still be emitted"
    );
    assert!(revealed.stderr.contains("reserved"));
}
