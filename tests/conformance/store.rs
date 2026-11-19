//! Store semantics. Ports `internal/vault/store_test.go` through the
//! verbs that drive each store operation.
//!
//! The Go tests call the store with fake sealers. Here every operation
//! goes through its verb with real envelopes, and the stored rows are
//! read back directly where the JSON output does not show them.

use std::thread;

use serde_json::Value;

use crate::support::envelope;
use crate::support::{Fixture, VALUE_ONE, VALUE_TWO, msg};

fn names(items: &[Value]) -> Vec<&str> {
    items
        .iter()
        .map(|item| item["name"].as_str().expect("an entry has a name"))
        .collect()
}

/// A timestamp safetybox writes: RFC3339, UTC, whole seconds.
#[track_caller]
fn assert_stored_time(value: &Value) {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("timestamp must be a string: {value}"));

    assert_eq!(
        text.len(),
        20,
        "timestamp must be whole seconds in UTC: {text}"
    );
    assert!(text.ends_with('Z'), "timestamp must be UTC: {text}");
    assert_eq!(&text[10..11], "T", "timestamp must be RFC3339: {text}");
}

// Go: TestAppendVersionCreatesAndIncrements
#[test]
fn append_version_creates_and_increments() {
    let fixture = Fixture::new();

    let first = fixture.set("api/testing/fake", VALUE_ONE, &[]);

    assert_eq!(
        first.stdout,
        "{\n  \"name\": \"api/testing/fake\",\n  \"version\": 1,\n  \"state\": \"enabled\",\n  \"revokedPrevious\": 0\n}\n"
    );

    let second = fixture.set("api/testing/fake", VALUE_TWO, &[]).json();

    assert_eq!(second["version"], 2);
    assert_eq!(
        second["revokedPrevious"], 0,
        "updates must not auto-disable prior versions"
    );

    let got = fixture.ok("", &["get", "api/testing/fake"]).json();

    assert_eq!(got["name"], "api/testing/fake");
    assert_eq!(got["version"], 2);
    assert_eq!(got["state"], "enabled");
    assert_eq!(got["expired"], false);
    assert_stored_time(&got["createdAt"]);
    assert_stored_time(&got["updatedAt"]);

    let keys: Vec<&str> = got
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "version",
            "state",
            "createdAt",
            "updatedAt",
            "expired",
            "value"
        ]
    );

    // Each envelope binds to its own row.
    let newest = fixture.newest_enabled("api/testing/fake");
    let frame = fixture.open_frame(&fixture.key(), &newest);

    assert_eq!(newest.number, 2);
    assert_eq!(frame.address, envelope::address("api/testing/fake", 2));
}

// Go: TestAppendVersionRevokePrevious
#[test]
fn append_version_revoke_previous() {
    let fixture = Fixture::new();

    fixture.set("rotate/me", VALUE_ONE, &[]);
    fixture.set("rotate/me", VALUE_ONE, &[]);

    let third = fixture
        .set("rotate/me", VALUE_TWO, &["--revoke-previous"])
        .json();
    assert_eq!(third["revokedPrevious"], 2);

    let shown = fixture.ok("", &["show", "rotate/me"]).json();
    let states: Vec<&str> = shown["versions"]
        .as_array()
        .expect("show lists versions")
        .iter()
        .map(|version| version["state"].as_str().expect("a version has a state"))
        .collect();

    assert_eq!(states, ["disabled", "disabled", "enabled"]);
}

// Go: TestAppendVersionRejectsBadNames
#[test]
fn append_version_rejects_bad_names() {
    let fixture = Fixture::new();

    for name in [
        "",
        "/leading",
        "trailing/",
        "has space",
        "new\nline",
        "double//slash",
        ".leading-dot",
        "seg/.dot",
        "ünïcode",
        "semi;colon",
    ] {
        fixture
            .fail(format!("{VALUE_ONE}\n"), &["set", name])
            .assert_stderr(msg::INVALID_NAME);
    }

    // A leading dash needs the separator to reach set as a name at all.
    fixture
        .fail(format!("{VALUE_ONE}\n"), &["set", "--", "-leading-dash"])
        .assert_stderr(msg::INVALID_NAME);

    // The grammar: segments of letters, digits, dots, underscores, and
    // dashes, joined by single slashes.
    for name in [
        "a",
        "A1",
        "api/stripe/live",
        "with.dot/and_under-score",
        "9/8/7",
    ] {
        fixture.set(name, VALUE_ONE, &[]);
    }

    assert_eq!(fixture.ok("", &["list", "--json"]).json_array().len(), 5);
}

// The invalid-name error quotes the name, so a newline in it cannot
// start a line of its own.
#[test]
fn invalid_name_error_quotes_the_name() {
    let fixture = Fixture::new();

    let refused = fixture.fail(
        format!("{VALUE_ONE}\n"),
        &["set", "new\nWARN fake injected line"],
    );

    assert_eq!(
        refused.stderr, "ERRO \"new\\nWARN fake injected line\": invalid secret name\n",
        "the name is quoted and the record stays on one line"
    );
}

// Go: TestAppendVersionStoresAttributes
#[test]
fn append_version_stores_attributes() {
    let fixture = Fixture::new();

    let stored = fixture
        .set(
            "api/testing/fake",
            VALUE_ONE,
            &[
                "--env-name",
                "FAKE_TEST_KEY",
                "--expires",
                "2099-06-07T08:09:10Z",
            ],
        )
        .json();

    assert_eq!(stored["envName"], "FAKE_TEST_KEY");
    assert_eq!(stored["expiresAt"], "2099-06-07T08:09:10Z");

    let keys: Vec<&str> = stored
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "version",
            "state",
            "envName",
            "expiresAt",
            "revokedPrevious"
        ]
    );

    // A later set without attributes keeps them.
    let kept = fixture.set("api/testing/fake", VALUE_TWO, &[]).json();

    assert_eq!(kept["envName"], "FAKE_TEST_KEY");
    assert_eq!(kept["expiresAt"], "2099-06-07T08:09:10Z");
}

// --expires takes RFC3339 or a bare date, which means midnight UTC, and
// stores UTC either way.
#[test]
fn expires_accepts_rfc3339_or_a_bare_date() {
    let fixture = Fixture::new();

    for (given, stored) in [
        ("2099-01-02", "2099-01-02T00:00:00Z"),
        ("2099-01-02T03:04:05Z", "2099-01-02T03:04:05Z"),
        ("2099-01-02T03:04:05+02:00", "2099-01-02T01:04:05Z"),
        ("2099-01-02T03:04:05.999Z", "2099-01-02T03:04:05Z"),
    ] {
        let shown = fixture
            .set("exp/forms", VALUE_ONE, &["--expires", given])
            .json();

        assert_eq!(shown["expiresAt"], stored, "--expires {given}");
        fixture.ok("", &["get", "exp/forms"]);
    }

    for invalid in [
        "tomorrow",
        "2099-13-01",
        "01/02/2099",
        "2099-01-02 03:04:05",
    ] {
        fixture
            .fail(
                format!("{VALUE_ONE}\n"),
                &["set", "exp/bad", "--expires", invalid],
            )
            .assert_stderr(&format!(
                "parse --expires {invalid:?}: use RFC3339 or YYYY-MM-DD"
            ));
    }
}

// set reads the value from stdin and strips exactly one trailing
// newline, so `echo value | safetybox set` stores what was typed.
#[test]
fn set_strips_one_trailing_newline() {
    let fixture = Fixture::new();

    for (index, (stdin, stored)) in [
        ("fake-value\n", "fake-value"),
        ("fake-value", "fake-value"),
        ("fake-value\r\n", "fake-value"),
        ("fake-value\n\n", "fake-value\n"),
        ("line one\nline two\n", "line one\nline two"),
        ("  padded  \n", "  padded  "),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("strip/{index}");

        fixture.ok(stdin, &["set", &name]);
        assert_eq!(fixture.reveal_value(&name), stored, "stdin {stdin:?}");
    }

    for empty in ["", "\n", "\r\n"] {
        fixture
            .fail(empty, &["set", "strip/empty"])
            .assert_stderr("value must not be empty");
    }

    fixture
        .fail("", &["show", "strip/empty"])
        .assert_stderr(msg::SECRET_NOT_FOUND);
}

// Go: TestNewestEnabledSkipsDisabled
#[test]
fn newest_enabled_skips_disabled() {
    let fixture = Fixture::new();

    fixture.set("skip/disabled", VALUE_ONE, &[]);
    fixture.set("skip/disabled", VALUE_TWO, &[]);

    let disabled = fixture.ok("", &["disable", "skip/disabled", "2"]);

    assert_eq!(
        disabled.stdout,
        "{\n  \"name\": \"skip/disabled\",\n  \"version\": 2,\n  \"result\": \"disabled\"\n}\n"
    );
    assert_eq!(
        fixture.ok("", &["get", "skip/disabled"]).json()["version"],
        1
    );

    // Disabling twice is a no-op.
    fixture.ok("", &["disable", "skip/disabled", "2"]);

    fixture.ok("", &["disable", "skip/disabled", "1"]);

    fixture
        .fail("", &["get", "skip/disabled"])
        .assert_stderr("secret skip/disabled has no enabled version")
        .assert_stderr(msg::VERSION_NOT_FOUND)
        .assert_stderr("`show` the secret to see its versions");

    // The secret still lists, with its latest version number.
    let listed = fixture.ok("", &["list", "--json"]).json_array();

    assert_eq!(names(&listed), ["skip/disabled"]);
    assert_eq!(listed[0]["latestVersion"], 2);
}

// Go: TestNewestEnabledErrors
#[test]
fn newest_enabled_errors() {
    let fixture = Fixture::new();

    fixture
        .fail("", &["get", "missing/secret"])
        .assert_stderr("secret missing/secret: secret not found");

    fixture.set("deleted/secret", VALUE_ONE, &[]);
    fixture.ok("", &["delete", "deleted/secret"]);

    fixture
        .fail("", &["get", "deleted/secret"])
        .assert_stderr(msg::SECRET_DELETED)
        .assert_stderr("`set` a new value to revive it or `purge` it for good");

    fixture
        .fail("", &["reveal", "deleted/secret"])
        .assert_stderr(msg::SECRET_DELETED);
    fixture
        .fail("", &["show", "missing/secret"])
        .assert_stderr(msg::SECRET_NOT_FOUND);
}

// Go: TestSetRevivesSoftDeletedSecret
#[test]
fn set_revives_soft_deleted_secret() {
    let fixture = Fixture::new();

    fixture.set("revive/me", VALUE_ONE, &[]);
    fixture.ok("", &["delete", "revive/me"]);

    let revived = fixture.set("revive/me", VALUE_TWO, &[]).json();
    assert_eq!(
        revived["version"], 2,
        "version numbers survive delete and revive"
    );

    let shown = fixture.ok("", &["show", "revive/me"]).json();
    assert!(
        shown.get("deletedAt").is_none(),
        "a revived secret carries no tombstone"
    );

    assert_eq!(fixture.reveal_value("revive/me"), VALUE_TWO);
}

// Go: TestListAndPrefix
#[test]
fn list_and_prefix() {
    let fixture = Fixture::new();

    for name in ["api/stripe/live", "api/stripe/test", "db/postgres"] {
        fixture.set(name, VALUE_ONE, &[]);
    }

    fixture.ok("", &["delete", "db/postgres"]);

    let all = fixture.ok("", &["list", "--json"]).json_array();
    assert_eq!(
        names(&all),
        ["api/stripe/live", "api/stripe/test"],
        "deleted secrets stay out of list"
    );

    let stripe = fixture
        .ok("", &["list", "api/stripe/", "--json"])
        .json_array();

    assert_eq!(names(&stripe), ["api/stripe/live", "api/stripe/test"]);
    assert_eq!(stripe[0]["latestVersion"], 1);
    assert_eq!(stripe[0]["expired"], false);

    let keys: Vec<&str> = stripe[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["name", "createdAt", "updatedAt", "latestVersion", "expired"]
    );
}

// Go: TestStale
#[test]
fn stale() {
    let fixture = Fixture::new();

    fixture.set("expired/secret", VALUE_ONE, &["--expires", "2020-01-02"]);
    fixture.set("fresh/secret", VALUE_ONE, &["--expires", "2099-01-02"]);
    fixture.set("eternal/secret", VALUE_ONE, &[]);

    let stale = fixture.ok("", &["stale", "--json"]).json_array();

    assert_eq!(names(&stale), ["expired/secret"]);
    assert_eq!(stale[0]["expired"], true);
    assert_eq!(stale[0]["expiresAt"], "2020-01-02T00:00:00Z");

    // list computes the same flag for every secret.
    let listed = fixture.ok("", &["list", "--json"]).json_array();
    let expired: Vec<bool> = listed
        .iter()
        .map(|item| item["expired"].as_bool().expect("a flag"))
        .collect();

    assert_eq!(
        names(&listed),
        ["eternal/secret", "expired/secret", "fresh/secret"]
    );
    assert_eq!(expired, [false, true, false]);

    // Expired secrets still resolve. Expiry is staleness, never deletion.
    assert_eq!(fixture.reveal_value("expired/secret"), VALUE_ONE);
    assert_eq!(
        fixture.ok("", &["get", "expired/secret"]).json()["expired"],
        true
    );

    // A deleted secret is never stale.
    fixture.ok("", &["delete", "expired/secret"]);
    assert_eq!(fixture.ok("", &["stale", "--json"]).stdout, "[]\n");
}

// Go: TestDisableErrors
#[test]
fn disable_errors() {
    let fixture = Fixture::new();

    fixture
        .fail("", &["disable", "missing", "1"])
        .assert_stderr(msg::SECRET_NOT_FOUND);

    fixture.set("dis/able", VALUE_ONE, &[]);

    fixture
        .fail("", &["disable", "dis/able", "9"])
        .assert_stderr("version 9 of dis/able: secret version not found");

    fixture
        .fail("", &["disable", "dis/able", "one"])
        .assert_stderr("version must be a number, got \"one\"");

    fixture.ok("", &["purge", "dis/able", "--yes"]);

    fixture
        .fail("", &["disable", "dis/able", "1"])
        .assert_stderr(&format!(
            "version 1 of dis/able: {}",
            msg::VERSION_DESTROYED
        ));
}

// Go: TestSoftDeleteTwiceFails
#[test]
fn soft_delete_twice_fails() {
    let fixture = Fixture::new();

    fixture.set("del/ete", VALUE_ONE, &[]);

    fixture.ok("", &["delete", "del/ete"]);
    fixture
        .fail("", &["delete", "del/ete"])
        .assert_stderr(msg::SECRET_DELETED);
    fixture
        .fail("", &["delete", "never/existed"])
        .assert_stderr(msg::SECRET_NOT_FOUND);
}

// Go: TestSoftDeleteConcurrentKeepsOneTombstone
//
// The guarded update makes exactly one racing delete win, so a second
// delete cannot overwrite the first tombstone's timestamp.
#[test]
fn soft_delete_concurrent_keeps_one_tombstone() {
    const WORKERS: usize = 8;

    let fixture = Fixture::new();

    fixture.set("race/delete", VALUE_ONE, &[]);

    let results: Vec<_> = thread::scope(|scope| {
        let workers: Vec<_> = (0..WORKERS)
            .map(|_| scope.spawn(|| fixture.run("", &["delete", "race/delete"])))
            .collect();

        workers
            .into_iter()
            .map(|worker| worker.join().expect("delete worker"))
            .collect()
    });

    let succeeded = results
        .iter()
        .filter(|result| result.status.success())
        .count();
    let already_deleted = results
        .iter()
        .filter(|result| result.code() == Some(1) && result.stderr.contains(msg::SECRET_DELETED))
        .count();

    assert_eq!(succeeded, 1, "exactly one concurrent delete must win");
    assert_eq!(
        already_deleted,
        WORKERS - 1,
        "the rest must report already deleted"
    );
}

// Go: TestPurgeDestroysEnvelopes
#[test]
fn purge_destroys_envelopes() {
    let fixture = Fixture::new();

    fixture.set("purge/me", VALUE_ONE, &[]);
    fixture.set("purge/me", VALUE_TWO, &[]);

    let purged = fixture.ok("", &["purge", "purge/me", "--yes"]);

    assert_eq!(
        purged.stdout,
        "{\n  \"name\": \"purge/me\",\n  \"destroyedVersions\": 2,\n  \"result\": \"purged\"\n}\n"
    );

    let shown = fixture.ok("", &["show", "purge/me"]).json();

    assert!(shown["deletedAt"].is_string(), "purge implies delete");

    for version in shown["versions"].as_array().expect("show lists versions") {
        assert_eq!(version["state"], "destroyed");
    }

    // Rows and history remain, and every envelope is gone.
    let (rows, with_envelope): (i64, i64) = fixture
        .db()
        .query_row(
            "SELECT COUNT(*), COUNT(envelope) FROM secret_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("count versions");

    assert_eq!((rows, with_envelope), (2, 0));

    fixture
        .fail("", &["get", "purge/me"])
        .assert_stderr(msg::SECRET_DELETED);

    // Purging again destroys nothing more, and purging a missing secret
    // is an error.
    let again = fixture.ok("", &["purge", "purge/me", "--yes"]).json();
    assert_eq!(again["destroyedVersions"], 0);

    fixture
        .fail("", &["purge", "never/existed", "--yes"])
        .assert_stderr(msg::SECRET_NOT_FOUND);
}

// A purge keeps the tombstone a delete already wrote.
#[test]
fn purge_keeps_an_existing_tombstone() {
    let fixture = Fixture::new();

    fixture.set("purge/later", VALUE_ONE, &[]);
    fixture.ok("", &["delete", "purge/later"]);

    fixture.sql(
        "UPDATE secret SET deleted_at = '2001-02-03T04:05:06Z' WHERE name = 'purge/later'",
        [],
    );

    fixture.ok("", &["purge", "purge/later", "--yes"]);

    let shown = fixture.ok("", &["show", "purge/later"]).json();
    assert_eq!(shown["deletedAt"], "2001-02-03T04:05:06Z");
}

// Go: TestEntries
//
// The batch selection: every non-deleted secret with an enabled
// version, at its newest enabled version, ordered by name.
#[test]
fn entries() {
    let fixture = Fixture::new();

    fixture.set(
        "api/stripe/live",
        VALUE_ONE,
        &["--env-name", "FAKE_STRIPE_KEY"],
    );
    fixture.set("api/stripe/live", VALUE_TWO, &[]);
    fixture.set("db/postgres", VALUE_ONE, &[]);

    let cases: [(&str, &[&str], &[&str]); 4] = [
        ("a bare slash names no segment", &["--prefix", "/"], &[]),
        ("env filter drops unnamed", &["--env"], &["api/stripe/live"]),
        ("prefix filter", &["--prefix", "db/"], &["db/postgres"]),
        (
            "filters compose to empty",
            &["--prefix", "db/", "--env"],
            &[],
        ),
    ];

    for (name, filter, want) in cases {
        let mut args = vec!["reveal"];
        args.extend_from_slice(filter);

        let revealed = fixture.ok("", &args).json_array();
        assert_eq!(names(&revealed), want, "{name}");
    }

    let named = fixture.ok("", &["reveal", "--env"]).json_array();

    assert_eq!(named[0]["envName"], "FAKE_STRIPE_KEY");
    assert_eq!(
        named[0]["version"], 2,
        "entries resolve the newest enabled version"
    );
    assert_eq!(named[0]["value"], VALUE_TWO);

    let unnamed = fixture.ok("", &["reveal", "--prefix", "db/"]).json_array();
    assert!(
        unnamed[0].get("envName").is_none(),
        "a secret without an env name carries no envName"
    );

    let keys: Vec<&str> = named[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["name", "envName", "version", "expired", "value"]);
}

// A secret whose every version is disabled, and a deleted secret, never
// enter a batch.
#[test]
fn entries_skip_secrets_with_nothing_to_resolve() {
    let fixture = Fixture::new();

    fixture.set("batch/live", VALUE_ONE, &["--env-name", "FAKE_LIVE"]);
    fixture.set(
        "batch/disabled",
        VALUE_ONE,
        &["--env-name", "FAKE_DISABLED"],
    );
    fixture.set("batch/deleted", VALUE_ONE, &["--env-name", "FAKE_DELETED"]);

    fixture.ok("", &["disable", "batch/disabled", "1"]);
    fixture.ok("", &["delete", "batch/deleted"]);

    let revealed = fixture
        .ok("", &["reveal", "--prefix", "batch"])
        .json_array();
    assert_eq!(names(&revealed), ["batch/live"]);

    let ran = fixture.ok(
        "",
        &[
            "exec",
            "--",
            "sh",
            "-c",
            r#"printf '%s|%s|%s' "$FAKE_LIVE" "$FAKE_DISABLED" "$FAKE_DELETED""#,
        ],
    );
    assert_eq!(ran.stdout, format!("{VALUE_ONE}||"));
}

// Go: TestEntriesPrefixIsExactNotLike
//
// The prefix filter does not treat name characters as LIKE wildcards or
// fold ASCII case, so reveal --prefix cannot over-match and disclose
// unselected secrets.
#[test]
fn entries_prefix_is_exact_not_like() {
    let fixture = Fixture::new();

    for name in [
        "api/my_service",
        "api/myXservice",
        "prod/db",
        "api/my_service/child",
    ] {
        fixture.set(name, VALUE_ONE, &[]);
    }

    // `_` must be literal, not a single-character wildcard.
    let got = fixture
        .ok("", &["reveal", "--prefix", "api/my_service"])
        .json_array();
    assert_eq!(
        names(&got),
        ["api/my_service", "api/my_service/child"],
        "prefix must match literally, never treat _ as a wildcard"
    );

    // Case sensitivity: Prod/ must not match prod/.
    let upper = fixture.ok("", &["reveal", "--prefix", "Prod/"]);
    assert_eq!(
        upper.stdout.trim(),
        "[]",
        "prefix match must be case-sensitive"
    );

    // A wildcard character in the prefix matches nothing literal.
    let wildcard = fixture.ok("", &["reveal", "--prefix", "%"]);
    assert_eq!(
        wildcard.stdout.trim(),
        "[]",
        "a literal % prefix must not match every row"
    );

    // list applies the same rule.
    let listed = fixture
        .ok("", &["list", "api/my_service", "--json"])
        .json_array();
    assert_eq!(names(&listed), ["api/my_service", "api/my_service/child"]);

    assert_eq!(fixture.ok("", &["list", "%", "--json"]).stdout, "[]\n");
    assert_eq!(fixture.ok("", &["list", "Prod", "--json"]).stdout, "[]\n");
}

// Go: TestEntriesPrefixStopsAtSegmentBoundary
//
// A prefix selects the name itself and whole segments under it, never
// a sibling hierarchy that merely shares leading characters.
#[test]
fn entries_prefix_stops_at_segment_boundary() {
    let fixture = Fixture::new();

    for name in [
        "projects/myapp",
        "projects/myapp/token",
        "projects/myapp-legacy/db",
        "projects/myapplication/key",
    ] {
        fixture.set(name, VALUE_ONE, &[]);
    }

    let want = ["projects/myapp", "projects/myapp/token"];

    let got = fixture
        .ok("", &["reveal", "--prefix", "projects/myapp"])
        .json_array();
    assert_eq!(
        names(&got),
        want,
        "a prefix must select the name itself and whole segments under it, never lexical siblings"
    );

    // A trailing slash selects the same set.
    let slashed = fixture
        .ok("", &["reveal", "--prefix", "projects/myapp/"])
        .json_array();
    assert_eq!(names(&slashed), want);

    // list applies the same rule.
    let listed = fixture
        .ok("", &["list", "projects/myapp", "--json"])
        .json_array();
    assert_eq!(names(&listed), want);
}

// Go: TestAppendVersionSealsToTheRecipientInsideTheTransaction
//
// set seals to the recipient the vault currently holds, and needs
// nothing but that public key.
#[test]
fn set_seals_to_the_stored_recipient_without_the_identity() {
    let fixture = Fixture::new();
    let key = fixture.key();

    // Neither the identity nor a passphrase is available to set.
    std::fs::remove_file(&fixture.identity).expect("remove identity");
    std::fs::remove_file(&fixture.passphrase_file).expect("remove passphrase file");

    fixture.set("race/target", VALUE_ONE, &[]);

    let frame = fixture.open_frame(&key, &fixture.newest_enabled("race/target"));
    assert_eq!(frame.value, VALUE_ONE.as_bytes());

    // The metadata verbs need no identity either.
    for verb in [
        &["show", "race/target"][..],
        &["list"],
        &["stale"],
        &["disable", "race/target", "1"],
        &["delete", "race/target"],
        &["purge", "race/target", "--yes"],
    ] {
        fixture.ok("", verb);
    }
}

// Go: TestAppendVersionFailsWhenTheRecipientRowIsMissing
//
// A missing recipient must fail the write rather than seal to nothing.
#[test]
fn set_fails_when_the_recipient_row_is_missing() {
    let fixture = Fixture::new();

    fixture.sql("DELETE FROM vault_meta WHERE key = 'recipient'", []);

    fixture.fail(format!("{VALUE_ONE}\n"), &["set", "race/norecipient"]);

    let rows: i64 = fixture
        .db()
        .query_row("SELECT COUNT(*) FROM secret", [], |row| row.get(0))
        .expect("count secrets");

    assert_eq!(rows, 0, "a failed write must roll back its secret row");
}

// A recipient that does not parse fails the write the same way.
#[test]
fn set_fails_when_the_recipient_does_not_parse() {
    let fixture = Fixture::new();

    fixture.swap_recipient("age1fake-recipient-for-tests-not-real");

    fixture
        .fail(format!("{VALUE_ONE}\n"), &["set", "race/badrecipient"])
        .assert_stderr("stored recipient does not parse");

    assert_eq!(fixture.ok("", &["list", "--json"]).stdout, "[]\n");
}

// show reports the full history with every state, and never the value
// or anything derived from it.
#[test]
fn show_reports_history_and_never_the_value() {
    let fixture = Fixture::new();

    fixture.set(
        "show/me",
        VALUE_ONE,
        &["--env-name", "FAKE_SHOWN", "--expires", "2020-01-02"],
    );
    fixture.set("show/me", VALUE_TWO, &[]);
    fixture.ok("", &["disable", "show/me", "1"]);

    let shown = fixture.ok("", &["show", "show/me"]);
    let object = shown.json();

    let keys: Vec<&str> = object
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "name",
            "envName",
            "createdAt",
            "updatedAt",
            "expiresAt",
            "expired",
            "versions"
        ]
    );

    assert_eq!(object["expired"], true);

    let versions = object["versions"].as_array().expect("show lists versions");

    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["version"], 1);
    assert_eq!(versions[0]["state"], "disabled");
    assert_eq!(versions[1]["version"], 2);
    assert_eq!(versions[1]["state"], "enabled");
    assert_stored_time(&versions[0]["createdAt"]);

    let version_keys: Vec<&str> = versions[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(version_keys, ["version", "state", "createdAt"]);

    assert!(!shown.stdout.contains(VALUE_ONE));
    assert!(!shown.stdout.contains(VALUE_TWO));
    assert!(
        shown.stderr.is_empty(),
        "show warns about nothing, expired or not"
    );
}
