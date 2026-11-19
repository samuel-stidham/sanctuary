# Test parity with the Go original

The conformance suite in `tests/conformance/` ports the Go test suite
of safetybox v4.0.2, commit `e37428e`. `make parity` checks this
ledger against the Go source, so it cannot drift.

## How a Go test becomes a Rust test

The Go tests call Go functions. No Rust test can call those, and no Go
binary can run a Rust unit test. The two implementations share exactly
one surface: the command line and the files on disk. So every ported
test drives a binary through argv, stdin, stdout, stderr, the exit
code, and the vault and identity files it leaves behind.

`make test-oracle` runs the suite against the Go binary. That proves
each expectation is the reference behavior and not a guess.
`cargo test` runs the same suite against the Rust binary. When both
pass, the port matches the original at that surface.

Three translations recur:

- A Go test that asserts on a sentinel with `errors.Is` asserts here on
  the sentinel's message in stderr, with exit code 1.
- A Go test that calls an internal helper to set up state does the same
  work from outside. The suite holds the same `flock` on the same
  `.lock` sibling. It builds and parses envelopes with its own age
  implementation and writes rows with its own SQLite. That also pins
  the on-disk format: a vault or identity written by one implementation
  must open in the other.
- A Go test that calls a pure function is ported through the verb that
  exposes the function, as a table.

Each Rust test names the Go tests it ports in a `// Go:` comment.

## Ported in part

These are ported, with a difference worth knowing.

| Go test | Difference |
| --- | --- |
| `TestOpenCorruptOneByteFails` | Go flips every byte in process. Each read here pays the passphrase KDF, so the port samples eight positions across the header, the MAC, the payload, and the final byte. |
| `TestDisplayName` | Only the product name `Safetybox` is reachable, through the help header. The other cases feed names the binary never has. |
| `TestIsShellIdentifier` | The empty name is not a refusal at the command line. An empty `--env-name` clears the env name, which `set_clears_env_name` covers. |
| `TestSQLiteDSNEscapesURISpecialCharacters`, `TestSQLiteDSNKeepsConnectionSettings` | The DSN string is a Go driver detail. The port pins what it buys: a path holding `#`, `?`, or `%` names the file itself, the journal is WAL, and a purge leaves no ciphertext in the vault files. |
| `TestSubcommandHelpMatchesStockCobra` | Holds for the Go binary alone, see Intended differences. Go compares styled help to stock cobra in process. The port compares against snapshots of that same output in `tests/conformance/golden/`, captured from the Go binary. |
| `TestBannerGradientOrder`, `TestBannerGradientRampDirection` | Pinned as rendered: the 16-color codes under forced color, and the four 24-bit stops on a terminal. |
| `TestWALSiblingInheritsPermissions` | The binary removes the write-ahead log when it exits. The port holds a second connection open to inspect it, so the test's own SQLite may be the one that creates the file. |
| `TestConcurrentSetAndRekeyLeaveNoVersionOnARetiredRecipient`, `TestSoftDeleteConcurrentKeepsOneTombstone` | The races run between processes, not goroutines. |

## Intended differences

The port is its own command. Where it differs from the Go original, the
difference is deliberate, and the suite pins it for each binary.

| What | Go original | Rust port |
| --- | --- | --- |
| Command name, in help and in hints | `safetybox` | `sanctuary` |
| Version line | `safetybox version v4.0.2` | `sanctuary 0.1.0 (Rust, compatible with safetybox v4.0.2)` |
| Help layout | cobra | laid out by the port, in clap's vocabulary |
| Usage error wording | cobra | clap, cut to one line |
| Completion scripts | cobra, with a hidden `__complete` verb | `clap_complete` |
| A refused `--expires`, after the shared `use RFC3339 or YYYY-MM-DD` | the Go time parser's own complaint follows | nothing follows |
| A corrupt stored timestamp, after the shared `stored timestamp is not valid, the vault may have been edited` | the Go time parser's own complaint follows, then the advice | the advice follows directly |
| A file that is not an age file, after the shared `identity decrypt failed:` or `envelope decrypt failed:` | the Go `age` library's complaint | the `age` crate's complaint. A wrong passphrase reads the same in both. |
| Locking the decrypted identity in memory fails | the process panics | the read goes on with the bytes unlocked, and they are still wiped |
| The order of variables in the environment `exec` gives the child | inherited order, with each injected variable last | sorted by name. The set of variables and their values is the same. |
| A stray argument, such as a value typed after the name in `set` | counted, never repeated, for a verb that takes arguments. Repeated as `unknown command "..."` for a verb that takes none. | never repeated, for any verb: `too many arguments: set accepts 1 argument` |
| A `--vault`, `--identity`, `SAFETYBOX_VAULT`, or `SAFETYBOX_IDENTITY` path that is not clean, such as one holding `x/..` | used as written. `rekey` then commits the vault and fails the identity swap. | cleaned once, when the path is resolved. Both versions already clean the default paths. |
| A stored recipient that does not parse, after the shared `malformed recipient "...":` | the Go `age` library's reason | the `age` crate's reason. An upper-case recipient reads `invalid type "AGE"` in both. |
| A secret name in the vault that is not UTF-8, quoted in an error | the bad byte as `\xff` | the replacement character as `\ufffd`. Result output shows the replacement character in both. |
| `exec` with one env-named secret over the kernel's limit for a single variable, 32 pages on Linux | every `exec` fails with `argument list too long` | the secret is skipped with a warning that names it, and the rest inject. Reported to safetybox. |
| A secret withheld from `exec` or from `reveal --format` for its value, such as one holding a NUL byte, when the caller already holds a variable of that name | the stale value stays in place | `exec` clears the variable for the child, and `reveal` writes an erase line. A reserved name keeps its inherited value in both. Reported to safetybox. |
| A secret name in the vault that the name grammar does not allow, named in a `rekey` or `migrate` error | printed as stored, so a newline or an escape sequence reaches the terminal | printed quoted and escaped. A valid name prints the same in both. Reported to safetybox. |
| A passphrase that is not UTF-8 | accepted | refused with `passphrase is not valid UTF-8`, because the `age` crate takes a passphrase as a string |

Everything else is held to be the same: the vault and identity paths
and formats, the environment variables, result output, log records,
prompts, and exit codes. The directory is still named `safetybox`, so
both commands open one vault.

The tests of presentation ask which binary they are driving:

- Help pages must say the same things for both: every verb with its
  summary, every flag with its help, the banner, the description. The
  byte-for-byte snapshots in `tests/conformance/golden/` hold for the
  Go binary alone.
- A usage error must be one `ERRO` record with exit 1 for both. The
  wording is pinned for the Go binary alone.
- Two parser behaviors are contract, not style, and stay pinned for
  both: exec stops reading flags at the child command, and `--log-json`
  holds when the command line fails to parse.

## Ported as unit tests

These check what cannot be seen from outside the process, so they are
unit tests inside the Rust module, named in a `// Go:` comment there.

| Go test | Rust module | Note |
| --- | --- | --- |
| `TestDestroyZeroesPlaintext`, `TestDestroyIsIdempotent`, `TestNewCopiesInput`, `TestEmptyValue`, `TestZeroBytes` | `secret` | |
| `TestSecretValueUnexportedFieldNeverLeaks` | `secret` | Go guards against fmt reflecting into an unexported field. Here a derived `Debug` calls the value's own. |
| `TestDestroyWipesCopies`, `TestExposeAliasesInternalStorage` | `secret` | Go copies of the struct share one backing array. Here the value is not `Clone`, so there is never a second holder. The test pins that. |
| `TestReadAllWipingZeroesOutgrownBuffer`, `TestReadAllWipingTreatsWrappedEOFAsFailure` | `secret` | |
| `TestSensitiveKeyBackstopRedactsRawString`, `TestSecretValueRedactedThroughHandler`, `TestCharmPathResolvesLogValuer`, `TestSetupInstallsDefault` | `logging` | |
| `TestCharmPathInlinesEmptyKeyGroup` | `logging` | The logger has flat attributes only. The one empty-key shape left is an attribute with no key, which is dropped alone. |
| `TestFailedRekeyKeepsStagedKeyOnAmbiguousCommit`, `TestPromoteStagedIdentityToleratesCompletedHeal` | `cmd::rekey` | Each needs a failure injected inside the process: a commit that errors after it became durable, and a reader's heal landing between the two renames of the swap. |
| `TestConcurrentMigrateLoserGetsAlreadyCurrent` | `vault::migrate` | The migrate lock refuses a second migrate before the check inside the transaction can run, so the test calls the vault directly from two threads. |
| `TestSealRejectsAddressWithSeparator`, `TestSealQuotesAnAddressCarryingANewline`, `TestSealReportsFirstInvalidFieldDeterministically`, `TestOpenLegacyQuotesAnAddressCarryingANewline` | `envelope` | |

## Not ported

### No counterpart in the port

The Go logger takes attributes scoped to a logger and nested in groups,
and these tests prove redaction reaches into both. The Rust logger has
neither: every attribute is a flat `key = value` on one call, and the
backstop checks every one. There is nothing for these to test.

| Go test | Why |
| --- | --- |
| `TestRedactsLoggerScopedAttrs` | No logger-scoped attributes. |
| `TestRedactsGroupedAttrs` | No attribute groups. |
| `TestRedactsAfterWithGroup` | No attribute groups. |

## Added

The suite also holds tests with no Go counterpart. Each pins behavior
the Go suite leaves to the code and the docs, and each passes against
the Go binary: exact JSON key order and escaping, exact log lines in
every format, usage errors, the prompts on a real terminal, the bytes
of the envelope frame and the schema, and `--expires` and stdin
parsing.

## Changes to the harness

The suite is never edited to make the port pass. One change fixed a
race in the harness itself, and the Go binary passes with and without
it. Tests were added that no Go test covers, and both binaries pass
each of them.

| What | Why |
| --- | --- |
| `support::pty::spawn` reads the terminal state before it starts the child, and the prompt tests compare against that. | The tests read it after the spawn. The Rust binary can reach its prompt and turn echo off before the test looks, so "a fresh pty starts with echo enabled" failed about one run in three. |
| `exec::exec_exits_one_on_sigint_without_waiting_for_the_child` was added. | The Go original exits 1 on SIGINT through its locked-memory library, and no Go test pinned that. The port must match it. |
| `plaintext::a_stray_argument_is_never_echoed` was added. | A review found that the port repeated a stray argument in its usage error. The test covers the verbs where the Go original does not repeat it either. |
| `rekey::rekey_swaps_the_identity_under_an_unclean_default_path` was added. | A review found that the port did not clean a default path, so a rekey could commit the vault and fail the swap. |
| `vault::a_relative_vault_path_shaped_like_a_uri_names_the_file_itself` was added. | A review found that the port opened a relative path starting with `file:` as a URI, and the vault landed in another file. |
| `reveal::a_reader_that_stops_early_ends_the_command_by_sigpipe` was added. | A review found that the port reported a broken pipe as an error. The Go original ends by the signal. |
| `tamper::a_name_that_is_not_utf8_does_not_break_the_metadata_verbs` was added. | A review found that one odd row stopped `list` for every secret in the port. |
| `exec::exec_skips_a_secret_too_large_for_a_variable`, `exec::a_withheld_secret_never_leaves_a_stale_variable`, and `tamper::a_tampered_name_cannot_forge_a_log_line` were added. | Each pins a fix the Go original does not have yet, so each returns early for the Go binary. Remove that guard when safetybox fixes the matching issue. |
| `cli::an_empty_path_flag_counts_as_not_passed`, `cli::help_and_completion_succeed_on_what_they_do_not_know`, and `logging::json_time_follows_tz_and_survives_a_hostile_one` were added. | A second review found the port differed from the Go original in each. Both binaries pass them. |
| `cli::terminal_help_is_plain_under_ci` was added, and the harness now removes `CI` from every run. | The first CI run found the Go version drops terminal color while `CI` is set, and the port did not. Both binaries pass it. |
| `tamper::set_refuses_a_stored_recipient_that_is_not_canonical` was added. | A review found that the port accepted an upper-case stored recipient, which the Go original refuses. |
