# Porting checklist

One command at a time. A step is done only when its gate passes.

## The gate, for every step

The Go test suite cannot run against a Rust binary, and Rust unit
tests cannot run against Go. The conformance suite is the one suite
both binaries run, so parity is proven there.

1. `make test-oracle` passes every test, 236 since the first CI run. The Go reference still agrees
   with every expectation, so no test was bent to fit the port.
2. `cargo test --test conformance <filter>` passes for the step's
   filters, against the Rust binary.
3. The count of conformance tests passing against the Rust binary never
   drops from the step before.
4. `make lint` is clean.
5. A conformance test is never edited to make the port pass. If a test
   looks wrong, prove it against the Go binary first.

Most tests use several verbs. A test goes green when the last verb it
needs lands, so each step lists the tests it is expected to complete,
not every test that mentions the verb.

## Decided before step 0

- [x] The port is its own command, `sanctuary`, so it can share a PATH with
      the Go `safetybox`. It opens the same vault. Its version line
      reads `sanctuary <version> (Rust, compatible with safetybox <tag>)`.
- [x] Help, usage errors, and completion scripts are Rust-native and
      need not match cobra. `tests/PARITY.md` lists every intended
      difference.
- [x] Crates: `clap` and `clap_complete` for the command line, `age`
      for encryption, `zeroize` for wiping, `thiserror` for
      errors. The local UTC offset of a log record comes from the C
      library, so no time zone crate is needed. Help pages and log records are rendered
      by the crate itself, so color follows the destination.
- [x] SQLite binding: `rusqlite` with bundled SQLite. The vault path
      is opened as a plain file name, never as a URI, so `#`, `?`, and
      `%` in a path need no escaping. A relative path is anchored at
      `./` first, because the bundled SQLite reads any name that
      starts with `file:` as a URI.
- [x] Locked memory for the unlocked identity: `zeroize` to wipe, and
      `mlock` through `nix` on the decrypted identity bytes. That is
      the same single buffer the Go original locks. It arrives with
      the identity load in step 9.
- [x] The scrypt cost is pinned to the Go original's. An identity is
      written at cost 18 and read with a cap of 22. Left alone, the
      `age` crate derives both from the speed of the machine.

## Step 0: foundations, no verb yet

- [x] Crate layout: `secret`, `envelope`, `logging`, `color`, `quote`,
      `json`, `cmd`. `identity` and `vault` arrive with step 1.
- [x] `secret`: the redacting value type and the wiping reader, with
      unit tests for the 10 memory tests.
- [x] `logging`: text and JSON formats, levels, color by destination,
      the sensitive-key backstop, with unit tests. 5 of the 8 Go tests
      are ported. 3 test attribute groups, which the port does not have.
- [x] `envelope`: seal, open, open legacy, the frame, with unit tests
      for the 4 seal tests.
- [x] Root command: global flags, path resolution, `--version`, usage
      errors, the early `--log-json` scan, exit codes.
- [x] Help: banner, styled pages, `help`, `completion`.
- [x] Gate: `cli::`, 12 of 14. `vault_path_precedence` needs `list`
      (step 4) and `identity_path_precedence` needs `passwd` (step 12).
      Path resolution itself is unit tested.
- [x] Oracle rebuilt at v4.0.1, commit `836962e`. No Go source changed
      from v4.0.0, only dependencies, docs, and CI.

## Step 1: init

Every fixture is built from one real `init`, so nothing else can pass
before this does.

- [x] `identity`: write, directory and file modes, fsync.
- [x] `vault`: create, schema, WAL, open, loose-permission scan.
- [x] Passphrase from file and from the no-echo prompt, with the signal
      handler.
- [x] Self-test, cleanup on failure, the two log records.
- [x] A repeated flag is accepted and the last one wins, as in the Go
      original.
- [x] Gate: `init::` 7 of 7, `vault::schema`, `vault::create` 3 of 5,
      `identity::write_` 2 of 3, `identity::empty_passphrase`,
      `logging::info_records`, `logging::operational_keys`,
      `prompt::init_`, `prompt::prompt_refuses_an_empty_line`.
      33 of 221 pass against `sanctuary`.
- [x] Checked by hand across the two binaries: `sanctuary init` made a
      vault and an identity, then the Go binary ran `set`, `reveal`,
      `get`, and `list` on them with no error.

Still red from the gate first written here, each waiting on one verb:
`vault::create_and_open`, `vault::open_` (6), and
`vault::loose_permissions_clean` need `list` (step 4).
`vault::create_and_open_survive_uri_special_characters_in_path` and
`identity::write_load_round_trip` need `set` and `reveal`.

## Steps 2 to 8: verbs that need no identity

- [x] **2. set**: name grammar, env name rules, `--expires`, stdin and
      prompt, seal inside the transaction, `--revoke-previous`, revive.
      Gate: `tamper::set_rejects`, `lifecycle::set_rejects`,
      `prompt::set_prompt_refuses`, `envname::set_` 1 of 2.
      42 of 221 pass against `sanctuary`.
      Checked by hand across the two binaries: both wrote versions of
      one secret in turn, the Go binary read every version back, and
      the same input gave byte-identical output from each.
      Still red, each waiting on one verb: `envname::set_refuses_reserved`
      and `plaintext::set_takes_no_value_argument` need `list`.
      `reveal::set_accepts` and `plaintext::set_reports_a_failed_read`
      need `show`.
- [x] **3. show**: metadata and history.
      Gate: `store::append_version_revoke`, `store::invalid_name`,
      `store::append_version_stores`, `tamper::set_clears_expiry`,
      `tamper::valid_expiry`. It also completes `reveal::set_accepts`
      and `plaintext::set_reports_a_failed_read` from step 2.
      47 of 221 pass against `sanctuary`.
      Checked by hand across the two binaries: stdout, stderr, and the
      exit code of `show` were byte-identical for a secret with three
      versions, a plain one, a deleted one, a missing one, and a bad
      name, in both layouts.
      Still red: `store::append_version_rejects_bad_names` needs `list`.
- [x] **4. list**: prefix rule, computed expiry.
      Gate: `lifecycle::list_`, `vault::create_and_open`,
      `vault::open_` 6 of 6, `vault::loose_permissions_clean`,
      `store::append_version_rejects`, and the step 2 leftovers that
      needed `list`.
- [x] **5. stale**: ported with `list`, since the two share one query
      and one output shape.
      64 of 221 pass against `sanctuary` after both.
      Checked by hand across the two binaries: 21 `list` and `stale`
      invocations on one vault that both had written to. stdout,
      stderr, and the exit code were byte-identical, apart from the
      differences `tests/PARITY.md` already lists.
- [x] **6. disable**. Gate: `store::disable_errors`.
- [x] **7. delete**. Gate: `tamper::json_output_is_pretty`,
      `store::soft_delete` 2 of 2, `store::list_and_prefix`.
- [x] **8. purge**: destroy, tombstone, WAL scrub.
      Gate: `store::purge_keeps`, `store::disable_errors`,
      `store::set_seals_to_the_stored_recipient`, `vault::purge_scrubs`.
      Every gate test of steps 6 to 8 passes.
      73 of 221 pass against `sanctuary` after all three.
      Checked by hand across the two binaries: the same 23 `disable`,
      `delete`, `purge`, and `list` invocations ran through each binary
      on twin vaults. stdout, stderr, and the exit code matched, and
      the two vaults ended row for row the same. The Go binary then
      read the vault `sanctuary` had modified.

## Steps 9 to 11: verbs that decrypt

- [x] **9. get**: identity load and its refusals, recipient check,
      envelope open, metadata binding, expiry warning, interrupted-rekey
      heal.
      Gate: `identity::` 10 of 13, `lifecycle::get_`,
      `lifecycle::verbose`, `logging::text_format_by`,
      `logging::json_format`, `logging::level_filtering`,
      `logging::records_are_styled`, `plaintext::get_`,
      `tamper::read_refuses_tampered_expiry`,
      `tamper::corrupt_stored_time_names`,
      `store::append_version_creates`, `store::newest_enabled_skips`,
      `envelope::swapped`, `envelope::open_wrong_identity`,
      `envelope::seal_open_binds`.
      Three tests named here before the step still wait on later
      verbs. `logging::forced_color` runs `migrate`,
      `store::newest_enabled_errors` runs `reveal`, and
      `identity::lock_sibling` runs `rekey`. Two more `identity::`
      tests run `reveal`.
      97 of 221 pass against `sanctuary`.
      The decrypted identity bytes sit in memory locked with `mlock`
      while the key is parsed, then they are wiped. Core dumps are
      turned off at startup, as `memguard` does for the Go original.
      Checked by hand across the two binaries: 19 `get` invocations
      ran against a vault written by each binary, read by each binary.
      stdout, stderr, and the exit code matched in all four pairings.
      Both binaries then read one vault after each of 10 edits to its
      rows and gave the same refusal.
      Not checked by hand: `get` at the passphrase prompt. The
      `prompt::` tests of step 10 cover that path.
- [x] **10. reveal**: names and filters, batch decrypt, JSON and base64,
      sh and fish quoting, skips and erase lines.
      Gate: `reveal::` 22 of 22, `envelope::` 14 of 14, `plaintext::`
      6 of 7, `store::` 24 of 25, `lifecycle::rotation`,
      `lifecycle::expiry`, `lifecycle::delete_purge`, `prompt::` 9 of
      12, `tamper::passphrase_file`.
      Every test still red in those groups runs `exec`, `passwd`,
      `rekey`, or `migrate`.
      154 of 221 pass against `sanctuary`.
      Checked by hand across the two binaries: 40 `reveal` invocations
      ran against a vault written by each binary, read by each binary.
      stdout was compared byte for byte, with stderr and the exit
      code. All four pairings matched, apart from the differences
      `tests/PARITY.md` already lists. The invocations covered values
      that are not UTF-8, a NUL byte, shell metacharacters, a repeated
      env name, and rows edited behind the vault's back.
- [x] **11. exec**: environment build, skips and clears, collisions,
      non-interspersed flags, exit code and signal mapping.
      Gate: `exec::` 12 of 12, `envname::` 4 of 4, `lifecycle::exec_`
      3 of 3, `tamper::` 17 of 17, `plaintext::` 7 of 7, `store::` 25
      of 25, `prompt::prompt_signal_handler_is_torn_down`.
      179 of 222 pass against `sanctuary`.
      SIGINT matches the Go original, as decided. The wrapper exits 1
      at once in any verb and does not wait for the child. The Go
      binary was probed first, with SIGINT at its default and ignored
      at start, and gave the same result both ways. The new test
      `exec::exec_exits_one_on_sigint_without_waiting_for_the_child`
      pins it for both binaries, which brings the suite to 222.
      The command is found the way the Go original finds it: with the
      PATH of `sanctuary` itself, never the child's, and a match under
      a relative PATH entry is refused.
      Checked by hand across the two binaries: 36 `exec` invocations
      ran against a vault written by each binary, read by each binary.
      The child's stdout was compared byte for byte, with stderr and
      the exit code. All four pairings matched, apart from the
      differences `tests/PARITY.md` lists.

## Steps 12 to 14: verbs that rewrite keys or format

- [x] **12. passwd**: identity lock, heal, atomic replace.
      Gate: `lifecycle::passwd`, `rekey::passwd_` 4 of 4,
      `prompt::passwd_`, `cli::identity_path_precedence`,
      `vault::loose_permissions_warn`.
      `locks::rekey_and_passwd_refuse` also runs `rekey`, so it waits
      on step 13. The passwd half was checked by hand.
      188 of 222 pass against `sanctuary`.
      The advisory lock arrived with this step, for `rekey` and
      `migrate` to share. The lock path resolves symbolic links the
      way the Go original does, so two spellings of one identity take
      one lock.
      Error reasons now use the C library's text. The earlier source
      worded two of them differently from the Go original: a held
      lock and a symbolic link loop. All 133 reasons were compared
      with the Go table, and 130 match. The other three cannot be
      reached from this program.
      Checked by hand across the two binaries: 19 `passwd` invocations
      ran in four pairings of writer, changer, and reader. stdout,
      stderr, and the exit code matched, apart from clap's wording for
      an extra argument. After each change the other binary read a
      secret with the new passphrase and was refused with the old one.
      The vault recipient never changed.
- [x] **13. rekey**: lock, vault-on-identity check, staging, one
      transaction, swap, failure cleanup. Unit tests for
      `TestFailedRekeyKeepsStagedKeyOnAmbiguousCommit` and
      `TestPromoteStagedIdentityToleratesCompletedHeal` are in
      `src/cmd/rekey.rs`, so `make parity` now reads 217 ported and 4
      not ported.
      Gate: `rekey::` 14 of 14, `lifecycle::` 12 of 12, `identity::` 13 of
      13, `locks::rekey_` and `locks::identity_` 4 of 4.
      203 of 222 pass against `sanctuary`. Every test still red runs
      `migrate`.
      Checked by hand across the two binaries: 15 `rekey` invocations
      ran in four pairings of writer, rekeyer, and reader. stdout,
      stderr, and the exit code matched, apart from the differences
      `tests/PARITY.md` lists. After each rekey the other binary read
      every secret back, and the old key was refused. The rows were
      the same before and after, envelopes aside. No write-ahead log
      was left behind. The refusals were checked too: a vault that is
      not on the loaded identity, with and without a staged key, a
      corrupt envelope, a held lock, and a wrong passphrase. Each left
      the vault and the identity files as they were.
- [x] **14. migrate**: lock, format check, re-seal, env name
      sanitizing, straggler repair. The unit test for
      `TestConcurrentMigrateLoserGetsAlreadyCurrent` is in
      `src/vault/migrate.rs`, so `make parity` reads 218 ported and 3
      not ported. The 3 test log attribute groups, which the port does
      not have.
      Gate: `migrate::` 19 of 19, `locks::` 9 of 9,
      `tamper::non_reveal_verbs`.
      222 of 222 pass against `sanctuary`.
      The fallback that reported a verb as not ported is gone, since
      nothing reaches it.
      Checked by hand across the two binaries: 22 `migrate`
      invocations ran in four pairings of writer, migrator, and
      reader, on a format 1 vault built by hand with the `age`
      command. stdout, stderr, and the exit code matched, apart from
      the differences `tests/PARITY.md` lists. After each migration
      the other binary read every secret back, and the rows matched.
      The repair of a stranded version 1 envelope was checked the same
      way. So were the refusals: a newer format, a swapped recipient,
      a corrupt envelope, an envelope bound to another address, a
      newline in the stored expiry, a held lock, and a vault path that
      is missing, a directory, or empty. Each left the vault at
      format 1.
      One difference was added afterward, on purpose. The Go original
      prints the advice for an undecryptable envelope twice during
      `migrate`. `sanctuary` prints it once. safetybox v4.0.2 fixed it
      too, so the two agree again.

## After the review

An independent review of the whole tree found two medium and six low
defects. The reference moved to safetybox v4.0.2 first, commit
`e37428e`, which prints the `migrate` advice once and adds one test.
Each defect was then reproduced against both binaries, fixed, and
pinned by a test. Both suites and the unit tests ran clean after each
fix, before the next one started.

- [x] A stray argument was repeated in the usage error, so a value
      typed after the name in `set` reached stderr and the JSON log.
      No verb repeats one now.
- [x] A default path was not cleaned, so `rekey` under an unclean
      `XDG_CONFIG_HOME` committed the vault and then failed the
      identity swap. Every resolved path is cleaned once. That also
      covers an unclean `--identity`, which still fails in the Go
      original.
- [x] A relative vault path starting with `file:` opened as a SQLite
      URI. The vault landed in another file at mode 0644. A relative
      path is now anchored at `./`.
- [x] A broken pipe exited 1 with an error record. The default
      SIGPIPE action is restored at startup, so the command ends by
      the signal, as the Go original does.
- [x] One text column that was not UTF-8 stopped `list`, `show`,
      `reveal --env`, and `exec`. Text columns are now read the way
      the Go original reads them.
- [x] `set` accepted an upper-case stored recipient. It is refused
      now, with the Go original's message.
- [x] A value piped into `set` passed through the standard library's
      stdin buffer, which nothing wipes. The descriptor is read
      directly now, in the same steps the Go original reads it.
- [x] Database errors and a year before zero were worded differently.
      Both match the Go original now.

- [x] One env-named secret over the kernel's limit for a single
      variable made every `exec` fail. It is skipped now, with a
      warning that names it. The Go original still fails, and the
      test is exempt for it until it is fixed there.

230 of 230 pass against both binaries. `make parity` reads 222 Go
tests, 219 ported, 3 not ported.

Not changed, because the Go original shares them and they are not
defects of the port: the reserved env name list leaves out names such
as `PS1` and `NODE_OPTIONS`, and SQLite runs with `trusted_schema`
on.

## After the second review

A second independent review found one medium and five low defects.
Each was reproduced against both binaries, fixed, and pinned by a
test, with the same checks between fixes.

- [x] A secret withheld from `exec` for its value left a stale value
      of the same name in the child's environment. The variable is
      cleared now, and `reveal --format` writes an erase line. A
      reserved name keeps its inherited value. The Go original keeps
      the stale value.
- [x] An empty path flag, such as `--vault ''`, was refused. It counts
      as not passed now, as in the Go original.
- [x] `help` with an unknown topic and `completion` with an unknown
      shell exited 1. Both exit 0 now, as in the Go original.
- [x] A batch entry expired one instant later than the metadata verbs
      said. Both use the same boundary now.
- [x] `set` failed when stdin was a pipe in non-blocking mode. It
      waits for the writer now.
- [x] A hostile `TZ` or `TZDIR` stalled any run that wrote a JSON log
      record, and `TZ=/dev/zero` took about 40 GB of memory. The local
      offset comes from the C library now, and the time zone crate is
      gone.
- [x] A secret name edited to hold a newline or an escape sequence
      reached the terminal as written in a `rekey` or `migrate` error.
      A name the grammar does not allow is quoted now. The Go original
      prints it raw.

Not fixed, because nothing here can fix it: `Cargo.lock` holds
`crypto-bigint 0.5.5`, which RUSTSEC-2026-0387 names. It arrives
through `age 0.12.1`, the newest release, by way of `p256`, which is
not optional. `age` uses `p256` only for its tagged and SSH
recipients. `sanctuary` builds and opens X25519 and scrypt recipients
alone. Update `age` when a release moves off that version.

## After the first CI run

The first run on a GitHub runner failed two color tests against the Go
reference. The runner sets `CI`. The Go version's color library treats
a terminal as a pipe while `CI` is set, so the reference printed no
color where the tests expected it.

- `sanctuary` did not read `CI`, so it colored a terminal the Go
  version left plain. `src/color.rs` now follows the Go version.
  `CLICOLOR_FORCE` still turns color on.
- The harness passed `CI` through to the binary. It now removes it,
  next to the other color variables.
- `cli::terminal_help_is_plain_under_ci` pins the behavior for both
  binaries.

236 of 236 pass against both binaries.

## Done

- [x] `cargo test` passes 236 of 236 conformance tests against the Rust
      binary, on three runs in a row.
- [x] `make test-oracle` passes 236 of 236 against the Go binary.
- [x] All 22 tests in the "Ported as unit tests" table of
      `tests/PARITY.md` have a Rust unit test. The 3 left as not
      ported test log attribute groups, which the port does not have.
- [x] `make parity` and `make lint` pass.
- [x] A vault and identity made by the Go binary work under the Rust
      binary, and the reverse. Each step above records its own check.

Not done: `sanctuary` has never been run against a real vault.
