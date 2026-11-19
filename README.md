# ![sanctuary](docs/assets/sanctuary-lockup.svg)

sanctuary is the Rust version of
[SafetyBox](https://github.com/samuel-stidham/safetybox), a single-user,
CLI-first secrets manager for *nix. It keeps named, versioned secrets in
a SQLite vault. Every value is sealed in an
[age](https://age-encryption.org) envelope before it touches disk.

## Two versions, both maintained

SafetyBox exists in two versions, and both are maintained.

| Version | Command | Repository |
| --- | --- | --- |
| Go | `safetybox` | [samuel-stidham/safetybox](https://github.com/samuel-stidham/safetybox) |
| Rust | `sanctuary` | this repository |

The Go version came first and is the reference. sanctuary is a rewrite
of it in idiomatic Rust, held to the same features and the same
behavior. Neither version replaces the other.

The two commands have different names, so both can sit on one PATH.
They read the same vault and the same identity file, at the same paths.
A vault created by one opens with the other.

Each version carries its own version number. sanctuary names the Go
release it is compatible with in its version line.

```console
$ sanctuary --version
sanctuary 0.1.0 (Rust, compatible with safetybox v4.0.2)
```

A behavior change lands in both versions. The Go release is tagged
first, then sanctuary moves its reference to that tag.

## Status

Every command of the Go version is ported: `init`, `set`, `get`,
`reveal`, `exec`, `passwd`, `rekey`, `migrate`, `show`, `list`,
`stale`, `disable`, `delete`, and `purge`. Each one reads and writes
the vault and the identity the Go version uses, and prints what the Go
version prints. sanctuary passes all 236 tests of the shared suite, as
the Go version does.

sanctuary has only been run against test vaults so far. Back up the
vault file and the identity file before the first run against real
secrets. [PORTING.md](PORTING.md) records each step and what was
checked.

## How parity is held

One conformance suite runs against both binaries. It drives each binary
as a black box, so it tests behavior and never the code behind it.

The Go binary must pass every test before a result from the Rust binary
counts. A test is never edited to make the port pass. The suite
currently holds 236 tests, and [tests/PARITY.md](tests/PARITY.md) maps
each Go test to its counterpart here.

The reference is built from a pinned commit of the Go repository. The
`Makefile` records that commit and its tag.

## Intended differences

sanctuary differs from the Go version in presentation only.

| What | Go version | Rust version |
| --- | --- | --- |
| Command name, in help and in hints | `safetybox` | `sanctuary` |
| Version line | `safetybox version v4.0.2` | `sanctuary 0.1.0 (Rust, compatible with safetybox v4.0.2)` |
| Help layout | cobra | laid out by sanctuary, in clap's vocabulary |
| Usage error wording | cobra | clap, cut to one line |
| Completion scripts | cobra | `clap_complete` |

Everything else is the same: the vault and identity formats, the
environment variables, result output, log records, prompts, and exit
codes.

## Configuration

sanctuary uses the Go version's paths and variables, unchanged. The
vault lives at `$XDG_DATA_HOME/safetybox/vault.db`. The identity lives
at `$XDG_CONFIG_HOME/safetybox/identity.age`. The directory keeps the
name `safetybox` so both commands open one vault.

A flag beats an environment variable, and both beat the default. The
flags are `--vault` and `--identity`. The environment variables are
`SAFETYBOX_VAULT` and `SAFETYBOX_IDENTITY`.

## Development

`make help` lists every target. Building the reference needs a Go
toolchain and a local clone of the Go repository. `ORACLE_REPO` in the
`Makefile` points at that clone.

```sh
make oracle        # build the Go reference into target/oracle/
make test-oracle   # run the conformance suite against the Go reference
make test          # run the unit tests and the suite against sanctuary
make parity        # check every Go test is ported or accounted for
make lint          # rustfmt and clippy
```

The suite never touches a real vault. Each test runs in its own
temporary home directory, with the `SAFETYBOX_*` and `XDG_*` variables
removed.

## Known issues

`cargo audit` reports RUSTSEC-2026-0387 against `crypto-bigint 0.5.5`.
sanctuary does not depend on that crate directly. It arrives through
`age`, which needs `p256` for its tagged and SSH recipient types, and
`age` does not make `p256` optional.

sanctuary uses X25519 keys and a scrypt-protected identity only. It
never builds or opens the recipient types that use `p256`, so no code
path of sanctuary calls the affected crate.

This will be fixed when `age` releases a version on a patched
`crypto-bigint`. sanctuary will move to that release then.

## License

MIT. See `LICENSE`.
