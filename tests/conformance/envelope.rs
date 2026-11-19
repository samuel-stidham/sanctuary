//! The envelope format. Ports `internal/envelope/envelope_test.go`
//! through the bytes the binary stores and the bytes it accepts.
//!
//! The Go tests call Seal and Open directly. Here the test decrypts
//! what `set` stored to prove the frame, and plants hand-built
//! envelopes to prove what a read refuses.

use crate::support::envelope::{self, Frame, VERSION_TAG};
use crate::support::{Fixture, VALUE_ONE, VALUE_TWO, msg, other_key};

const NAME: &str = "testing/fake";

fn fixture_with_secret() -> Fixture {
    let fixture = Fixture::new();

    fixture.set(NAME, VALUE_ONE, &[]);

    fixture
}

/// Replaces the newest envelope of `NAME` with `plaintext` sealed to
/// the vault's own recipient.
fn plant(fixture: &Fixture, plaintext: &[u8]) {
    let row = fixture.newest_enabled(NAME);

    fixture.store_envelope(
        row.id,
        &envelope::seal(&fixture.key().to_public(), plaintext),
    );
}

// Go: TestSealOpenRoundTrip
//
// The stored envelope is an age file to the vault's recipient. Its
// plaintext is the version tag, the canonical address, a blank line,
// then the value, and the ciphertext holds none of it.
#[test]
fn seal_open_round_trip() {
    let fixture = fixture_with_secret();
    let row = fixture.newest_enabled(NAME);

    assert!(
        row.envelope
            .starts_with(b"age-encryption.org/v1\n-> X25519 "),
        "the envelope is a binary age file with an X25519 stanza"
    );
    assert!(
        !row.envelope
            .windows(VALUE_ONE.len())
            .any(|window| window == VALUE_ONE.as_bytes()),
        "the sealed blob must not contain plaintext"
    );

    let payload = envelope::open(&fixture.key(), &row.envelope);

    assert_eq!(
        payload,
        format!("{VERSION_TAG}\napi/v1/{NAME}/1\n\n{VALUE_ONE}").into_bytes(),
        "an empty bound frames as the tag, the address, and a blank line"
    );
    assert_eq!(fixture.reveal_value(NAME), VALUE_ONE);
}

// Go: TestSealOpenBindsMetadata
//
// The env name and expiry seal into the envelope, in that order, so a
// read can compare them to the plaintext columns.
#[test]
fn seal_open_binds_metadata() {
    let fixture = Fixture::new();

    fixture.set(
        NAME,
        VALUE_ONE,
        &[
            "--env-name",
            "FAKE_KEY",
            "--expires",
            "2030-01-02T03:04:05Z",
        ],
    );

    let row = fixture.newest_enabled(NAME);

    assert!(
        !row.envelope.windows(8).any(|window| window == b"FAKE_KEY"),
        "the sealed blob must not contain the plaintext env name"
    );

    let payload = envelope::open(&fixture.key(), &row.envelope);

    assert_eq!(
        payload,
        format!(
            "{VERSION_TAG}\napi/v1/{NAME}/1\nenv:FAKE_KEY\nexp:2030-01-02T03:04:05Z\n\n{VALUE_ONE}"
        )
        .into_bytes()
    );

    fixture.ok("", &["get", NAME]);
}

// The expiry is bound in UTC whatever offset it was given in, and a
// later version carries the metadata it inherited.
#[test]
fn seal_binds_the_effective_metadata_of_each_version() {
    let fixture = Fixture::new();

    fixture.set(
        NAME,
        VALUE_ONE,
        &[
            "--env-name",
            "FAKE_KEY",
            "--expires",
            "2030-01-02T03:04:05+02:00",
        ],
    );
    fixture.set(NAME, VALUE_TWO, &[]);

    let frame = fixture.open_frame(&fixture.key(), &fixture.newest_enabled(NAME));

    assert_eq!(
        frame,
        Frame {
            address: envelope::address(NAME, 2),
            env_name: Some("FAKE_KEY".to_owned()),
            expires_at: Some("2030-01-02T01:04:05Z".to_owned()),
            value: VALUE_TWO.as_bytes().to_vec(),
        }
    );
}

// A value that itself holds blank lines survives: the first blank line
// is always the header terminator.
#[test]
fn value_with_blank_lines_round_trips() {
    let fixture = Fixture::new();
    let value = "line one\n\nline three\n\n\nend";

    fixture.set(NAME, value, &["--env-name", "FAKE_KEY"]);

    assert_eq!(fixture.reveal_value(NAME), value);
}

// An envelope another implementation sealed in the same frame reads
// back, with and without bound metadata.
#[test]
fn reads_an_envelope_sealed_by_another_implementation() {
    let fixture = fixture_with_secret();

    plant(
        &fixture,
        &Frame {
            address: envelope::address(NAME, 1),
            env_name: None,
            expires_at: None,
            value: b"fake-planted-value".to_vec(),
        }
        .encode(),
    );

    assert_eq!(fixture.reveal_value(NAME), "fake-planted-value");
}

// Go: TestOpenWrongAddressFails
//
// An envelope moved to another row, another version, or a truncated or
// empty address is refused. The binding travels inside the ciphertext.
#[test]
fn open_wrong_address_fails() {
    let fixture = fixture_with_secret();

    for address in [
        "api/v1/testing/other/1",
        "api/v1/testing/fake/2",
        "",
        "api/v1/testing/fake",
    ] {
        plant(
            &fixture,
            &Frame {
                address: address.to_owned(),
                env_name: None,
                expires_at: None,
                value: VALUE_ONE.as_bytes().to_vec(),
            }
            .encode(),
        );

        let refused = fixture
            .fail("", &["reveal", NAME])
            .assert_stderr(msg::ADDRESS_MISMATCH);

        assert!(
            !refused.stdout.contains(VALUE_ONE),
            "address {address:?} must be refused"
        );
    }
}

// Go: TestOpenWrongAddressFails ("different secret")
//
// The same refusal for real rows: swapping two secrets' envelopes
// breaks both reads.
#[test]
fn swapped_envelopes_fail() {
    let fixture = Fixture::new();

    fixture.set("swap/one", VALUE_ONE, &[]);
    fixture.set("swap/two", VALUE_TWO, &[]);

    let one = fixture.newest_enabled("swap/one");
    let two = fixture.newest_enabled("swap/two");

    fixture.store_envelope(one.id, &two.envelope);
    fixture.store_envelope(two.id, &one.envelope);

    fixture
        .fail("", &["get", "swap/one"])
        .assert_stderr(msg::ADDRESS_MISMATCH);
    fixture
        .fail("", &["get", "swap/two"])
        .assert_stderr(msg::ADDRESS_MISMATCH);
}

// Go: TestOpenWrongIdentityFails
//
// An envelope sealed to some other key cannot be opened, and the error
// points at the identity rather than at tampering.
#[test]
fn open_wrong_identity_fails() {
    let fixture = fixture_with_secret();
    let row = fixture.newest_enabled(NAME);

    let frame = fixture.open_frame(&fixture.key(), &row);

    fixture.store_envelope(
        row.id,
        &envelope::seal(&other_key().to_public(), &frame.encode()),
    );

    fixture
        .fail("", &["get", NAME])
        .assert_stderr(msg::ENVELOPE_DECRYPT_FAILED)
        .assert_stderr("the identity may not match this vault");
}

// Go: TestOpenCorruptOneByteFails
//
// Corrupting any byte must fail the read and never yield plaintext.
// The Go test flips every byte in process. Each read here pays the
// passphrase KDF, so this samples the header, the stanza, the MAC, the
// payload nonce, the body, and the final byte.
#[test]
fn open_corrupt_one_byte_fails() {
    let fixture = fixture_with_secret();
    let row = fixture.newest_enabled(NAME);
    let length = row.envelope.len();

    let header_end = row
        .envelope
        .windows(4)
        .position(|window| window == b"\n---")
        .expect("an age header ends with a MAC line");

    for index in [
        0,
        10,
        30,
        header_end - 5,
        header_end + 10,
        length - 40,
        length / 2,
        length - 1,
    ] {
        let mut corrupted = row.envelope.clone();
        corrupted[index] ^= 0xff;

        fixture.store_envelope(row.id, &corrupted);

        let refused = fixture.fail("", &["reveal", NAME]);

        assert!(
            !refused.stdout.contains(VALUE_ONE),
            "corrupting byte {index} must never yield plaintext"
        );
        assert!(
            refused.stderr.contains(msg::ENVELOPE_DECRYPT_FAILED),
            "corrupting byte {index} must fail decryption: {}",
            refused.stderr
        );
    }
}

// Go: TestOpenLegacyFrameFails
//
// An envelope without the version tag is refused, which blocks a
// downgrade to the older unbound frame.
#[test]
fn open_legacy_frame_fails() {
    let fixture = fixture_with_secret();

    plant(
        &fixture,
        &Frame::legacy(&envelope::address(NAME, 1), VALUE_ONE.as_bytes()),
    );

    let refused = fixture
        .fail("", &["reveal", NAME])
        .assert_stderr(msg::ADDRESS_MISMATCH);

    assert!(!refused.stdout.contains(VALUE_ONE));
}

// Go: TestOpenBlobWithoutHeaderFails
//
// A payload with no header frame at all, an unknown version tag, and an
// unknown header line are all framing failures.
#[test]
fn open_blob_without_valid_header_fails() {
    let fixture = fixture_with_secret();
    let address = envelope::address(NAME, 1);

    let payloads = [
        "no-terminator-in-here".to_owned(),
        format!("sbx3\n{address}\n\n{VALUE_ONE}"),
        format!("{VERSION_TAG}\n{address}\nbogus:line\n\n{VALUE_ONE}"),
        format!("{VERSION_TAG}\n\n{VALUE_ONE}"),
    ];

    for payload in payloads {
        plant(&fixture, payload.as_bytes());

        let refused = fixture
            .fail("", &["reveal", NAME])
            .assert_stderr(msg::ADDRESS_MISMATCH);

        assert!(
            !refused.stdout.contains(VALUE_ONE),
            "payload {payload:?} must be refused"
        );
    }
}

// Go: TestOpenTruncatedBlobFails
#[test]
fn open_truncated_blob_fails() {
    let fixture = fixture_with_secret();
    let row = fixture.newest_enabled(NAME);
    let sealed = &row.envelope;

    let truncations: [(&str, &[u8]); 5] = [
        ("empty", &[]),
        ("one byte", &sealed[..1]),
        ("header only", &sealed[..(sealed.len() - 1).min(100)]),
        ("half", &sealed[..sealed.len() / 2]),
        ("one byte short", &sealed[..sealed.len() - 1]),
    ];

    for (name, blob) in truncations {
        fixture.store_envelope(row.id, blob);

        let refused = fixture.fail("", &["reveal", NAME]);

        assert!(
            refused.stderr.contains(msg::ENVELOPE_DECRYPT_FAILED),
            "{name}: a truncated envelope must fail decryption: {}",
            refused.stderr
        );
    }
}

// Go: TestSealOpenRoundTripLargeValue
//
// A payload past the wiping reader's growth boundary round-trips.
#[test]
fn seal_open_round_trip_large_value() {
    let fixture = Fixture::new();
    let large = "fake-large-payload-not-real-".repeat(200);

    fixture.set(NAME, &large, &[]);

    assert_eq!(fixture.reveal_value(NAME), large);
    assert_eq!(
        fixture
            .open_frame(&fixture.key(), &fixture.newest_enabled(NAME))
            .value,
        large.as_bytes()
    );
}

// Go: TestOpenQuotesAnAddressCarryingANewline
//
// Every open refusal names the address it was asked about, and a batch
// builds addresses from the name column a vault-write attacker
// controls. A newline there is quoted, so the refusal stays on one line
// and injected text cannot pose as a log record of its own.
#[test]
fn open_quotes_an_address_carrying_a_newline() {
    let fixture = Fixture::new();

    fixture.set("spoof/one", VALUE_ONE, &[]);
    fixture.sql(
        "UPDATE secret SET name = ?1 WHERE name = 'spoof/one'",
        ["spoof/one\nWARN fake injected line"],
    );

    let refused = fixture.fail("", &["reveal", "--prefix", "spoof"]);

    assert_eq!(
        refused.stderr,
        "ERRO open \"spoof/one\\nWARN fake injected line\": \
         open \"api/v1/spoof/one\\nWARN fake injected line/1\": envelope address mismatch\n",
        "the newline must appear escaped, not literal"
    );
    assert!(refused.stdout.is_empty());
}
