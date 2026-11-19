//! Seals secret values in age envelopes bound to their vault address
//! and to the mutable metadata a read must verify.
//!
//! The plaintext inside every envelope starts with a small header. The
//! header carries a version tag, the canonical address
//! (`api/v1/<name>/<version>`), and the env name and expiry the secret
//! carried when this version was written. [`open`] verifies the address
//! against the row the blob came from, and returns the bound env name
//! and expiry so the caller can compare them to the plaintext columns.
//! That binds ciphertext to its row and makes a plaintext-column edit
//! detectable, as long as the writer holds the value. A holder of the
//! public recipient can still re-seal a whole forged envelope, so this
//! is tamper evidence for keyless writes, not authentication.

use std::io::Write;
use std::iter;

use age::x25519::{Identity, Recipient};
use zeroize::Zeroizing;

use crate::quote::quote;
use crate::secret::{self, Value};

/// Tags the framed plaintext. A version 1 vault had no tag and framed
/// only the address. A current envelope always carries this tag, so a
/// missing tag on a read is a framing failure, which also blocks a
/// downgrade to the older unbound frame.
const VERSION_TAG: &str = "sbx2";

const ENV_PREFIX: &str = "env:";
const EXPIRY_PREFIX: &str = "exp:";

/// The blank line that separates the header from the value. The header
/// lines are all non-empty, so the first occurrence is always the real
/// terminator.
const HEADER_TERMINATOR: &[u8] = b"\n\n";

/// The per-version metadata sealed into the envelope beside the value.
/// `None` means the secret had no env name or no expiry when the
/// version was written. An empty string means the same and is never
/// stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bound {
    pub env_name: Option<String>,
    pub expires_at: Option<String>,
}

impl Bound {
    pub fn new(env_name: Option<&str>, expires_at: Option<&str>) -> Self {
        let present =
            |field: Option<&str>| field.filter(|text| !text.is_empty()).map(str::to_owned);

        Self {
            env_name: present(env_name),
            expires_at: present(expires_at),
        }
    }
}

/// Why an envelope could not be sealed or opened. Every message quotes
/// the address, because an address comes from the vault file and may
/// carry a newline that would otherwise start a line of its own.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A field bound into the envelope cannot be framed.
    #[error("seal {}: {field} has a newline: invalid envelope frame", quote(.address))]
    InvalidFrame {
        address: String,
        field: &'static str,
    },

    /// age could not write the envelope.
    #[error("seal {}: {reason}", quote(.address))]
    Seal { address: String, reason: String },

    /// age could not open the envelope.
    #[error("open {}: envelope decrypt failed: {reason}", quote(.address))]
    DecryptFailed { address: String, reason: String },

    /// The payload decrypted cleanly but carries the version 1 frame,
    /// which has no version tag and no bound metadata. It is still a
    /// refusal, and a caller that cares can tell a stranded legacy row
    /// from real tampering. The usual cause is an older safetybox
    /// writing to a vault that migrate had already upgraded.
    #[error(
        "open {}: envelope is in the superseded version 1 format: envelope address mismatch",
        quote(.address)
    )]
    Legacy { address: String },

    /// The address inside the envelope does not match the row it was
    /// read from, or the frame is not one this format writes. Treat as
    /// tampering.
    #[error("open {}: {detail}envelope address mismatch", quote(.address))]
    AddressMismatch {
        address: String,
        detail: &'static str,
    },
}

impl Error {
    /// Whether the read must be refused as a mismatch. A legacy frame
    /// counts, so every caller that refuses tampering refuses it too.
    pub fn is_address_mismatch(&self) -> bool {
        matches!(self, Self::Legacy { .. } | Self::AddressMismatch { .. })
    }
}

/// Encrypts `value` to `recipient`, binding it to `address` and to
/// `bound`.
pub fn seal(
    recipient: &Recipient,
    address: &str,
    bound: &Bound,
    value: &Value,
) -> Result<Vec<u8>, Error> {
    // Check the framed fields in a fixed order, so a newline is
    // reported against a deterministic field.
    let framed = [
        ("address", address),
        ("env name", bound.env_name.as_deref().unwrap_or_default()),
        ("expiry", bound.expires_at.as_deref().unwrap_or_default()),
    ];

    if let Some((field, _)) = framed.iter().find(|(_, text)| text.contains('\n')) {
        return Err(Error::InvalidFrame {
            address: address.to_owned(),
            field,
        });
    }

    let failed = |reason: String| Error::Seal {
        address: address.to_owned(),
        reason,
    };

    let encryptor = age::Encryptor::with_recipients(iter::once(recipient as &dyn age::Recipient))
        .map_err(|err| failed(err.to_string()))?;

    let mut writer = encryptor
        .wrap_output(Vec::new())
        .map_err(|err| failed(err.to_string()))?;

    writer
        .write_all(&header(address, bound))
        .map_err(|err| failed(err.to_string()))?;
    writer
        .write_all(value.expose())
        .map_err(|err| failed(err.to_string()))?;

    writer.finish().map_err(|err| failed(err.to_string()))
}

/// Frames the version tag, address, and bound metadata, terminated by a
/// blank line.
fn header(address: &str, bound: &Bound) -> Vec<u8> {
    let mut header = format!("{VERSION_TAG}\n{address}\n");

    if let Some(env_name) = &bound.env_name {
        header.push_str(ENV_PREFIX);
        header.push_str(env_name);
        header.push('\n');
    }

    if let Some(expires_at) = &bound.expires_at {
        header.push_str(EXPIRY_PREFIX);
        header.push_str(expires_at);
        header.push('\n');
    }

    header.push('\n');

    header.into_bytes()
}

/// Decrypts `blob` with `identity`, verifies it is bound to `address`,
/// and returns the value with the env name and expiry sealed into it.
/// The caller compares those against the plaintext columns to detect a
/// metadata edit. The header is stripped before the value is wrapped.
pub fn open(identity: &Identity, address: &str, blob: &[u8]) -> Result<(Value, Bound), Error> {
    // The payload holds plaintext on every path, including the mismatch
    // refusals where it is the wrong row's plaintext. It wipes itself
    // when it drops, and the value copies only what it keeps.
    let payload = decrypt(identity, address, blob)?;

    let (value, bound) = parse_frame(address, &payload)?;

    Ok((Value::new(value), bound))
}

/// Decrypts a version 1 envelope, whose frame is the address, a
/// newline, and the value, with no version tag and no bound metadata.
/// It is used only by the format migration to read the old frame before
/// re-sealing it into the current one with [`seal`].
pub fn open_legacy(identity: &Identity, address: &str, blob: &[u8]) -> Result<Value, Error> {
    let payload = decrypt(identity, address, blob)?;

    match split_once(&payload, b"\n") {
        Some((embedded, value)) if embedded == address.as_bytes() => Ok(Value::new(value)),
        _ => Err(Error::AddressMismatch {
            address: address.to_owned(),
            detail: "",
        }),
    }
}

/// Decrypts `blob` into a buffer that wipes itself, leaving no unwiped
/// intermediate copies behind.
fn decrypt(identity: &Identity, address: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let failed = |reason: String| Error::DecryptFailed {
        address: address.to_owned(),
        reason,
    };

    let decryptor = age::Decryptor::new(blob).map_err(|err| failed(err.to_string()))?;

    let reader = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|err| failed(err.to_string()))?;

    secret::read_all_wiping(reader).map_err(|err| failed(err.to_string()))
}

/// Splits the decrypted payload into its header and value, checks the
/// version tag and address, and reads the bound metadata. A missing
/// tag, a wrong address, or an unknown header line is a framing
/// failure, reported as a mismatch so the read path treats it as
/// tampering.
fn parse_frame<'a>(address: &str, payload: &'a [u8]) -> Result<(&'a [u8], Bound), Error> {
    let mismatch = |detail: &'static str| Error::AddressMismatch {
        address: address.to_owned(),
        detail,
    };

    // A version 1 frame is the bare address, a single newline, then the
    // value, so it carries no blank-line terminator at all. Recognise
    // it before the split. A current frame starts with the version tag,
    // and a canonical address never equals that tag, so the two cannot
    // be confused.
    if payload
        .strip_prefix(address.as_bytes())
        .is_some_and(|rest| rest.starts_with(b"\n"))
    {
        return Err(Error::Legacy {
            address: address.to_owned(),
        });
    }

    let (header, value) =
        split_once(payload, HEADER_TERMINATOR).ok_or_else(|| mismatch("no header terminator: "))?;

    let mut lines = header.split(|byte| *byte == b'\n');

    let (Some(tag), Some(embedded)) = (lines.next(), lines.next()) else {
        return Err(mismatch("not a v2 envelope: "));
    };

    if tag != VERSION_TAG.as_bytes() {
        return Err(mismatch("not a v2 envelope: "));
    }

    if embedded != address.as_bytes() {
        return Err(mismatch(""));
    }

    let mut bound = Bound::default();

    for line in lines {
        // Metadata that is not text can match no column, so it reads as
        // a line this format never writes.
        let line = std::str::from_utf8(line).map_err(|_| mismatch("unknown header line: "))?;

        if let Some(env_name) = line.strip_prefix(ENV_PREFIX) {
            bound.env_name = Some(env_name)
                .filter(|text| !text.is_empty())
                .map(str::to_owned);
        } else if let Some(expires_at) = line.strip_prefix(EXPIRY_PREFIX) {
            bound.expires_at = Some(expires_at)
                .filter(|text| !text.is_empty())
                .map(str::to_owned);
        } else {
            return Err(mismatch("unknown header line: "));
        }
    }

    Ok((value, bound))
}

/// Splits `bytes` around the first `separator`.
fn split_once<'a>(bytes: &'a [u8], separator: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let at = bytes
        .windows(separator.len())
        .position(|window| window == separator)?;

    Some((&bytes[..at], &bytes[at + separator.len()..]))
}

#[cfg(test)]
mod tests {
    use age::x25519::Identity;

    use super::{Bound, Error, open, open_legacy, parse_frame, seal};
    use crate::secret::Value;

    // Obviously fake test material, never a real secret.
    const FAKE_VALUE: &[u8] = b"fake-envelope-value-not-real";
    const ADDRESS: &str = "api/v1/testing/fake/1";
    const SPOOFED: &str = "api/v1/spoof\nwarning: fake injected line/1";

    fn value() -> Value {
        Value::new(FAKE_VALUE)
    }

    /// Encrypts a raw payload with no framing, the way an older binary
    /// or an attacker would.
    fn seal_raw(identity: &Identity, payload: &[u8]) -> Vec<u8> {
        age::encrypt(&identity.to_public(), payload).expect("age encrypt")
    }

    // Go: TestSealOpenRoundTrip
    #[test]
    fn seal_open_round_trip() {
        let identity = Identity::generate();
        let bound = Bound::new(Some("FAKE_ENV"), Some("2030-01-02T00:00:00Z"));

        let blob = seal(&identity.to_public(), ADDRESS, &bound, &value()).expect("seal");
        let (opened, read_back) = open(&identity, ADDRESS, &blob).expect("open");

        assert_eq!(opened.expose(), FAKE_VALUE);
        assert_eq!(read_back, bound);
    }

    // An empty field is the same as an absent one, in and out.
    #[test]
    fn empty_metadata_is_not_framed() {
        let identity = Identity::generate();
        let bound = Bound::new(Some(""), None);

        assert_eq!(bound, Bound::default());

        let blob = seal(&identity.to_public(), ADDRESS, &bound, &value()).expect("seal");
        let payload = age::decrypt(&identity, &blob).expect("decrypt");

        assert_eq!(
            payload,
            [b"sbx2\napi/v1/testing/fake/1\n\n", FAKE_VALUE].concat()
        );
    }

    // Go: TestOpenWrongAddressFails
    #[test]
    fn open_wrong_address_fails() {
        let identity = Identity::generate();
        let blob = seal(&identity.to_public(), ADDRESS, &Bound::default(), &value()).expect("seal");

        let err = open(&identity, "api/v1/testing/other/1", &blob).expect_err("must refuse");

        assert!(err.is_address_mismatch());
        assert_eq!(
            err.to_string(),
            "open \"api/v1/testing/other/1\": envelope address mismatch"
        );
    }

    // Go: TestOpenWrongIdentityFails
    #[test]
    fn open_wrong_identity_fails() {
        let blob = seal(
            &Identity::generate().to_public(),
            ADDRESS,
            &Bound::default(),
            &value(),
        )
        .expect("seal");

        let err = open(&Identity::generate(), ADDRESS, &blob).expect_err("must refuse");

        assert!(matches!(err, Error::DecryptFailed { .. }));
        assert!(
            err.to_string()
                .starts_with("open \"api/v1/testing/fake/1\": envelope decrypt failed: ")
        );
    }

    // Go: TestSealRejectsAddressWithSeparator
    //
    // A newline in the address would let it forge header lines.
    #[test]
    fn seal_rejects_an_address_with_a_separator() {
        let recipient = Identity::generate().to_public();

        let err = seal(
            &recipient,
            "api/v1/a\nenv:FORGED/1",
            &Bound::default(),
            &value(),
        )
        .expect_err("must refuse");

        assert!(matches!(
            err,
            Error::InvalidFrame {
                field: "address",
                ..
            }
        ));
    }

    // Go: TestSealQuotesAnAddressCarryingANewline
    #[test]
    fn seal_quotes_an_address_carrying_a_newline() {
        let recipient = Identity::generate().to_public();

        let message = seal(&recipient, SPOOFED, &Bound::default(), &value())
            .expect_err("must refuse")
            .to_string();

        assert_eq!(
            message.lines().count(),
            1,
            "an error must stay on one line: {message:?}"
        );
        assert_eq!(
            message,
            "seal \"api/v1/spoof\\nwarning: fake injected line/1\": \
             address has a newline: invalid envelope frame"
        );
    }

    // Go: TestSealReportsFirstInvalidFieldDeterministically
    //
    // With a newline in every field, the address is always the one named.
    #[test]
    fn seal_reports_the_first_invalid_field_deterministically() {
        let recipient = Identity::generate().to_public();
        let everything = Bound::new(Some("A\nB"), Some("C\nD"));

        for _ in 0..20 {
            let err = seal(&recipient, "x\ny", &everything, &value()).expect_err("must refuse");

            assert!(matches!(
                err,
                Error::InvalidFrame {
                    field: "address",
                    ..
                }
            ));
        }

        let err = seal(&recipient, ADDRESS, &everything, &value()).expect_err("must refuse");
        assert!(matches!(
            err,
            Error::InvalidFrame {
                field: "env name",
                ..
            }
        ));

        let expiry_only = Bound::new(None, Some("C\nD"));
        let err = seal(&recipient, ADDRESS, &expiry_only, &value()).expect_err("must refuse");
        assert!(matches!(
            err,
            Error::InvalidFrame {
                field: "expiry",
                ..
            }
        ));
    }

    // Go: TestOpenLegacyQuotesAnAddressCarryingANewline
    #[test]
    fn open_legacy_quotes_an_address_carrying_a_newline() {
        let identity = Identity::generate();
        let blob = seal_raw(&identity, b"api/v1/other/1\nfake-value");

        let message = open_legacy(&identity, SPOOFED, &blob)
            .expect_err("must refuse")
            .to_string();

        assert_eq!(
            message.lines().count(),
            1,
            "an error must stay on one line: {message:?}"
        );
        assert_eq!(
            message,
            "open \"api/v1/spoof\\nwarning: fake injected line/1\": envelope address mismatch"
        );
    }

    // Go: TestOpenLegacyRoundTrip
    #[test]
    fn open_legacy_reads_the_version_one_frame() {
        let identity = Identity::generate();
        let blob = seal_raw(
            &identity,
            &[b"api/v1/testing/fake/1\n", FAKE_VALUE].concat(),
        );

        assert_eq!(
            open_legacy(&identity, ADDRESS, &blob)
                .expect("open")
                .expose(),
            FAKE_VALUE
        );

        // The current reader refuses it, and says which kind of refusal.
        let err = open(&identity, ADDRESS, &blob).expect_err("must refuse");

        assert!(matches!(err, Error::Legacy { .. }));
        assert!(err.is_address_mismatch());
    }

    // Every frame this format does not write is a mismatch.
    #[test]
    fn parse_frame_refuses_foreign_frames() {
        let cases: [(&[u8], &str); 6] = [
            (b"sbx2\napi/v1/testing/fake/1\n", "no header terminator: "),
            (b"", "no header terminator: "),
            (b"sbx1\napi/v1/testing/fake/1\n\nv", "not a v2 envelope: "),
            (b"sbx2\n\nv", "not a v2 envelope: "),
            (b"sbx2\napi/v1/testing/other/1\n\nv", ""),
            (
                b"sbx2\napi/v1/testing/fake/1\nzzz:1\n\nv",
                "unknown header line: ",
            ),
        ];

        for (payload, want) in cases {
            match parse_frame(ADDRESS, payload) {
                Err(Error::AddressMismatch { detail, .. }) => assert_eq!(detail, want),
                other => panic!("{payload:?} must be a mismatch, got {other:?}"),
            }
        }
    }

    // The value is everything after the first blank line, blank lines
    // of its own included.
    #[test]
    fn parse_frame_keeps_the_value_verbatim() {
        let (value, bound) = parse_frame(
            ADDRESS,
            b"sbx2\napi/v1/testing/fake/1\nexp:2030-01-02T00:00:00Z\n\na\n\nb\n",
        )
        .expect("parse");

        assert_eq!(value, b"a\n\nb\n");
        assert_eq!(bound, Bound::new(None, Some("2030-01-02T00:00:00Z")));
    }
}
