//! The on-disk envelope format, rebuilt independently of the binary.
//!
//! An envelope is an age file encrypted to the vault's X25519 recipient.
//! Its plaintext is a framed header followed by the value. The suite
//! builds and parses that frame itself, so a test can forge the rows an
//! attacker or an older binary would write, and can prove the binary
//! writes exactly the bytes the reference implementation writes.

/// The tag that opens every current-format frame.
pub const VERSION_TAG: &str = "sbx2";

/// The canonical address baked into every envelope.
pub fn address(name: &str, version: i64) -> String {
    format!("api/v1/{name}/{version}")
}

/// Encrypts `plaintext` to `recipient` with no framing of its own.
pub fn seal(recipient: &age::x25519::Recipient, plaintext: &[u8]) -> Vec<u8> {
    age::encrypt(recipient, plaintext).expect("age encrypt")
}

/// Decrypts an envelope to its framed plaintext.
#[track_caller]
pub fn open(key: &age::x25519::Identity, envelope: &[u8]) -> Vec<u8> {
    age::decrypt(key, envelope).unwrap_or_else(|err| panic!("envelope must decrypt: {err}"))
}

/// A parsed current-format frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub address: String,
    pub env_name: Option<String>,
    pub expires_at: Option<String>,
    pub value: Vec<u8>,
}

impl Frame {
    /// Parses `sbx2\n<address>\n[env:<name>\n][exp:<rfc3339>\n]\n<value>`.
    #[track_caller]
    pub fn parse(payload: &[u8]) -> Self {
        let split = payload
            .windows(2)
            .position(|window| window == b"\n\n")
            .expect("frame must carry a blank-line header terminator");

        let header = std::str::from_utf8(&payload[..split]).expect("frame header is text");
        let value = payload[split + 2..].to_vec();

        let mut lines = header.split('\n');

        assert_eq!(
            lines.next(),
            Some(VERSION_TAG),
            "frame must open with the version tag"
        );

        let address = lines
            .next()
            .expect("frame must carry an address")
            .to_owned();

        let mut env_name = None;
        let mut expires_at = None;

        for line in lines {
            if let Some(name) = line.strip_prefix("env:") {
                env_name = Some(name.to_owned());
            } else if let Some(expiry) = line.strip_prefix("exp:") {
                expires_at = Some(expiry.to_owned());
            } else {
                panic!("unknown frame header line {line:?}");
            }
        }

        Self {
            address,
            env_name,
            expires_at,
            value,
        }
    }

    /// Renders the frame exactly as the reference implementation does.
    pub fn encode(&self) -> Vec<u8> {
        let mut header = format!("{VERSION_TAG}\n{}\n", self.address);

        if let Some(env_name) = &self.env_name {
            header.push_str(&format!("env:{env_name}\n"));
        }

        if let Some(expires_at) = &self.expires_at {
            header.push_str(&format!("exp:{expires_at}\n"));
        }

        header.push('\n');

        let mut payload = header.into_bytes();
        payload.extend_from_slice(&self.value);

        payload
    }

    /// The version 1 frame: the address, one newline, then the value,
    /// with no version tag and no bound metadata.
    pub fn legacy(address: &str, value: &[u8]) -> Vec<u8> {
        let mut payload = format!("{address}\n").into_bytes();
        payload.extend_from_slice(value);

        payload
    }
}
