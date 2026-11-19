//! The get verb: decrypt and verify the newest enabled version, and
//! print its metadata with the value redacted.

use super::cli::Globals;
use super::decrypt::resolve_newest;
use super::{Error, print_json};
use crate::json::Json;
use crate::secret::REDACTED;
use crate::timestamp::Time;

pub fn run(globals: &Globals, name: &str) -> Result<(), Error> {
    // The value is decrypted to prove it opens and is bound to its
    // row. It is never printed, so it is wiped as soon as that is
    // known. Only reveal shows plaintext.
    let resolved = resolve_newest(globals, name)?;
    let secret = resolved.secret;

    drop(resolved.value);

    let expired = secret.expired(Time::now());

    let mut output = vec![
        ("name", Json::from(secret.name)),
        ("version", resolved.version.number.into()),
        ("state", resolved.version.state.as_str().into()),
    ];

    if let Some(env_name) = secret.env_name {
        output.push(("envName", env_name.into()));
    }

    output.push(("createdAt", secret.created_at.to_output().into()));
    output.push(("updatedAt", secret.updated_at.to_output().into()));

    if let Some(expires_at) = secret.expires_at {
        output.push(("expiresAt", expires_at.to_output().into()));
    }

    output.push(("expired", expired.into()));
    output.push(("value", REDACTED.into()));

    print_json(globals, &Json::Object(output))
}
