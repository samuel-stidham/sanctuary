//! The show verb: a secret's metadata, never its value.

use super::cli::Globals;
use super::{Error, hint, open_vault, print_json};
use crate::json::Json;
use crate::timestamp::Time;
use crate::vault::{SecretMeta, VersionMeta};

pub fn run(globals: &Globals, name: &str) -> Result<(), Error> {
    let vault = open_vault(globals)?;
    let (secret, versions) = vault.meta(name).map_err(hint::vault)?;

    let expired = secret.expired(Time::now());
    let mut output = secret_members(secret);

    output.push(("expired", expired.into()));
    output.push(("versions", versions_json(&versions)));

    print_json(globals, &Json::Object(output))
}

/// A secret's metadata as result output members, in the order every
/// verb prints them. Output carries metadata only: never the value,
/// its length, or anything worked out from the plaintext.
pub fn secret_members(secret: SecretMeta) -> Vec<(&'static str, Json)> {
    let mut members = vec![("name", Json::from(secret.name))];

    if let Some(env_name) = secret.env_name {
        members.push(("envName", env_name.into()));
    }

    members.push(("createdAt", secret.created_at.to_output().into()));
    members.push(("updatedAt", secret.updated_at.to_output().into()));

    if let Some(deleted_at) = secret.deleted_at {
        members.push(("deletedAt", deleted_at.to_output().into()));
    }

    if let Some(expires_at) = secret.expires_at {
        members.push(("expiresAt", expires_at.to_output().into()));
    }

    members
}

/// The version history. A secret with no version rows prints `null`,
/// as the Go original does.
fn versions_json(versions: &[VersionMeta]) -> Json {
    if versions.is_empty() {
        return Json::Null;
    }

    Json::Array(
        versions
            .iter()
            .map(|version| {
                Json::Object(vec![
                    ("version", version.number.into()),
                    ("state", version.state.as_str().into()),
                    ("createdAt", version.created_at.to_output().into()),
                ])
            })
            .collect(),
    )
}
