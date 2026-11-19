//! The list and stale verbs: metadata for many secrets at once. Names
//! are plaintext columns, so neither needs the identity.

use super::cli::Globals;
use super::show::secret_members;
use super::{Error, hint, open_vault, print_json};
use crate::json::Json;
use crate::timestamp::Time;
use crate::vault::Summary;

/// Lists every live secret, or the ones under `prefix`.
pub fn run(globals: &Globals, prefix: &str) -> Result<(), Error> {
    let vault = open_vault(globals)?;
    let summaries = vault.list(prefix).map_err(hint::vault)?;

    print_json(globals, &entries(summaries))
}

/// Lists the secrets whose expiry has passed. They still resolve.
/// Expiry marks a secret stale and never deletes it.
pub fn run_stale(globals: &Globals) -> Result<(), Error> {
    let vault = open_vault(globals)?;
    let summaries = vault.stale(Time::now()).map_err(hint::vault)?;

    print_json(globals, &entries(summaries))
}

/// Each summary with its expiry state worked out against one clock
/// read.
fn entries(summaries: Vec<Summary>) -> Json {
    let now = Time::now();

    Json::Array(
        summaries
            .into_iter()
            .map(|summary| {
                let expired = summary.secret.expired(now);
                let mut members = secret_members(summary.secret);

                members.push(("latestVersion", summary.latest_version.into()));
                members.push(("expired", expired.into()));

                Json::Object(members)
            })
            .collect(),
    )
}
