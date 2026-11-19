//! The passwd verb: a new passphrase around the same key.
//!
//! The key itself does not change, so the vault is untouched.

use std::path::Path;

use super::cli::Globals;
use super::decrypt::complete_interrupted_rekey;
use super::{Error, hint, lock, passphrase, paths};
use crate::{identity, info};

pub fn run(globals: &Globals, new_passphrase_file: Option<&Path>) -> Result<(), Error> {
    let identity_path = paths::identity(globals.identity.as_deref(), &paths::process_env)?;

    // Serialize against rekey and other passwd runs. An interleaved
    // passwd can overwrite an identity a rekey has just promoted, so
    // both verbs hold one lock for their whole run.
    let _lock = lock::acquire_identity(&identity_path)?;

    // Heal a rekey that crashed in the middle of its swap, like every
    // other verb that loads the identity. Without this, passwd would
    // report the identity missing and point at init while the live key
    // sits in the staged file.
    complete_interrupted_rekey(&identity_path)?;

    let current = passphrase::read(globals.passphrase_file.as_deref(), "Current passphrase: ")?;
    let key = identity::load(&identity_path, &current).map_err(hint::identity)?;
    let fresh = passphrase::read_new(new_passphrase_file, "New passphrase: ")?;

    identity::replace(&identity_path, &key, &fresh).map_err(hint::identity)?;

    info!("passphrase changed", "identity_path" => identity_path.to_string_lossy().as_ref());

    Ok(())
}
