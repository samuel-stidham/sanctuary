//! The init verb: a new identity, a new vault, and a self-test of the
//! two together.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use age::x25519::{Identity, Recipient};

use super::cli::Globals;
use super::{Error, hint, passphrase, paths, recipient};
use crate::envelope::{self, Bound};
use crate::secret::Value;
use crate::sys::PathError;
use crate::vault::{self, Vault};
use crate::{identity, info, warn};

pub fn run(globals: &Globals) -> Result<(), Error> {
    let identity_path = paths::identity(globals.identity.as_deref(), &paths::process_env)?;
    let vault_path = paths::vault(globals.vault.as_deref(), &paths::process_env)?;

    match fs::metadata(&identity_path) {
        Ok(_) => {
            return Err(Error::Message(format!(
                "identity already exists at {}: refusing to overwrite it, move it aside first",
                identity_path.display()
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        // A permission or path error is not a green light to create.
        Err(err) => {
            return Err(Error::Message(format!(
                "stat identity {}: {}",
                identity_path.display(),
                PathError::new("stat", &identity_path, err)
            )));
        }
    }

    let passphrase = passphrase::read_new(
        globals.passphrase_file.as_deref(),
        "Passphrase for the new identity: ",
    )?;

    let key = Identity::generate();
    let recipient = key.to_public().to_string();

    identity::write(&identity_path, &key, &passphrase).map_err(hint::identity)?;

    if let Err(err) = vault::create(&vault_path, &recipient) {
        // The identity was written by this run and guards nothing yet,
        // so remove it to keep init retryable.
        let _ = fs::remove_file(&identity_path);

        return Err(hint::vault_in("create vault", err));
    }

    if let Err(reason) = self_test(&vault_path, &key) {
        // Both files were created by this run and guard nothing, so
        // remove them rather than wedge the next run on "already
        // exists".
        let _ = fs::remove_file(&identity_path);

        vault::remove_files(&vault_path);

        return Err(Error::Message(format!("self-test: {reason}")));
    }

    let identity_path = identity_path.to_string_lossy();

    info!(
        "safetybox initialized",
        "identity_path" => identity_path.as_ref(),
        "vault_path" => vault_path.to_string_lossy().as_ref(),
        "recipient" => recipient.as_str(),
    );

    // The backup warning is the one record a new user must not scroll
    // past: without the identity file the vault cannot be opened.
    warn!(
        "back up the identity file now: without it every secret in this vault is \
         unrecoverable, and the passphrase alone cannot recover them, copy the identity \
         file somewhere safe and offline",
        "identity_path" => identity_path.as_ref(),
    );

    Ok(())
}

/// Seals and opens one throwaway value through the full stack: the
/// recipient read back from the vault, the envelope seal, the envelope
/// open.
fn self_test(vault_path: &Path, key: &Identity) -> Result<(), String> {
    const ADDRESS: &str = "api/v1/safetybox/self-test/1";
    const PROBE: &[u8] = b"safetybox-init-self-test-probe";

    let vault = Vault::open(vault_path).map_err(|err| format!("open new vault: {err}"))?;
    let recipient = stored_recipient(&vault)?;

    let sealed = envelope::seal(&recipient, ADDRESS, &Bound::default(), &Value::new(PROBE))
        .map_err(|err| format!("seal probe: {err}"))?;

    let (opened, _) =
        envelope::open(key, ADDRESS, &sealed).map_err(|err| format!("open probe: {err}"))?;

    if opened.expose() != PROBE {
        return Err("round-trip produced different bytes".to_owned());
    }

    Ok(())
}

/// Reads and parses the vault's recipient. The write verbs need nothing
/// else, which is the point of the asymmetric model.
fn stored_recipient(vault: &Vault) -> Result<Recipient, String> {
    let stored = vault
        .recipient()
        .map_err(|err| format!("read stored recipient: {err}"))?;

    recipient::parse_stored(&stored)
}
