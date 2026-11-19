//! Reading and writing secrets.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::types::{
    AppendResult, Change, Entry, EntryFilter, Resolved, SealRequest, SecretMeta, SetOptions, State,
    Summary, VersionMeta, canonical_address, is_valid_name,
};
use super::types::{optional_text, shown_name, text};
use super::{Error, META_RECIPIENT, ResealFailure, Vault};
use crate::quote::quote;
use crate::timestamp::Time;

/// The secret table, as stored.
struct SecretRow {
    id: i64,
    name: String,
    env_name: Option<String>,
    created_at: String,
    updated_at: String,
    deleted_at: Option<String>,
    expires_at: Option<String>,
}

impl SecretRow {
    fn meta(&self) -> Result<SecretMeta, Error> {
        let stored = |column: &'static str, raw: &str| {
            // The secret is named, so an operator can tell which of
            // possibly hundreds of rows was edited.
            parse_stored(raw, column, || format!("secret {}", quote(&self.name)))
        };

        // A column that is present but empty is not the same as NULL.
        // No writer produces one, so it is treated as corruption.
        let nullable = |column: &'static str, raw: &Option<String>| {
            raw.as_deref().map(|raw| stored(column, raw)).transpose()
        };

        Ok(SecretMeta {
            name: self.name.clone(),
            created_at: stored("created_at", &self.created_at)?,
            updated_at: stored("updated_at", &self.updated_at)?,
            deleted_at: nullable("deleted_at", &self.deleted_at)?,
            expires_at: nullable("expires_at", &self.expires_at)?,
            env_name: self.env_name.clone(),
        })
    }
}

/// Reads a stored timestamp. `subject` names the row, so a failure
/// says which one held the bad value.
fn parse_stored(
    raw: &str,
    column: &'static str,
    subject: impl FnOnce() -> String,
) -> Result<Time, Error> {
    Time::parse_rfc3339(raw).ok_or_else(|| Error::StoredTimeCorrupt {
        subject: subject(),
        column,
        raw: raw.to_owned(),
    })
}

/// Finds the secret row called `name`, if there is one.
fn find_secret(connection: &Connection, name: &str) -> Result<Option<SecretRow>, Error> {
    connection
        .query_row(
            "SELECT id, name, env_name, created_at, updated_at, deleted_at, expires_at
               FROM secret WHERE name = ?1",
            [name],
            |row| {
                Ok(SecretRow {
                    id: row.get(0)?,
                    name: text(row, 1)?,
                    env_name: optional_text(row, 2)?,
                    created_at: text(row, 3)?,
                    updated_at: text(row, 4)?,
                    deleted_at: optional_text(row, 5)?,
                    expires_at: optional_text(row, 6)?,
                })
            },
        )
        .optional()
        .map_err(database(format!("look up secret {name}")))
}

/// The rows a rekey must re-encrypt: row id, secret name, and version
/// number of every version that still has an envelope.
fn live_versions(connection: &Connection) -> Result<Vec<(i64, String, i64)>, Error> {
    let collecting = || database("collect live versions".to_owned());

    let mut statement = connection
        .prepare(
            "SELECT sv.id, s.name, sv.version_number
               FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
              WHERE sv.state != ?1 AND sv.envelope IS NOT NULL
              ORDER BY s.name, sv.version_number",
        )
        .map_err(collecting())?;

    let rows = statement
        .query_map([State::Destroyed.as_str()], |row| {
            Ok((row.get(0)?, text(row, 1)?, row.get(2)?))
        })
        .map_err(collecting())?;

    rows.collect::<Result<_, _>>()
        .map_err(database("scan live version".to_owned()))
}

/// Wraps a database error in what was being done.
fn database(context: String) -> impl FnOnce(rusqlite::Error) -> Error {
    move |source| Error::Database { context, source }
}

/// Every live secret with its newest version number. The filters and
/// the grouping are appended to it.
const SUMMARY_QUERY: &str =
    "SELECT s.id, s.name, s.env_name, s.created_at, s.updated_at, s.deleted_at, s.expires_at,
            COALESCE(MAX(sv.version_number), 0)
       FROM secret s LEFT JOIN secret_version sv ON sv.secret_id = s.id
      WHERE s.deleted_at IS NULL";

/// Matches a name that is the prefix or lives under it as a whole
/// segment, so `projects/app` never selects its sibling
/// `projects/app-legacy`. The comparison is exact and case-sensitive.
/// LIKE is not used: it treats `_` and `%` in a name as wildcards and
/// folds ASCII case, which would match too much and, through
/// `reveal --prefix`, disclose secrets the caller did not select.
const PREFIX_CLAUSE: &str = " AND (s.name = ?1 OR substr(s.name, 1, length(?1) + 1) = ?1 || '/')";

/// The newest enabled version of every live secret. `?1` is the
/// prefix and `?2` the enabled state.
const ENTRIES_QUERY: &str =
    "SELECT s.name, s.env_name, s.expires_at, sv.version_number, sv.envelope
       FROM secret s JOIN secret_version sv ON sv.secret_id = s.id AND sv.state = ?2
      WHERE s.deleted_at IS NULL
        AND sv.version_number = (
            SELECT MAX(v2.version_number) FROM secret_version v2
             WHERE v2.secret_id = s.id AND v2.state = ?2)";

const SUMMARY_ORDER: &str = " GROUP BY s.id ORDER BY s.name";

impl Vault {
    /// The live secrets whose name equals `prefix` or sits under it as
    /// a whole segment. An empty prefix lists everything. A trailing
    /// slash is dropped, so `db/` and `db` select the same set.
    pub fn list(&self, prefix: &str) -> Result<Vec<Summary>, Error> {
        if prefix.is_empty() {
            return self.summaries(&format!("{SUMMARY_QUERY}{SUMMARY_ORDER}"), None);
        }

        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);

        self.summaries(
            &format!("{SUMMARY_QUERY}{PREFIX_CLAUSE}{SUMMARY_ORDER}"),
            Some(prefix),
        )
    }

    /// The live secrets whose expiry has passed at `now`.
    pub fn stale(&self, now: Time) -> Result<Vec<Summary>, Error> {
        self.summaries(
            &format!(
                "{SUMMARY_QUERY} AND s.expires_at IS NOT NULL AND s.expires_at <= ?1{SUMMARY_ORDER}"
            ),
            Some(&now.to_stored()),
        )
    }

    /// Marks one version disabled. A destroyed version stays destroyed,
    /// and disabling twice changes nothing.
    pub fn disable(&self, name: &str, number: i64) -> Result<(), Error> {
        let row = self.require_secret(name)?;
        let version = || format!("version {number} of {name}");

        let state: Option<State> = self
            .connection
            .query_row(
                "SELECT state FROM secret_version WHERE secret_id = ?1 AND version_number = ?2",
                params![row.id, number],
                |row| row.get(0),
            )
            .optional()
            .map_err(database(format!("look up {}", version())))?;

        match state {
            None => return Err(Error::VersionNotFound { version: version() }),
            Some(State::Destroyed) => return Err(Error::VersionDestroyed { version: version() }),
            Some(State::Enabled | State::Disabled) => {}
        }

        // The guard on the state makes the update check itself. A purge
        // that destroys the row between the read above and this
        // statement cannot be undone: the update changes no row, which
        // is reported as destroyed.
        let changed = self
            .connection
            .execute(
                "UPDATE secret_version SET state = ?1
                  WHERE secret_id = ?2 AND version_number = ?3 AND state != ?4",
                params![
                    State::Disabled.as_str(),
                    row.id,
                    number,
                    State::Destroyed.as_str()
                ],
            )
            .map_err(database(format!("disable {}", version())))?;

        if changed == 0 {
            return Err(Error::VersionDestroyed { version: version() });
        }

        Ok(())
    }

    /// Marks the secret deleted. Its versions and envelopes stay intact
    /// until a purge.
    pub fn soft_delete(&self, name: &str) -> Result<(), Error> {
        let row = self.require_secret(name)?;
        let deleted = || Error::SecretDeleted {
            name: name.to_owned(),
        };

        if row.deleted_at.is_some() {
            return Err(deleted());
        }

        let now = Time::now().to_stored();

        // The guard on deleted_at makes the update check itself, as in
        // disable. A second delete or a purge that lands between the
        // read above and this statement changes no row, so the first
        // tombstone keeps its timestamp.
        let changed = self
            .connection
            .execute(
                "UPDATE secret SET deleted_at = ?1, updated_at = ?1
                  WHERE id = ?2 AND deleted_at IS NULL",
                params![now, row.id],
            )
            .map_err(database(format!("delete secret {name}")))?;

        if changed == 0 {
            return Err(deleted());
        }

        Ok(())
    }

    /// Erases every envelope of the secret and marks all its versions
    /// destroyed, in one transaction. Rows and history remain. It
    /// returns how many versions it destroyed.
    pub fn purge(&mut self, name: &str) -> Result<i64, Error> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database("begin purge transaction".to_owned()))?;

        let row = find_secret(&transaction, name)?.ok_or_else(|| Error::SecretNotFound {
            name: name.to_owned(),
        })?;

        let destroyed = transaction
            .execute(
                "UPDATE secret_version SET state = ?1, envelope = NULL
                  WHERE secret_id = ?2 AND state != ?1",
                params![State::Destroyed.as_str(), row.id],
            )
            .map_err(database(format!("destroy envelopes of {name}")))?;

        let now = Time::now().to_stored();

        transaction
            .execute(
                "UPDATE secret SET deleted_at = COALESCE(deleted_at, ?1), updated_at = ?1
                  WHERE id = ?2",
                params![now, row.id],
            )
            .map_err(database(format!("mark {name} deleted")))?;

        transaction
            .commit()
            .map_err(database(format!("commit purge of {name}")))?;

        // Flush the write-ahead log, so the erased envelope bytes do
        // not linger in its frames. secure_delete zeroed the freed
        // pages, and this truncates the log that still holds what they
        // held before. The purge is already committed, so a failure
        // here must not report it as failed. The next checkpoint
        // reclaims the frames.
        let _ = self.checkpoint();

        Ok(i64::try_from(destroyed).unwrap_or(i64::MAX))
    }

    /// Flushes and truncates the write-ahead log, so content freed by a
    /// destructive operation cannot be recovered from its frames.
    ///
    /// A reader in another process can block the truncate. SQLite
    /// reports that in the result row with no error, so the row is
    /// read, and a blocked checkpoint comes back as
    /// [`Error::CheckpointBlocked`].
    pub fn checkpoint(&self) -> Result<(), Error> {
        let busy: i64 = self
            .connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(database("checkpoint wal".to_owned()))?;

        if busy != 0 {
            return Err(Error::CheckpointBlocked);
        }

        Ok(())
    }

    fn require_secret(&self, name: &str) -> Result<SecretRow, Error> {
        find_secret(&self.connection, name)?.ok_or_else(|| Error::SecretNotFound {
            name: name.to_owned(),
        })
    }

    fn summaries(&self, query: &str, argument: Option<&str>) -> Result<Vec<Summary>, Error> {
        let listing = || database("list secrets".to_owned());
        let mut statement = self.connection.prepare(query).map_err(listing())?;

        let mut rows = match argument {
            Some(argument) => statement.query([argument]),
            None => statement.query([]),
        }
        .map_err(listing())?;

        let mut summaries = Vec::new();

        while let Some(row) = rows.next().map_err(listing())? {
            let scanned = (|| {
                Ok((
                    SecretRow {
                        id: row.get(0)?,
                        name: text(row, 1)?,
                        env_name: optional_text(row, 2)?,
                        created_at: text(row, 3)?,
                        updated_at: text(row, 4)?,
                        deleted_at: optional_text(row, 5)?,
                        expires_at: optional_text(row, 6)?,
                    },
                    row.get(7)?,
                ))
            })();

            let (secret, latest_version) =
                scanned.map_err(database("scan secret list".to_owned()))?;

            summaries.push(Summary {
                secret: secret.meta()?,
                latest_version,
            });
        }

        Ok(summaries)
    }

    /// The newest enabled version of `name` with its envelope. A
    /// deleted secret does not resolve.
    pub fn newest_enabled(&self, name: &str) -> Result<Resolved, Error> {
        let row = find_secret(&self.connection, name)?.ok_or_else(|| Error::SecretNotFound {
            name: name.to_owned(),
        })?;

        if row.deleted_at.is_some() {
            return Err(Error::SecretDeleted {
                name: name.to_owned(),
            });
        }

        let secret = row.meta()?;

        let newest: Option<(i64, String, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT version_number, created_at, envelope FROM secret_version
                  WHERE secret_id = ?1 AND state = ?2 ORDER BY version_number DESC LIMIT 1",
                params![row.id, State::Enabled.as_str()],
                |row| Ok((row.get(0)?, text(row, 1)?, row.get(2)?)),
            )
            .optional()
            .map_err(database(format!("newest version of {name}")))?;

        let (number, created_at, envelope) = newest.ok_or_else(|| Error::VersionNotFound {
            version: format!("secret {name} has no enabled version"),
        })?;

        Ok(Resolved {
            secret,
            version: VersionMeta {
                number,
                state: State::Enabled,
                created_at: parse_stored(&created_at, "secret_version.created_at", || {
                    format!("secret {}", quote(name))
                })?,
            },
            envelope: envelope.unwrap_or_default(),
        })
    }

    /// Re-encrypts every version that still has an envelope through
    /// `reseal`, and stores `new_recipient`, all inside one
    /// transaction. The recipient is stored last. A failure before the
    /// commit rolls the whole vault back. The commit itself can report
    /// an error after its record became durable, and that case is
    /// [`Error::CommitAmbiguous`].
    ///
    /// It returns how many versions were re-encrypted.
    pub fn rekey(
        &mut self,
        new_recipient: &str,
        mut reseal: impl FnMut(&str, i64, &[u8]) -> Result<Vec<u8>, ResealFailure>,
    ) -> Result<i64, Error> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database("begin rekey transaction".to_owned()))?;

        let live = live_versions(&transaction)?;

        {
            // The fetch is prepared once. An envelope is read just
            // before it is re-encrypted, so the ciphertext of the
            // whole vault is never in memory at once.
            let mut fetch = transaction
                .prepare("SELECT envelope FROM secret_version WHERE id = ?1")
                .map_err(database("prepare envelope fetch".to_owned()))?;

            for (id, name, number) in &live {
                let version = format!("{} version {number}", shown_name(name));

                let envelope: Vec<u8> = fetch
                    .query_row([id], |row| row.get(0))
                    .map_err(database(format!("read {version}")))?;

                let resealed =
                    reseal(name, *number, &envelope).map_err(|failure| Error::Reseal {
                        version: version.clone(),
                        reason: failure.message,
                        advice: failure.advice,
                    })?;

                transaction
                    .execute(
                        "UPDATE secret_version SET envelope = ?1 WHERE id = ?2",
                        params![resealed, id],
                    )
                    .map_err(database(format!("store resealed {version}")))?;
            }
        }

        transaction
            .execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = ?2",
                params![new_recipient, META_RECIPIENT],
            )
            .map_err(database("store new recipient".to_owned()))?;

        transaction
            .commit()
            .map_err(|source| Error::CommitAmbiguous {
                context: "commit rekey",
                source,
            })?;

        // Flush the log so envelopes sealed to the old recipient do
        // not survive in it. A failure here is dropped on purpose. The
        // rekey is committed, and the caller treats any error from
        // this method as "the vault is unchanged" and discards the new
        // identity. Reporting one would destroy the only key that
        // reads the vault. A frame left for the next checkpoint is the
        // lesser harm.
        let _ = self.checkpoint();

        Ok(i64::try_from(live.len()).unwrap_or(i64::MAX))
    }

    /// The newest enabled version of every live secret `filter`
    /// selects, ordered by name.
    pub fn entries(&self, filter: EntryFilter<'_>) -> Result<Vec<Entry>, Error> {
        let mut query = ENTRIES_QUERY.to_owned();

        if filter.env_named {
            query.push_str(" AND s.env_name IS NOT NULL");
        }

        if !filter.prefix.is_empty() {
            query.push_str(PREFIX_CLAUSE);
        }

        query.push_str(" ORDER BY s.name");

        // A trailing slash is dropped, so `db/` and `db` select the
        // same set. A bare slash is left naming nothing.
        let prefix = filter.prefix.strip_suffix('/').unwrap_or(filter.prefix);

        let listing = || database("batch entries".to_owned());
        let mut statement = self.connection.prepare(&query).map_err(listing())?;

        let mut rows = statement
            .query(params![prefix, State::Enabled.as_str()])
            .map_err(listing())?;

        let mut entries = Vec::new();

        while let Some(row) = rows.next().map_err(listing())? {
            type Scanned = (String, Option<String>, Option<String>, i64, Option<Vec<u8>>);

            let scanned: Result<Scanned, rusqlite::Error> = (|| {
                Ok((
                    text(row, 0)?,
                    optional_text(row, 1)?,
                    optional_text(row, 2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })();

            let (name, env_name, expires_at, version, envelope) =
                scanned.map_err(database("scan batch entry".to_owned()))?;

            let expires_at = expires_at
                .map(|raw| parse_stored(&raw, "expires_at", || format!("secret {}", quote(&name))))
                .transpose()?;

            entries.push(Entry {
                name,
                env_name,
                version,
                expires_at,
                envelope: envelope.unwrap_or_default(),
            });
        }

        Ok(entries)
    }

    /// The secret row and all its versions, soft-deleted secrets and
    /// destroyed versions included. It never touches an envelope.
    pub fn meta(&self, name: &str) -> Result<(SecretMeta, Vec<VersionMeta>), Error> {
        let row = find_secret(&self.connection, name)?.ok_or_else(|| Error::SecretNotFound {
            name: name.to_owned(),
        })?;

        let secret = row.meta()?;
        let listing = || database(format!("versions of {name}"));

        let mut statement = self
            .connection
            .prepare(
                "SELECT version_number, state, created_at FROM secret_version
                  WHERE secret_id = ?1 ORDER BY version_number",
            )
            .map_err(listing())?;

        let mut rows = statement.query([row.id]).map_err(listing())?;
        let mut versions = Vec::new();

        while let Some(row) = rows.next().map_err(listing())? {
            let scanning = || database(format!("scan version of {name}"));

            let number: i64 = row.get(0).map_err(scanning())?;
            let state: State = row.get(1).map_err(scanning())?;
            let created_at = text(row, 2).map_err(scanning())?;

            versions.push(VersionMeta {
                number,
                state,
                created_at: parse_stored(&created_at, "secret_version.created_at", || {
                    format!("secret {} version {number}", quote(name))
                })?,
            });
        }

        Ok((secret, versions))
    }

    /// Stores a new sealed version of `name` inside one transaction. It
    /// creates the secret row on first use and revives a secret that
    /// was soft-deleted. `seal` is given the canonical address of the
    /// new version, so the envelope binds to its row.
    ///
    /// The vault never sees plaintext, so sealing is the caller's.
    pub fn append_version(
        &mut self,
        name: &str,
        options: &SetOptions,
        seal: impl FnOnce(SealRequest<'_>) -> Result<Vec<u8>, String>,
    ) -> Result<AppendResult, Error> {
        if !is_valid_name(name) {
            return Err(Error::InvalidName { name: quote(name) });
        }

        // The transaction takes the write lock up front. A deferred one
        // that reads and then writes fails outright when another writer
        // commits in between.
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database("begin set transaction".to_owned()))?;

        let now = Time::now().to_second();
        let secret_id = upsert_secret(&transaction, name, options, now)?;

        // Read the row as the upsert left it, so the seal binds the
        // env name and expiry now in effect into the new envelope.
        let row = find_secret(&transaction, name)?.ok_or_else(|| Error::SecretNotFound {
            name: name.to_owned(),
        })?;

        let number: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(version_number), 0) + 1 FROM secret_version WHERE secret_id = ?1",
                [secret_id],
                |row| row.get(0),
            )
            .map_err(database(format!("next version for {name}")))?;

        // Read the recipient here, inside the writing transaction. The
        // write lock is already held, so no rekey can rotate the
        // recipient between this read and the commit. A recipient read
        // earlier could be one a rekey had just retired, and the new
        // version would be sealed to a key nothing can open.
        let recipient: String = transaction
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                [META_RECIPIENT],
                |row| text(row, 0),
            )
            .map_err(database(format!("vault_meta[{META_RECIPIENT}]")))?;

        let envelope = seal(SealRequest {
            recipient: &recipient,
            address: &canonical_address(name, number),
            env_name: row.env_name.as_deref(),
            expires_at: row.expires_at.as_deref(),
        })
        .map_err(|reason| Error::Seal {
            name: name.to_owned(),
            reason,
        })?;

        transaction
            .execute(
                "INSERT INTO secret_version (secret_id, version_number, state, envelope, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    secret_id,
                    number,
                    State::Enabled.as_str(),
                    envelope,
                    now.to_stored()
                ],
            )
            .map_err(database(format!("insert version {number} of {name}")))?;

        let revoked = if options.revoke_previous {
            let disabled = transaction
                .execute(
                    "UPDATE secret_version SET state = ?1
                      WHERE secret_id = ?2 AND state = ?3 AND version_number < ?4",
                    params![
                        State::Disabled.as_str(),
                        secret_id,
                        State::Enabled.as_str(),
                        number
                    ],
                )
                .map_err(database(format!(
                    "revoke previous versions of {name}: disable older versions"
                )))?;

            i64::try_from(disabled).unwrap_or(i64::MAX)
        } else {
            0
        };

        let secret = row.meta()?;

        transaction
            .commit()
            .map_err(database(format!("commit set of {name}")))?;

        Ok(AppendResult {
            secret,
            version: VersionMeta {
                number,
                state: State::Enabled,
                created_at: now,
            },
            revoked,
        })
    }
}

/// Creates the secret row, or updates the one already there. A set
/// revives a soft-deleted secret and applies only the attributes that
/// were passed.
fn upsert_secret(
    transaction: &Transaction<'_>,
    name: &str,
    options: &SetOptions,
    now: Time,
) -> Result<i64, Error> {
    let now = now.to_stored();

    let Some(row) = find_secret(transaction, name)? else {
        // An empty env name asks to clear one, and a new secret has
        // none to clear.
        let env_name = match &options.env_name {
            Change::Set(env_name) => Some(env_name.as_str()),
            Change::Keep | Change::Clear => None,
        };

        let expires_at = match &options.expires_at {
            Change::Set(expires_at) => Some(expires_at.to_stored()),
            Change::Keep | Change::Clear => None,
        };

        transaction
            .execute(
                "INSERT INTO secret (name, env_name, created_at, updated_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![name, env_name, now, now, expires_at],
            )
            .map_err(database(format!("insert secret {name}")))?;

        return Ok(transaction.last_insert_rowid());
    };

    let env_name = match &options.env_name {
        Change::Keep => row.env_name,
        Change::Clear => None,
        Change::Set(env_name) => Some(env_name.clone()),
    };

    let expires_at = match &options.expires_at {
        Change::Keep => row.expires_at,
        Change::Clear => None,
        Change::Set(expires_at) => Some(expires_at.to_stored()),
    };

    transaction
        .execute(
            "UPDATE secret SET env_name = ?1, expires_at = ?2, deleted_at = NULL, updated_at = ?3
              WHERE id = ?4",
            params![env_name, expires_at, now, row.id],
        )
        .map_err(database(format!("update secret {name}")))?;

    Ok(row.id)
}
