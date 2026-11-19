//! The SQL schema.
//!
//! Name visibility: `secret.name` is a plaintext column, so list,
//! stale, and prefix queries stay cheap. Moving names inside the
//! encryption boundary would change the on-disk format, so it can only
//! arrive with a major release of both versions.
//!
//! The text is the Go original's, byte for byte. SQLite stores each
//! statement as written, so a vault made by either binary carries the
//! same schema text.

const SCHEMA_V1: &str = "
CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE secret (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    env_name   TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    expires_at TEXT
) STRICT;

CREATE TABLE secret_version (
    id             INTEGER PRIMARY KEY,
    secret_id      INTEGER NOT NULL REFERENCES secret (id),
    version_number INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'destroyed')),
    envelope       BLOB,
    created_at     TEXT NOT NULL,
    UNIQUE (secret_id, version_number)
) STRICT;

CREATE INDEX secret_version_lookup
    ON secret_version (secret_id, state, version_number);
";

/// The SQL migrations, applied in order when a vault is created.
/// Format version 2 changed the envelope frame, not the SQL schema, so
/// it added no migration here.
pub const MIGRATIONS: [&str; 1] = [SCHEMA_V1];
