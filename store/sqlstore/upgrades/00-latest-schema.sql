-- v0 -> v20 (compatible with v8+): Latest schema
CREATE TABLE IF NOT EXISTS whatsmeow_device (
	jid TEXT PRIMARY KEY,
	lid TEXT,

	facebook_uuid uuid,

	registration_id BIGINT NOT NULL CHECK ( registration_id >= 0 AND registration_id < 4294967296 ),

	noise_key    bytea NOT NULL CHECK ( length(noise_key) = 32 ),
	identity_key bytea NOT NULL CHECK ( length(identity_key) = 32 ),

	signed_pre_key     bytea   NOT NULL CHECK ( length(signed_pre_key) = 32 ),
	signed_pre_key_id  INTEGER NOT NULL CHECK ( signed_pre_key_id >= 0 AND signed_pre_key_id < 16777216 ),
	signed_pre_key_sig bytea   NOT NULL CHECK ( length(signed_pre_key_sig) = 64 ),

	adv_key             bytea NOT NULL,
	adv_details         bytea NOT NULL,
	adv_account_sig     bytea NOT NULL CHECK ( length(adv_account_sig) = 64 ),
	adv_account_sig_key bytea NOT NULL CHECK ( length(adv_account_sig_key) = 32 ),
	adv_device_sig      bytea NOT NULL CHECK ( length(adv_device_sig) = 64 ),

	platform      TEXT NOT NULL DEFAULT '',
	business_name TEXT NOT NULL DEFAULT '',
	push_name     TEXT NOT NULL DEFAULT '',

	lid_migration_ts BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS whatsmeow_identity_keys (
	our_jid  TEXT,
	their_id TEXT,
	identity bytea NOT NULL CHECK ( length(identity) = 32 ),

	PRIMARY KEY (our_jid, their_id),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_pre_keys (
	jid      TEXT,
	key_id   INTEGER          CHECK ( key_id >= 0 AND key_id < 16777216 ),
	key      bytea   NOT NULL CHECK ( length(key) = 32 ),
	uploaded BOOLEAN NOT NULL,

	PRIMARY KEY (jid, key_id),
	FOREIGN KEY (jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_sessions (
	our_jid  TEXT,
	their_id TEXT,
	session  bytea,

	PRIMARY KEY (our_jid, their_id),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

-- whatsmeow_sender_keys: end-state schema at v20.
-- v18: primary key replaced with a UNIQUE INDEX using text_pattern_ops on sender_id
--      (turns LIKE sender_id prefix scans into index range seeks; enforces same uniqueness).
-- v19: sk_keyid0 STORED GENERATED column (KeyID of state[0] from PackFlat bytes [1..4]);
--      sender_key is NOT NULL (all rows carry flat blobs post-migration).
-- v20: index is named whatsmeow_sender_keys_pkey (canonical name, no _new suffix).
-- Columnar columns from v16 are not present: a fresh bootstrap never needed them
-- (they were an intermediate dual-read phase; v19 drops them on the upgrade path).
CREATE TABLE IF NOT EXISTS whatsmeow_sender_keys (
	our_jid    TEXT NOT NULL,
	chat_id    TEXT NOT NULL,
	sender_id  TEXT NOT NULL,
	sender_key bytea NOT NULL,

	sk_keyid0 INT4 GENERATED ALWAYS AS (
		(get_byte(sender_key, 1)::int4 << 24) |
		(get_byte(sender_key, 2)::int4 << 16) |
		(get_byte(sender_key, 3)::int4 << 8) |
		get_byte(sender_key, 4)::int4
	) STORED,

	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Unique index with text_pattern_ops on sender_id (v18 end-state).
-- text_pattern_ops enables LIKE prefix seeks (sender_id LIKE bare||':%') on the PK index,
-- avoiding collation-bound full-group scans. ON CONFLICT column-inference still resolves it.
-- Named whatsmeow_sender_keys_pkey (v20 canonical name) — no _new suffix on a fresh bootstrap.
CREATE UNIQUE INDEX IF NOT EXISTS whatsmeow_sender_keys_pkey
    ON whatsmeow_sender_keys (our_jid, chat_id, sender_id text_pattern_ops);

-- Composite index serving recoveryScanQueryFast: (chat_id, sk_keyid0).
-- Leading on chat_id (highest selectivity: one group), then sk_keyid0 (equality),
-- letting PG seek directly to (group, keyID) before applying the sender_id LIKE filter.
CREATE INDEX IF NOT EXISTS whatsmeow_sender_keys_chat_keyid0_idx
    ON whatsmeow_sender_keys(chat_id, sk_keyid0);

CREATE TABLE IF NOT EXISTS whatsmeow_app_state_sync_keys (
	jid         TEXT,
	key_id      bytea,
	key_data    bytea  NOT NULL,
	timestamp   BIGINT NOT NULL,
	fingerprint bytea  NOT NULL,

	PRIMARY KEY (jid, key_id),
	FOREIGN KEY (jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_app_state_version (
	jid     TEXT,
	name    TEXT,
	version BIGINT NOT NULL,
	hash    bytea  NOT NULL CHECK ( length(hash) = 128 ),

	PRIMARY KEY (jid, name),
	FOREIGN KEY (jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_app_state_mutation_macs (
	jid       TEXT,
	name      TEXT,
	version   BIGINT,
	index_mac bytea          CHECK ( length(index_mac) = 32 ),
	value_mac bytea NOT NULL CHECK ( length(value_mac) = 32 ),

	PRIMARY KEY (jid, name, version, index_mac),
	FOREIGN KEY (jid, name) REFERENCES whatsmeow_app_state_version(jid, name) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_contacts (
	our_jid        TEXT,
	their_jid      TEXT,
	first_name     TEXT,
	full_name      TEXT,
	push_name      TEXT,
	business_name  TEXT,
	redacted_phone TEXT,

	PRIMARY KEY (our_jid, their_jid),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_chat_settings (
	our_jid       TEXT,
	chat_jid      TEXT,
	muted_until   BIGINT  NOT NULL DEFAULT 0,
	pinned        BOOLEAN NOT NULL DEFAULT false,
	archived      BOOLEAN NOT NULL DEFAULT false,

	PRIMARY KEY (our_jid, chat_jid),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_message_secrets (
	our_jid    TEXT,
	chat_jid   TEXT,
	sender_jid TEXT,
	message_id TEXT,
	key        bytea NOT NULL,

	PRIMARY KEY (our_jid, chat_jid, sender_jid, message_id),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_privacy_tokens (
	our_jid          TEXT,
	their_jid        TEXT,
	token            bytea  NOT NULL,
	timestamp        BIGINT NOT NULL,
	sender_timestamp BIGINT,
	PRIMARY KEY (our_jid, their_jid)
);

CREATE INDEX IF NOT EXISTS idx_whatsmeow_privacy_tokens_our_jid_timestamp
ON whatsmeow_privacy_tokens (our_jid, timestamp);

CREATE TABLE IF NOT EXISTS whatsmeow_nct_salt (
	our_jid TEXT PRIMARY KEY,
	salt    bytea NOT NULL,
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_lid_map (
	lid TEXT PRIMARY KEY,
	pn  TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS whatsmeow_event_buffer (
	our_jid          TEXT   NOT NULL,
	ciphertext_hash  bytea  NOT NULL CHECK ( length(ciphertext_hash) = 32 ),
	plaintext        bytea,
	server_timestamp BIGINT NOT NULL,
	insert_timestamp BIGINT NOT NULL,
	PRIMARY KEY (our_jid, ciphertext_hash),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS whatsmeow_retry_buffer (
	our_jid    TEXT   NOT NULL,
	chat_jid   TEXT   NOT NULL,
	message_id TEXT   NOT NULL,
	format     TEXT   NOT NULL,
	plaintext  bytea  NOT NULL,
	timestamp  BIGINT NOT NULL,

	PRIMARY KEY (our_jid, chat_jid, message_id),
	FOREIGN KEY (our_jid) REFERENCES whatsmeow_device(jid) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS whatsmeow_retry_buffer_timestamp_idx ON whatsmeow_retry_buffer (our_jid, timestamp);
CREATE INDEX IF NOT EXISTS whatsmeow_retry_buffer_msgid_idx ON whatsmeow_retry_buffer (our_jid, message_id);
