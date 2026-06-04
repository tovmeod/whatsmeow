-- v19 (compatible with v8+): drop columnar sender-key columns; restore sender_key NOT NULL;
-- add R8 sk_keyid0 STORED GENERATED column + composite (chat_id, sk_keyid0) index

-- Phase 17.11 plan 05 — post-migration schema cleanup.
-- This upgrade runs ONLY after plan 06's data migration (whatsmeow_sender_keys_new rename
-- to whatsmeow_sender_keys) is complete. The driver that includes this upgrade is NOT
-- deployed until plan 06's migration + rename + verification pass.
--
-- DDL rationale:
--   16-sender-key-columns.sql added fmt_ver + 10 st_*/smk_* columns for the dual-read
--   phase (17.9). With the flat binary migration complete (plan 06), those columns are
--   redundant: all rows now carry a PackFlat bytea in sender_key and carry no columnar
--   state. This upgrade drops them and restores the NOT NULL constraint that 17 dropped
--   (17 dropped NOT NULL to allow column-only fmt_ver=2 rows with no blob; post-migration,
--   every row has a flat blob, so NOT NULL is correct again).
--
-- R8 sk_keyid0 generated column:
--   After migration all sender_key values are PackFlat format. The first byte is nStates
--   (u8), then 4 bytes of state[0].KeyID (big-endian u32, bytes [1..4] = flatHeaderOff=1).
--   sk_keyid0 is a STORED GENERATED INT4 that reads those bytes, giving a stable numeric
--   projection of the most-recent state's KeyID without any independent crypto state (it
--   cannot diverge from sender_key — recomputed on every INSERT/UPDATE).
--
-- CONTEXT decision D2 compliance:
--   sk_keyid0 is NOT a reversal of D2 (eliminate decomposed crypto-STATE columns). D2
--   targets columns like st_chain_key, smk_seed that carry independent mutable state.
--   sk_keyid0 is a pure read-only projection of the first 4 bytes of sender_key; it holds
--   zero independent crypto state and exists solely as an indexable prefilter for the R8
--   donor scan (plan 05's recoveryScanQueryFast). Removing it would require a full Seq
--   Scan on every recovery attempt (CONTEXT decision 6 / RESEARCH R8).
--
-- Composite index (chat_id, sk_keyid0):
--   recoveryScanQueryFast filters chat_id=$1 AND sk_keyid0=$3 AND sender_id LIKE $2||':%'.
--   chat_id is the leading column (highest selectivity: one group) and sk_keyid0 is the
--   second column. This lets PG seek directly to (group, keyID) and apply the LIKE filter
--   on the narrow result. A bare (sk_keyid0) index cannot seek the predicate efficiently
--   (would scan all rows matching keyID across every group). chat_id-leading composes
--   naturally with how rows cluster around the existing PK (our_jid, chat_id, sender_id).

-- DDL block 1: drop columnar columns and fmt_ver added in upgrade 16.
ALTER TABLE whatsmeow_sender_keys
    DROP COLUMN IF EXISTS fmt_ver,
    DROP COLUMN IF EXISTS st_key_id,
    DROP COLUMN IF EXISTS st_chain_key_iteration,
    DROP COLUMN IF EXISTS st_chain_key,
    DROP COLUMN IF EXISTS st_signing_key_public,
    DROP COLUMN IF EXISTS st_signing_key_private,
    DROP COLUMN IF EXISTS smk_state_idx,
    DROP COLUMN IF EXISTS smk_iteration,
    DROP COLUMN IF EXISTS smk_iv,
    DROP COLUMN IF EXISTS smk_cipher_key,
    DROP COLUMN IF EXISTS smk_seed;

-- DDL block 2: restore NOT NULL on sender_key (dropped in upgrade 17 for dual-read).
-- Post-migration every row carries a PackFlat bytea; NULL is no longer valid.
ALTER TABLE whatsmeow_sender_keys
    ALTER COLUMN sender_key SET NOT NULL;

-- DDL block 3: R8 generated column — KeyID of state[0] as an indexable INT4.
-- Expression reads bytes [1..4] of sender_key (flatHeaderOff=1 in PackFlat format).
-- STORED means the value is computed and persisted on INSERT/UPDATE, not on read.
-- ADD COLUMN IF NOT EXISTS is idempotent; safe to re-run after interruption.
ALTER TABLE whatsmeow_sender_keys
    ADD COLUMN IF NOT EXISTS sk_keyid0 INT4
        GENERATED ALWAYS AS (
            (get_byte(sender_key, 1)::int4 << 24) |
            (get_byte(sender_key, 2)::int4 << 16) |
            (get_byte(sender_key, 3)::int4 << 8) |
            get_byte(sender_key, 4)::int4
        ) STORED;

-- DDL block 4: composite index serving recoveryScanQueryFast.
-- Leading on chat_id (equality, highest selectivity), then sk_keyid0 (equality),
-- allowing PG to seek directly to (group, keyID) and filter sender_id LIKE on the
-- narrow result. CREATE INDEX IF NOT EXISTS is idempotent.
CREATE INDEX IF NOT EXISTS whatsmeow_sender_keys_chat_keyid0_idx
    ON whatsmeow_sender_keys(chat_id, sk_keyid0);
