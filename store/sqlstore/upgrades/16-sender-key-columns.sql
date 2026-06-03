-- v16 (compatible with v8+): sender-key columnar storage (dual-read; legacy blob kept)

ALTER TABLE whatsmeow_sender_keys
    ADD COLUMN IF NOT EXISTS fmt_ver                  SMALLINT,
    ADD COLUMN IF NOT EXISTS st_key_id               BIGINT[],
    ADD COLUMN IF NOT EXISTS st_chain_key_iteration  BIGINT[],
    ADD COLUMN IF NOT EXISTS st_chain_key            BYTEA[],
    ADD COLUMN IF NOT EXISTS st_signing_key_public   BYTEA[],
    ADD COLUMN IF NOT EXISTS st_signing_key_private  BYTEA[],
    ADD COLUMN IF NOT EXISTS smk_state_idx           INT[],
    ADD COLUMN IF NOT EXISTS smk_iteration           BIGINT[],
    ADD COLUMN IF NOT EXISTS smk_iv                  BYTEA[],
    ADD COLUMN IF NOT EXISTS smk_cipher_key          BYTEA[],
    ADD COLUMN IF NOT EXISTS smk_seed                BYTEA[];
