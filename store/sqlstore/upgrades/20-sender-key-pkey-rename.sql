-- v20 (compatible with v8+): rename whatsmeow_sender_keys_new_pkey to whatsmeow_sender_keys_pkey
--
-- After the plan 06 rename-swap (whatsmeow_sender_keys_new -> whatsmeow_sender_keys), the
-- primary-key constraint inherited the _new suffix. This upgrade renames it to the canonical
-- name. ALTER INDEX IF EXISTS is idempotent -- safe to re-run if the rename already happened.

ALTER INDEX IF EXISTS whatsmeow_sender_keys_new_pkey RENAME TO whatsmeow_sender_keys_pkey;
