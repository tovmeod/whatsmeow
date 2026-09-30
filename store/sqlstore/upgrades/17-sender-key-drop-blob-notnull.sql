-- v17 (compatible with v8+): sender-key dual-READ only — allow NULL legacy blob on column-only (fmt_ver=2) rows

-- Phase 17.9 ships dual-READ (read columns for fmt_ver=2, fall back to the legacy
-- JSON blob for fmt_ver=1/NULL) WITHOUT dual-write: a column-only write no longer
-- rewrites sender_key. A brand-new fmt_ver=2 row therefore has no blob, so the
-- NOT NULL constraint must be dropped. Existing legacy rows keep their blob.
ALTER TABLE whatsmeow_sender_keys
    ALTER COLUMN sender_key DROP NOT NULL;
