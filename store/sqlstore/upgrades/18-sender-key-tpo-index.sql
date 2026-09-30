-- v18 (compatible with v8+): sender-key prefix-LIKE index — text_pattern_ops opclass on sender_id

-- GetSenderKeyDevices (and the recovery scan) filter `sender_id LIKE bare || ':%'`.
-- Under the default-collation PK the LIKE cannot be an index range bound, so the
-- planner seeks (our_jid, chat_id) and then SCANS every sender_id in the group,
-- filtering by LIKE — 2449 rows scanned to return 1 on the biggest prod group;
-- ~42% of all sender-key rows live in groups with >=500 senders. Measured on a
-- full 8.79M-row copy of prod (local test DB): the text_pattern_ops opclass turns
-- the LIKE into a real range seek (sender_id ~>=~ 'bare:' AND ~<~ 'bare;'),
-- cutting the biggest-group lookup from 2449-rows-scanned/36-buffers/0.197ms to a
-- direct seek/5-buffers/0.045ms, and is byte-wise (C-like) so it avoids the
-- en_US.utf8 LIKE-bounds collation trap (Phase 26 silent-0-rows hazard).
--
-- Rather than ADD a second index (+~883MB disk, ~73% slower new-row inserts from
-- maintaining two btrees), we REPLACE the PK's sender_id opclass with
-- text_pattern_ops: same read win, zero extra disk, zero extra write overhead.
-- text_pattern_ops supports both = (exact-match GetSenderKey) and prefix-LIKE, and
-- ON CONFLICT (our_jid, chat_id, sender_id) column-inference still resolves it
-- (verified). PostgreSQL does not allow a formal PRIMARY KEY on a non-default
-- opclass index, so the replacement is a UNIQUE INDEX reusing the pkey name; it
-- enforces the same uniqueness (columns remain NOT NULL). Atomic in one
-- transaction — if a duplicate existed the CREATE would fail and the PK is kept.
ALTER TABLE whatsmeow_sender_keys DROP CONSTRAINT whatsmeow_sender_keys_pkey;
CREATE UNIQUE INDEX whatsmeow_sender_keys_pkey
    ON whatsmeow_sender_keys (our_jid, chat_id, sender_id text_pattern_ops);
