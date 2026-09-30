-- v15 (compatible with v8+): Add (our_jid, message_id) index on the retry buffer so own-account
-- DeviceSentMessage retries -- looked up by message_id alone (ignoring chat_jid) -- seek directly
-- instead of scanning an account's entire 48h buffer on the high-frequency retry miss path.
CREATE INDEX whatsmeow_retry_buffer_msgid_idx ON whatsmeow_retry_buffer (our_jid, message_id);
