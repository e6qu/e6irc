-- CHATHISTORY replay must reconstruct a draft/multiline message as the single
-- message it was — one msgid, its lines and their per-line concat flags — not
-- one row per line with fresh, never-delivered msgids. Store the encoded lines
-- (see `core::handler::message::encode_multiline`) alongside the message; NULL
-- for an ordinary single-line message. Existing rows are NULL (they predate the
-- column and were never multiline), so replay treats them as plain messages.
ALTER TABLE messages ADD COLUMN multiline TEXT;
