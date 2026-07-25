-- CHATHISTORY replay must be byte-identical to live delivery, but the stored
-- message carried no bot flag, so a replayed message dropped the `bot` tag a
-- bot's live message carried (for message-tags recipients). Record it so the
-- replay can re-emit it. Existing rows default to non-bot (the honest value —
-- their bot-ness was never captured).
ALTER TABLE messages ADD COLUMN sender_is_bot BOOLEAN NOT NULL DEFAULT false;
