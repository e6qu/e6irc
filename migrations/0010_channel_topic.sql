-- Retain a registered channel's topic across empty→recreate cycles
-- (DESIGN §7.6, §8). Null when the channel has no topic set.
ALTER TABLE channels
    ADD COLUMN topic        TEXT,
    ADD COLUMN topic_setter TEXT,
    ADD COLUMN topic_set_at TIMESTAMPTZ;
