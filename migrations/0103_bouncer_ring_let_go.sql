-- Per-conversation backlog shares (DESIGN §8, §10.1): a network's stored
-- backlog is trimmed in the order it keeps its rows — the newest of every
-- conversation before the second newest of any — so a busy channel's older
-- lines go from the middle of the ring, not only from its front. A resume
-- cursor before such a line has a gap after it, and a continued ring (0102)
-- must refuse it: `let_go_through` is the newest position of the ring's epoch
-- that a trim deleted. A new epoch clears it.
ALTER TABLE bnc_ring_positions
    ADD COLUMN let_go_through BIGINT CHECK (let_go_through > 0);
