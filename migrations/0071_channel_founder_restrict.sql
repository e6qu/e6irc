-- A registered channel named its founder with ON DELETE CASCADE, so deleting
-- an account silently deleted every channel it founded. Account deletion
-- refuses a founder, but that refusal is a count taken by the application: a
-- founder transfer committing between the count and the DELETE let the cascade
-- drop a channel nobody asked to drop. A channel is the network's, not data
-- about its founder, so no account deletion may remove one: the reference now
-- restricts, and a deletion that would orphan a channel fails in PostgreSQL
-- whatever the application counted.
--
-- The other references to `accounts` keep their cascade. Each of them
-- (credentials, OpenID Connect identities, browser sessions, access tokens,
-- read markers, BNC networks and their markers, device grants, channel-access
-- entries) is data about the deleted account itself, which permanent deletion
-- exists to remove; `account_invitations.accepted_account_id` sets NULL.
ALTER TABLE channels
    DROP CONSTRAINT channels_founder_account_id_fkey,
    ADD CONSTRAINT channels_founder_account_id_fkey
        FOREIGN KEY (founder_account_id) REFERENCES accounts (id) ON DELETE RESTRICT;
