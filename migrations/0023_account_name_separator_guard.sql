-- Direct-message conversations are keyed by their participants' identities
-- joined with `!` (DESIGN §11.1.1). That key is only unambiguous while `!`
-- cannot occur in an identity: an account named `a!b` could otherwise collide
-- with the conversation between `a` and `b` and read it.
--
-- Both paths that create accounts already exclude it — NickServ registers a
-- validated nick, and OIDC provisioning filters to [A-Za-z0-9-_] — but that is
-- an invariant held by callers, which the next caller can forget. Enforce it
-- where the name is actually stored, so the bug class cannot come back.
ALTER TABLE accounts
    ADD CONSTRAINT accounts_name_has_no_conversation_separator
    CHECK (position('!' in name) = 0 AND position('!' in name_folded) = 0);
