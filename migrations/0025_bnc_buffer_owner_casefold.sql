-- `bnc_buffer.owner` is now the RFC1459-casefolded account name, matching the
-- registry key and every ownership check elsewhere. Rows written before this
-- carry the account's display casing, so fold them rather than leaving that
-- backlog orphaned under a spelling nothing looks up any more.
--
-- The mapping is RFC1459's: ASCII case plus []\~ -> {}|^. Account names are
-- ASCII by construction (registered from a validated nick, or filtered to
-- [A-Za-z0-9-_] when provisioned from OIDC), so `lower` is unambiguous here.
-- The shared/server-level owner `*` is untouched by both.
UPDATE bnc_buffer
   SET owner = translate(lower(owner), '[]\~', '{}|^')
 WHERE owner <> translate(lower(owner), '[]\~', '{}|^');
