-- The operations that mint or redirect lasting authority over an account --
-- an API token, an app password, a device approval, a linked login identity,
-- a first primary password, the recovery email, deleting the account --
-- require that the browser session proved its person recently (DESIGN §9.4,
-- step-up): a stolen session cookie alone must not turn into a credential
-- that outlives the session. A session records when its person last proved
-- themselves: at sign-in, and again at each re-authentication.
ALTER TABLE web_sessions ADD COLUMN authenticated_at TIMESTAMPTZ;

-- A session that exists already proved its person when it was created, and
-- has not since.
UPDATE web_sessions SET authenticated_at = created_at;

ALTER TABLE web_sessions
    ALTER COLUMN authenticated_at SET DEFAULT now(),
    ALTER COLUMN authenticated_at SET NOT NULL;
