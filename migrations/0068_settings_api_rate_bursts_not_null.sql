-- The same fault migration 0067 repaired, two fields over, found by reviewing
-- every persisted field whose type changed: `limits.api_rate_burst` and
-- `limits.administrator_api_rate_burst` were `Option<usize>` until API rate
-- limits were made explicit, and are required now. A settings row written
-- before that release stores them as JSON `null`, which serde refuses, so the
-- daemon would crash-loop exactly as it did on `command_burst`. A stored
-- `null` meant "use the built-in default"; removing the key means the same
-- thing to the required field.
UPDATE server_settings
SET settings = settings #- '{limits,api_rate_burst}'
WHERE jsonb_typeof(settings #> '{limits,api_rate_burst}') = 'null';

UPDATE server_settings
SET settings = settings #- '{limits,administrator_api_rate_burst}'
WHERE jsonb_typeof(settings #> '{limits,administrator_api_rate_burst}') = 'null';
