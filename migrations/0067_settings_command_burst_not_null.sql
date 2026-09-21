-- `limits.command_burst` was optional (`Option<usize>`), so a settings row saved
-- before #336 stores it as JSON `null`. It is now always on and required, and
-- serde reads an absent key as the default but refuses `null`: the daemon
-- failed to start on such a row ("invalid persisted server settings: invalid
-- type: null, expected usize"). A stored `null` meant "no burst configured";
-- removing the key gives it the documented default, which is what the setting
-- now means when unstated.
UPDATE server_settings
SET settings = settings #- '{limits,command_burst}'
WHERE jsonb_typeof(settings #> '{limits,command_burst}') = 'null';
