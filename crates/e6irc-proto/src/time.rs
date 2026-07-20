//! Epoch → ISO 8601 UTC formatting for the IRCv3 `server-time` tag
//! (format `YYYY-MM-DDThh:mm:ss.sssZ`, always UTC).
//!
//! Implemented in-repo (days-from-civil inversion per Howard Hinnant's
//! chrono-compatible algorithms, public domain) — a date crate is not
//! warranted for one fixed output format.

/// Format milliseconds since the Unix epoch as `server-time` requires.
pub fn server_time(epoch_millis: u64) -> String {
    let (secs, millis) = (epoch_millis / 1000, epoch_millis % 1000);
    let days = secs / 86_400;
    let (hh, mm, ss) = {
        let s = secs % 86_400;
        (s / 3600, (s % 3600) / 60, s % 60)
    };
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Days since 1970-01-01 → (year, month, day) in the proleptic
/// Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse a `server-time`-format timestamp back to epoch seconds
/// (milliseconds are truncated). `None` on any format violation.
pub fn parse_server_time_seconds(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    // The `server-time` format has a 4-digit year. Bounding it here is not
    // cosmetic: it keeps the returned seconds small enough that callers'
    // `secs * 1000` (millis) cannot overflow u64 — an unbounded year let a
    // client trigger that overflow (panic in debug, marker corruption in
    // release) via MARKREAD.
    if date_parts.next().is_some()
        || !(0..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let time = time.split_once('.').map_or(time, |(t, _)| t);
    let mut time_parts = time.split(':');
    let hh: u64 = time_parts.next()?.parse().ok()?;
    let mm: u64 = time_parts.next()?.parse().ok()?;
    let ss: u64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days.checked_mul(86_400)? + (hh * 3600 + mm * 60 + ss) as i64;
    u64::try_from(secs).ok()
}

/// Inverse of `civil_from_days` (same Hinnant algorithm family).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_timestamps() {
        assert_eq!(server_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(server_time(1_000_000_000_000), "2001-09-09T01:46:40.000Z");
        // leap year day
        assert_eq!(server_time(1_582_934_400_000), "2020-02-29T00:00:00.000Z");
        // end of year rollover with millis
        assert_eq!(server_time(1_704_067_199_999), "2023-12-31T23:59:59.999Z");
        assert_eq!(server_time(1_704_067_200_000), "2024-01-01T00:00:00.000Z");
        // a recent moment (2026-07-18T12:00:00Z)
        assert_eq!(server_time(1_784_376_000_000), "2026-07-18T12:00:00.000Z");
    }

    #[test]
    fn parse_round_trips() {
        for ms in [
            0u64,
            1_000_000_000_000,
            1_582_934_400_000,
            1_784_376_000_000,
        ] {
            let text = server_time(ms);
            assert_eq!(parse_server_time_seconds(&text), Some(ms / 1000), "{text}");
        }
        assert_eq!(
            parse_server_time_seconds("2026-07-18T12:00:00Z"),
            Some(1_784_376_000)
        );
        for bad in [
            "",
            "not-a-time",
            "2026-13-01T00:00:00Z",
            "2026-07-18T25:00:00Z",
            "2026-07-18 12:00:00Z",
        ] {
            assert_eq!(parse_server_time_seconds(bad), None, "{bad}");
        }
    }
    #[test]
    fn rejects_out_of_range_year_to_prevent_millis_overflow() {
        // A giant year previously returned a huge `secs` whose `* 1000`
        // overflowed u64 downstream (MARKREAD). It is now rejected.
        assert_eq!(parse_server_time_seconds("585000000-01-01T00:00:00Z"), None);
        assert_eq!(parse_server_time_seconds("-5-01-01T00:00:00Z"), None);
        // The largest valid year still parses and its millis fit in u64.
        let secs = parse_server_time_seconds("9999-12-31T23:59:59Z").expect("valid");
        assert!(secs.checked_mul(1000).is_some());
        // A normal timestamp still round-trips.
        let secs = parse_server_time_seconds("2021-01-02T03:04:05.678Z").expect("valid");
        assert_eq!(server_time(secs * 1000), "2021-01-02T03:04:05.000Z");
    }
}
