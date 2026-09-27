//! Epoch → RFC 3339 UTC formatting for the IRCv3 `server-time` tag
//! (format `YYYY-MM-DDThh:mm:ss.sssZ`, always UTC).
//!
//! Implemented in-repo (days-from-civil inversion per Howard Hinnant's
//! chrono-compatible algorithms, public domain) — a date crate is not
//! warranted for one fixed output format.

/// Milliseconds since the Unix epoch.
///
/// A newtype, not a bare `u64`, because epoch time in this codebase exists in
/// two units — milliseconds (the clock, message timestamps, `server-time`) and
/// seconds (the coarse `*_secs` display fields) — and mixing them silently is a
/// bug that has shipped twice: a whole-second clock made same-second messages
/// unpageable by CHATHISTORY, and a `server_time(ts * 1000)` on an
/// already-millisecond value put every REST timestamp a thousandfold into the
/// future for six sweeps. With this type, `server_time(ts * 1000)` does not
/// compile and a seconds value cannot be passed where milliseconds are meant.
/// The `* 1000` / `/ 1000` conversions live behind [`Millis::as_secs`] and the
/// SQL edge, where they are named and greppable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(u64);

impl Millis {
    /// Wrap a raw millisecond count (a clock reading, or a value crossing the
    /// SQL boundary where the column is `bigint` milliseconds).
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// The raw millisecond count, for arithmetic, the `msgid` derivation, and
    /// the SQL boundary.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Truncate to whole seconds since the epoch — the one place the
    /// millisecond→second conversion is allowed, for the coarse `*_secs`
    /// display fields (RPL_CREATIONTIME, RPL_TOPICWHOTIME, WHOIS signon).
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// `self - other`, saturating at zero — a duration in milliseconds (e.g.
    /// idle time = now − last-active), which the caller then reads in whichever
    /// unit it needs.
    pub const fn saturating_sub(self, other: Millis) -> Millis {
        Millis(self.0.saturating_sub(other.0))
    }

    /// Advance by a raw millisecond amount (the flood-bucket refill).
    pub const fn saturating_add_millis(self, ms: u64) -> Millis {
        Millis(self.0.saturating_add(ms))
    }
}

/// Milliseconds from a **monotonic** source, for timer decisions only.
///
/// A distinct type from [`Millis`] for the same reason `Millis` is distinct
/// from a bare `u64`: wall-clock time and monotonic time must not be mixed. A
/// deadline decision — the ping/registration reaper, the flood-bucket refill —
/// stamped against the wall clock breaks whenever the wall clock steps: an NTP
/// correction or a virtual-machine resume that jumps the clock forward mass-reaps every live
/// connection at once (every registration "times out", every idle client is
/// pinged in the same tick), and a backward step freezes the reaper entirely
/// (nothing ever times out) until the clock climbs back. A monotonic clock
/// never steps, so a timer keyed on `MonoMillis` cannot exhibit either.
/// Because the type differs, a `MonoMillis` deadline cannot be compared against
/// a wall-clock [`Millis`] `now` (it does not compile), so the class of
/// "timer decision on wall-clock time" is unrepresentable. Wall-clock `Millis`
/// stays the source for what genuinely needs real time — `server-time`, msgids,
/// signon/last-seen timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MonoMillis(u64);

impl MonoMillis {
    /// Wrap a raw monotonic millisecond count (a monotonic clock reading).
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// The raw millisecond count, for the flood-bucket arithmetic.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Truncate an *elapsed* count to whole seconds (the WHOIS/WHOX idle field).
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }

    /// `self - other`, saturating at zero — an elapsed monotonic duration (idle
    /// time, time since a ping was sent), read by the caller in its own unit.
    pub const fn saturating_sub(self, other: MonoMillis) -> MonoMillis {
        MonoMillis(self.0.saturating_sub(other.0))
    }

    /// Advance by a raw millisecond amount (the flood-bucket refill watermark).
    pub const fn saturating_add_millis(self, ms: u64) -> MonoMillis {
        MonoMillis(self.0.saturating_add(ms))
    }
}

/// Format milliseconds since the Unix epoch as `server-time` requires.
pub fn server_time(at: Millis) -> String {
    let epoch_millis = at.as_millis();
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

/// Number of days in `month` of `year` (proleptic Gregorian leap rules), so a
/// parsed date can be rejected if its day exceeds the real month length.
/// `month` is assumed already range-checked to 1..=12.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Parse one `server-time` numeric field of exactly `width` ASCII digits.
/// Rust's integer `FromStr` accepts a leading `+` and any number of leading
/// zeros, but the grammar is fixed-width plain digits, so without this
/// `2024-+2-+29T+1:+2:+3Z`, `2026-7-18T12:0:0Z` and `02026-07-18T12:00:00Z`
/// would each be another spelling of an instant that has one canonical form.
/// Every field (fraction included) goes through this one gate, so neither the
/// sign nor the width class can reappear on a field a future edit forgets.
fn parse_time_field(s: &str, width: usize) -> Option<u32> {
    if s.len() != width || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse a `server-time` string to epoch **milliseconds**. `None` on any
/// format violation.
///
/// The grammar is exactly `YYYY-MM-DDThh:mm:ss[.f]Z`: every field is
/// fixed-width digits, and the fraction `f` is absent or **one to three**
/// digits running up to the `Z` (`.5` is 500 ms, `.12` is 120 ms). IRCv3
/// `server-time` specifies `.sss`, and the one in-repo producer
/// ([`server_time`]) always emits three digits; one- and two-digit fractions
/// are still accepted because the bouncer ingests `time` tags from third-party
/// upstream servers, and such a fraction still names exactly one millisecond.
/// An empty fraction (`.Z`), a non-digit in it, or a fourth digit (precision
/// [`Millis`] would have to silently truncate) is rejected.
pub fn parse_server_time_millis(text: &str) -> Option<Millis> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = parse_time_field(date_parts.next()?, 4)?;
    let month = parse_time_field(date_parts.next()?, 2)?;
    let day = parse_time_field(date_parts.next()?, 2)?;
    // The four-digit year bounds the result, so the `* 1000` below cannot
    // overflow u64. The day is checked against the real length of the month
    // (leap years included), so `2026-02-31` is rejected rather than rolling
    // forward into the next month.
    if date_parts.next().is_some()
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(i64::from(year), month)
    {
        return None;
    }
    let (hms, frac) = match time.split_once('.') {
        Some((hms, frac)) => (hms, Some(frac)),
        None => (time, None),
    };
    let mut time_parts = hms.split(':');
    let hh = parse_time_field(time_parts.next()?, 2)?;
    let mm = parse_time_field(time_parts.next()?, 2)?;
    let ss = parse_time_field(time_parts.next()?, 2)?;
    // No leap seconds: server-time values are server-generated and never carry
    // `:60`, and accepting it would silently roll a client-supplied timestamp
    // into the next minute.
    if time_parts.next().is_some() || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    let millis = match frac {
        None => 0,
        Some(frac) => {
            let width = frac.len();
            if !(1..=3).contains(&width) {
                return None;
            }
            parse_time_field(frac, width)? * 10u32.pow(3 - width as u32)
        }
    };
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days.checked_mul(86_400)? + i64::from(hh * 3600 + mm * 60 + ss);
    let ms = u64::try_from(secs)
        .ok()?
        .checked_mul(1000)?
        .checked_add(u64::from(millis))?;
    Some(Millis::from_millis(ms))
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
        assert_eq!(
            server_time(Millis::from_millis(0)),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            server_time(Millis::from_millis(1_000_000_000_000)),
            "2001-09-09T01:46:40.000Z"
        );
        // leap year day
        assert_eq!(
            server_time(Millis::from_millis(1_582_934_400_000)),
            "2020-02-29T00:00:00.000Z"
        );
        // end of year rollover with millis
        assert_eq!(
            server_time(Millis::from_millis(1_704_067_199_999)),
            "2023-12-31T23:59:59.999Z"
        );
        assert_eq!(
            server_time(Millis::from_millis(1_704_067_200_000)),
            "2024-01-01T00:00:00.000Z"
        );
        // a recent moment (2026-07-18T12:00:00Z)
        assert_eq!(
            server_time(Millis::from_millis(1_784_376_000_000)),
            "2026-07-18T12:00:00.000Z"
        );
    }

    #[test]
    fn parse_round_trips() {
        // Formatting and parsing are exact inverses at millisecond precision,
        // including a non-zero fraction — CHATHISTORY pages on these values,
        // so a lossy round trip would drop or reorder messages.
        for ms in [
            0u64,
            1_000_000_000_000,
            1_582_934_400_000,
            1_784_376_000_000,
            1_704_067_199_999,
        ] {
            let text = server_time(Millis::from_millis(ms));
            assert_eq!(
                parse_server_time_millis(&text),
                Some(Millis::from_millis(ms)),
                "{text}"
            );
        }
        // A fractionless timestamp is accepted and reads as .000.
        assert_eq!(
            parse_server_time_millis("2026-07-18T12:00:00Z"),
            Some(Millis::from_millis(1_784_376_000_000))
        );
        for bad in [
            "",
            "not-a-time",
            "2026-13-01T00:00:00Z",
            "2026-07-18T25:00:00Z",
            "2026-07-18 12:00:00Z",
        ] {
            assert_eq!(parse_server_time_millis(bad), None, "{bad}");
        }
    }

    #[test]
    fn parse_millis_preserves_fraction() {
        // The `.mmm` fraction round-trips at millisecond precision.
        assert_eq!(
            parse_server_time_millis("2019-01-04T14:33:26.123Z"),
            Some(Millis::from_millis(1_546_612_406_123))
        );
        // One or two digits scale to milliseconds.
        assert_eq!(
            parse_server_time_millis("2026-07-18T12:00:00.5Z"),
            Some(Millis::from_millis(1_784_376_000_500))
        );
        assert_eq!(
            parse_server_time_millis("2026-07-18T12:00:00.12Z"),
            Some(Millis::from_millis(1_784_376_000_120))
        );
        // No fraction ⇒ .000.
        assert_eq!(
            parse_server_time_millis("2026-07-18T12:00:00Z"),
            Some(Millis::from_millis(1_784_376_000_000))
        );
        // A full round-trip through the formatter.
        for ms in [0u64, 1_546_612_406_123, 1_784_376_000_500] {
            assert_eq!(
                parse_server_time_millis(&server_time(Millis::from_millis(ms))),
                Some(Millis::from_millis(ms))
            );
        }
    }
    #[test]
    fn rejects_out_of_range_year_to_prevent_millis_overflow() {
        // A giant year previously produced a huge seconds value whose `* 1000`
        // overflowed u64 downstream (MARKREAD). It is now rejected.
        assert_eq!(parse_server_time_millis("585000000-01-01T00:00:00Z"), None);
        assert_eq!(parse_server_time_millis("-5-01-01T00:00:00Z"), None);
        // The largest valid year still parses, in range as millis.
        assert!(parse_server_time_millis("9999-12-31T23:59:59Z").is_some());
        // A normal timestamp still round-trips, fraction preserved.
        let ms = parse_server_time_millis("2021-01-02T03:04:05.678Z").expect("valid");
        assert_eq!(server_time(ms), "2021-01-02T03:04:05.678Z");
    }

    #[test]
    fn rejects_impossible_dates_and_times() {
        // A day past the month's real length must not silently roll forward.
        assert_eq!(parse_server_time_millis("2026-02-31T00:00:00Z"), None);
        assert_eq!(parse_server_time_millis("2026-02-29T00:00:00Z"), None); // not a leap year
        assert_eq!(parse_server_time_millis("2026-04-31T00:00:00Z"), None); // April has 30
        assert_eq!(parse_server_time_millis("2026-01-00T00:00:00Z"), None); // day 0
        // A genuine leap day is accepted.
        assert!(parse_server_time_millis("2024-02-29T00:00:00Z").is_some());
        // No leap seconds.
        assert_eq!(parse_server_time_millis("2026-01-01T00:00:60Z"), None);
        // A signed year is not the 4-digit grammar.
        assert_eq!(parse_server_time_millis("+526-01-01T00:00:00Z"), None);
        // ...and neither is a sign on ANY other field: Rust's integer FromStr
        // accepts a leading '+', so without a strict digit gate on every field
        // these would map to the same instant as the canonical form.
        assert_eq!(parse_server_time_millis("2024-+2-29T01:02:03Z"), None);
        assert_eq!(parse_server_time_millis("2024-02-+9T01:02:03Z"), None);
        assert_eq!(parse_server_time_millis("2024-02-29T+1:02:03Z"), None);
        assert_eq!(parse_server_time_millis("2024-02-29T01:+2:03Z"), None);
        assert_eq!(parse_server_time_millis("2024-02-29T01:02:+3Z"), None);
        // The canonical form still parses.
        assert!(parse_server_time_millis("2024-02-29T01:02:03Z").is_some());
    }

    #[test]
    fn rejects_every_non_canonical_spelling_of_an_instant() {
        // Each of these once parsed to an instant that also has a canonical
        // spelling, or silently dropped trailing bytes of the fraction.
        for bad in [
            // Field widths are fixed.
            "2026-7-18T12:00:00Z",
            "2026-07-8T12:00:00Z",
            "2026-07-18T2:00:00Z",
            "2026-07-18T12:0:00Z",
            "2026-07-18T12:00:0Z",
            "2026-7-18T12:0:0Z",
            "02026-07-18T12:00:00Z",
            "026-07-18T12:00:00Z",
            "2026-007-18T12:00:00Z",
            "2026-07-18T012:00:00Z",
            // The fraction is one to three digits running to the `Z`.
            "2026-07-18T12:00:00.Z",
            "2026-07-18T12:00:00.000garbageZ",
            "2026-07-18T12:00:00.1239Z",
            "2026-07-18T12:00:00.000000Z",
            "2026-07-18T12:00:00.+12Z",
            "2026-07-18T12:00:00.1.2Z",
            "2026-07-18T12:00:00..1Z",
        ] {
            assert_eq!(parse_server_time_millis(bad), None, "{bad}");
        }
        assert_eq!(
            parse_server_time_millis("2026-07-18T12:00:00.000Z"),
            Some(Millis::from_millis(1_784_376_000_000))
        );
    }
}
