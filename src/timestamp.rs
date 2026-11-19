//! Instants as the vault stores them and as result output prints them.
//!
//! The vault keeps every timestamp as RFC 3339 text in UTC, to the
//! second. Both binaries read and write those columns, so parsing and
//! formatting here follow the Go original exactly: what it accepts,
//! this accepts, and what it prints, this prints.

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: i64 = 86_400;

/// An instant, with the UTC offset it was written with. The offset
/// only affects how the instant prints. Two instants compare by when
/// they are, never by how they were written.
#[derive(Debug, Clone, Copy)]
pub struct Time {
    /// Seconds since the Unix epoch.
    seconds: i64,
    nanos: u32,
    /// Seconds east of UTC.
    offset: i32,
}

impl Time {
    /// The current instant, carrying the local UTC offset.
    ///
    /// The offset comes from the C library, which reads one zone file
    /// and only as much of it as its header declares. A `TZ` or `TZDIR`
    /// set by a hostile caller therefore costs nothing: a zone that
    /// cannot be read prints as UTC. A zone library that loads the
    /// named file whole, or walks the zone directory, would let either
    /// variable stall every run that writes a log record.
    pub fn now_local() -> Self {
        let mut now = Self::now();

        // `time_t` is 64 bits wide on every platform this builds for.
        let seconds: nix::libc::time_t = now.seconds;

        // SAFETY: an all-zero `tm` is a valid value of the struct.
        let mut broken_down: nix::libc::tm = unsafe { std::mem::zeroed() };

        // SAFETY: both pointers refer to live values of the right
        // types, and localtime_r writes only to the second. It reads
        // the environment, which this program never changes.
        let converted = unsafe { nix::libc::localtime_r(&raw const seconds, &raw mut broken_down) };

        if !converted.is_null() {
            now.offset = i32::try_from(broken_down.tm_gmtoff).unwrap_or(0);
        }

        now
    }

    /// The current instant in UTC.
    pub fn now() -> Self {
        let (seconds, nanos) = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => (
                i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
                since.subsec_nanos(),
            ),
            // A clock set before the epoch is cut to the second.
            Err(before) => (
                -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
                0,
            ),
        };

        Self {
            seconds,
            nanos,
            offset: 0,
        }
    }

    /// The same instant with its fraction of a second dropped, which is
    /// the precision the vault stores.
    pub fn to_second(self) -> Self {
        Self { nanos: 0, ..self }
    }

    /// Parses an RFC 3339 timestamp: `2006-01-02T15:04:05Z`, with an
    /// optional fraction of a second and either `Z` or a `+07:00`
    /// offset.
    ///
    /// It is as lenient as the Go original and no more. That parser
    /// takes a one-digit hour, a comma before the fraction, an offset
    /// hour of 24, and an offset minute of 60, so this does too.
    pub fn parse_rfc3339(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();

        if bytes.len() < "2006-01-02T".len() {
            return None;
        }

        let year = number(&bytes[0..4], 0, 9999)?;
        let month = number(&bytes[5..7], 1, 12)?;
        let day = number(&bytes[8..10], 1, days_in(month, year))?;

        if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
            return None;
        }

        let clock = &bytes[11..];
        let hour_digits = clock
            .iter()
            .take(2)
            .take_while(|byte| byte.is_ascii_digit())
            .count();

        let (hour, clock) = clock.split_at(hour_digits);
        let hour = number(hour, 0, 23).filter(|_| hour_digits > 0)?;

        let [b':', m1, m2, b':', s1, s2, rest @ ..] = clock else {
            return None;
        };

        let minute = number(&[*m1, *m2], 0, 59)?;
        let second = number(&[*s1, *s2], 0, 59)?;

        let mut rest = rest;
        let mut nanos = 0;

        if rest.len() >= 2 && matches!(rest[0], b'.' | b',') && rest[1].is_ascii_digit() {
            let digits = rest[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();

            nanos = fraction(&rest[1..=digits]);
            rest = &rest[1 + digits..];
        }

        let offset = match rest {
            b"Z" => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
                let hours = number(&[*h1, *h2], 0, 24)?;
                let minutes = number(&[*m1, *m2], 0, 60)?;
                let seconds = i32::try_from((hours * 60 + minutes) * 60).ok()?;

                if *sign == b'-' { -seconds } else { seconds }
            }
            _ => return None,
        };

        let local = days_from_civil(year, month, day) * SECONDS_PER_DAY
            + hour * 3600
            + minute * 60
            + second;

        Some(Self {
            seconds: local - i64::from(offset),
            nanos,
            offset,
        })
    }

    /// Parses a bare `2006-01-02` date as midnight UTC of that day.
    pub fn parse_date(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();

        if bytes.len() != "2006-01-02".len() || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }

        let year = number(&bytes[0..4], 0, 9999)?;
        let month = number(&bytes[5..7], 1, 12)?;
        let day = number(&bytes[8..10], 1, days_in(month, year))?;

        Some(Self {
            seconds: days_from_civil(year, month, day) * SECONDS_PER_DAY,
            nanos: 0,
            offset: 0,
        })
    }

    /// The same instant, written in UTC.
    pub fn to_utc(self) -> Self {
        Self { offset: 0, ..self }
    }

    /// The text a vault column holds: UTC, to the second.
    pub fn to_stored(self) -> String {
        self.to_utc().render(false)
    }

    /// The text result output and log records carry: the offset the
    /// instant was written with, and its fraction when it has one.
    pub fn to_output(self) -> String {
        self.render(true)
    }

    fn render(self, with_fraction: bool) -> String {
        let local = self.seconds + i64::from(self.offset);
        let (year, month, day) = civil_from_days(local.div_euclid(SECONDS_PER_DAY));
        let clock = local.rem_euclid(SECONDS_PER_DAY);

        // A year before zero keeps four digits after its sign, as the
        // Go original prints it: `-0001`.
        let sign = if year < 0 { "-" } else { "" };
        let year = year.abs();

        let mut text = format!(
            "{sign}{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            clock / 3600,
            clock / 60 % 60,
            clock % 60
        );

        if with_fraction && self.nanos != 0 {
            let digits = format!("{:09}", self.nanos);

            text.push('.');
            text.push_str(digits.trim_end_matches('0'));
        }

        if self.offset == 0 {
            text.push('Z');
        } else {
            let minutes = self.offset.abs() / 60;
            let sign = if self.offset < 0 { '-' } else { '+' };

            text.push_str(&format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60));
        }

        text
    }
}

impl PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Time {}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.seconds, self.nanos).cmp(&(other.seconds, other.nanos))
    }
}

/// Reads `digits` as a decimal number within `min..=max`.
fn number(digits: &[u8], min: i64, max: i64) -> Option<i64> {
    let mut value = 0_i64;

    for digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }

        value = value * 10 + i64::from(digit - b'0');
    }

    (min..=max).contains(&value).then_some(value)
}

/// Reads the digits after the decimal point as nanoseconds. Digits
/// past the ninth are dropped.
fn fraction(digits: &[u8]) -> u32 {
    let mut nanos = 0_u32;

    for index in 0..9 {
        let digit = digits.get(index).map_or(0, |byte| byte - b'0');

        nanos = nanos * 10 + u32::from(digit);
    }

    nanos
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from the Unix epoch to a date in the proleptic Gregorian
/// calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

/// The date a count of days from the Unix epoch falls on.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::Time;

    #[test]
    fn rfc3339_round_trips_through_the_stored_form() {
        let cases = [
            ("2026-01-02T15:04:05Z", "2026-01-02T15:04:05Z"),
            ("2026-01-02T15:04:05+00:00", "2026-01-02T15:04:05Z"),
            ("2026-01-02T15:04:05+07:00", "2026-01-02T08:04:05Z"),
            ("2026-01-02T00:30:00-05:30", "2026-01-02T06:00:00Z"),
            ("2026-01-01T00:00:00+01:00", "2025-12-31T23:00:00Z"),
            ("2024-02-29T23:59:59Z", "2024-02-29T23:59:59Z"),
            ("2026-01-02T15:04:05.999Z", "2026-01-02T15:04:05Z"),
            ("2026-01-02T15:04:05,5Z", "2026-01-02T15:04:05Z"),
            ("2026-01-02T5:04:05Z", "2026-01-02T05:04:05Z"),
            ("2026-01-02T15:04:05+24:00", "2026-01-01T15:04:05Z"),
            ("2026-01-02T15:04:05+07:60", "2026-01-02T07:04:05Z"),
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
            ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
            ("1969-12-31T23:59:59Z", "1969-12-31T23:59:59Z"),
            ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
            ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z"),
        ];

        for (text, want) in cases {
            let parsed = Time::parse_rfc3339(text).unwrap_or_else(|| panic!("{text} must parse"));

            assert_eq!(parsed.to_stored(), want, "{text}");
        }
    }

    #[test]
    fn rfc3339_refuses_what_the_reference_refuses() {
        for text in [
            "",
            "2026-01-02",
            "2026-01-02T15:04:05",
            "2026-01-02 15:04:05Z",
            "2026-01-02t15:04:05Z",
            "2026-01-02T15:04:05z",
            "2026-01-02T15:04Z",
            "2026-13-02T15:04:05Z",
            "2026-02-30T15:04:05Z",
            "2025-02-29T15:04:05Z",
            "2026-01-02T24:00:00Z",
            "2026-01-02T15:60:00Z",
            "2026-01-02T15:04:60Z",
            "2026-01-02T15:04:05.Z",
            "2026-01-02T15:04:05+0700",
            "2026-01-02T15:04:05+25:00",
            "2026-01-02T15:04:05+07:99",
            "2026-01-02T:04:05Z",
            "2026-01-02T015:04:05Z",
            "2026-01-02T15:04:05Z ",
            " 2026-01-02T15:04:05Z",
            "2026-01-02T15:04:05ZZ",
            "next tuesday",
        ] {
            assert!(
                Time::parse_rfc3339(text).is_none(),
                "{text:?} must not parse"
            );
        }
    }

    #[test]
    fn a_bare_date_is_midnight_utc() {
        let parsed = Time::parse_date("2026-12-25").expect("a date");

        assert_eq!(parsed.to_stored(), "2026-12-25T00:00:00Z");

        for text in [
            "2026-1-2",
            "2026-02-30",
            "2026/01/02",
            "2026-01-02T",
            "26-01-02",
            "2026-12-25 ",
        ] {
            assert!(Time::parse_date(text).is_none(), "{text:?} must not parse");
        }
    }

    #[test]
    fn a_year_before_zero_keeps_four_digits() {
        // Year zero at one hour east is the last hour of the year
        // before it in UTC.
        let early = Time::parse_rfc3339("0000-01-01T00:00:00+01:00").expect("parse");

        assert_eq!(early.to_stored(), "-0001-12-31T23:00:00Z");
        assert_eq!(early.to_output(), "0000-01-01T00:00:00+01:00");
    }

    #[test]
    fn output_keeps_the_offset_and_the_fraction() {
        let cases = [
            ("2026-01-02T15:04:05Z", "2026-01-02T15:04:05Z"),
            ("2026-01-02T15:04:05+07:00", "2026-01-02T15:04:05+07:00"),
            ("2026-01-02T15:04:05-05:30", "2026-01-02T15:04:05-05:30"),
            ("2026-01-02T15:04:05+07:60", "2026-01-02T15:04:05+08:00"),
            ("2026-01-02T15:04:05,5Z", "2026-01-02T15:04:05.5Z"),
            ("2026-01-02T15:04:05.500Z", "2026-01-02T15:04:05.5Z"),
            (
                "2026-01-02T15:04:05.000000001Z",
                "2026-01-02T15:04:05.000000001Z",
            ),
            (
                "2026-01-02T15:04:05.1234567899Z",
                "2026-01-02T15:04:05.123456789Z",
            ),
        ];

        for (text, want) in cases {
            let parsed = Time::parse_rfc3339(text).unwrap_or_else(|| panic!("{text} must parse"));

            assert_eq!(parsed.to_output(), want, "{text}");
        }
    }

    #[test]
    fn instants_compare_by_when_they_are() {
        let utc = Time::parse_rfc3339("2026-01-02T08:04:05Z").expect("utc");
        let offset = Time::parse_rfc3339("2026-01-02T15:04:05+07:00").expect("offset");
        let later = Time::parse_rfc3339("2026-01-02T08:04:05.5Z").expect("later");

        assert_eq!(utc, offset);
        assert!(utc < later);
        assert!(Time::now() > utc);
    }

    #[test]
    fn now_is_cut_to_the_second_in_utc() {
        let now = Time::now().to_second().to_output();

        assert_eq!(now.len(), "2026-01-02T15:04:05Z".len(), "{now}");
        assert!(now.ends_with('Z'), "{now}");
        assert_eq!(
            Time::parse_rfc3339(&now).expect("round trip").to_stored(),
            now
        );
    }
}
