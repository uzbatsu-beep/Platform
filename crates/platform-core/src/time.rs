//! Exact lossless conversion between SDK `UtcMillis` (Unix milliseconds) and
//! SQLite ISO-8601 UTC `TEXT` (`YYYY-MM-DDTHH:MM:SS.sssZ`), using Howard Hinnant's civil calendar algorithm.

use platform_sdk::UtcMillis;

const MILLIS_PER_DAY: u64 = 86_400_000;
const MILLIS_PER_HOUR: u64 = 3_600_000;
const MILLIS_PER_MINUTE: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimestampError {
    #[error("invalid ISO-8601 UTC timestamp format: {0}")]
    InvalidFormat(String),
    #[error("timestamp date/time component out of valid range: {0}")]
    OutOfRange(String),
    #[error("timestamps before 1970-01-01T00:00:00.000Z cannot be represented as UtcMillis: {0}")]
    BeforeUnixEpoch(String),
}

/// Converts `UtcMillis` to canonical ISO-8601 UTC string `YYYY-MM-DDTHH:MM:SS.sssZ`.
#[must_use]
pub fn utc_millis_to_iso8601(ts: UtcMillis) -> String {
    let total_ms = ts.as_unix_millis();
    let days = (total_ms / MILLIS_PER_DAY) as i64;
    let rem_ms = total_ms % MILLIS_PER_DAY;

    let hour = rem_ms / MILLIS_PER_HOUR;
    let rem_ms = rem_ms % MILLIS_PER_HOUR;
    let minute = rem_ms / MILLIS_PER_MINUTE;
    let rem_ms = rem_ms % MILLIS_PER_MINUTE;
    let second = rem_ms / 1_000;
    let millis = rem_ms % 1_000;

    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Parses canonical ISO-8601 UTC strings (`YYYY-MM-DDTHH:MM:SS.sssZ`, `YYYY-MM-DDTHH:MM:SSZ`,
/// or `+00:00` suffix) into exact `UtcMillis`.
pub fn iso8601_to_utc_millis(raw: &str) -> Result<UtcMillis, TimestampError> {
    let trimmed = raw.trim();
    let core = trimmed
        .strip_suffix('Z')
        .or_else(|| trimmed.strip_suffix("+00:00"))
        .or_else(|| trimmed.strip_suffix("-00:00"))
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;

    let (date_part, time_part) = core
        .split_once('T')
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;

    let mut d_iter = date_part.split('-');
    let year: i64 = d_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    let month: u32 = d_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    let day: u32 = d_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    if d_iter.next().is_some() {
        return Err(TimestampError::InvalidFormat(raw.to_string()));
    }

    if !(1..=12).contains(&month) {
        return Err(TimestampError::OutOfRange(raw.to_string()));
    }
    let max_day = days_in_month(year, month);
    if !(1..=max_day).contains(&day) {
        return Err(TimestampError::OutOfRange(raw.to_string()));
    }

    let (hms_part, frac_part) = match time_part.split_once('.') {
        Some((hms, frac)) => (hms, Some(frac)),
        None => (time_part, None),
    };

    let mut t_iter = hms_part.split(':');
    let hour: u64 = t_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    let minute: u64 = t_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    let second: u64 = t_iter
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| TimestampError::InvalidFormat(raw.to_string()))?;
    if t_iter.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return Err(TimestampError::OutOfRange(raw.to_string()));
    }

    let millis: u64 = match frac_part {
        None => 0,
        Some(frac) if !frac.is_empty() && frac.chars().all(|c| c.is_ascii_digit()) => {
            let mut normalized = frac.to_string();
            while normalized.len() < 3 {
                normalized.push('0');
            }
            normalized[..3]
                .parse::<u64>()
                .map_err(|_| TimestampError::InvalidFormat(raw.to_string()))?
        }
        Some(_) => return Err(TimestampError::InvalidFormat(raw.to_string())),
    };

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Err(TimestampError::BeforeUnixEpoch(raw.to_string()));
    }

    let total_ms = (days as u64)
        .checked_mul(MILLIS_PER_DAY)
        .and_then(|v| v.checked_add(hour * MILLIS_PER_HOUR))
        .and_then(|v| v.checked_add(minute * MILLIS_PER_MINUTE))
        .and_then(|v| v.checked_add(second * 1_000))
        .and_then(|v| v.checked_add(millis))
        .ok_or_else(|| TimestampError::OutOfRange(raw.to_string()))?;

    Ok(UtcMillis::from_unix_millis(total_ms))
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    (year, m as u32, d as u32)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m_u64 = u64::from(m);
    let doy = (153 * (if m_u64 > 2 { m_u64 - 3 } else { m_u64 + 9 }) + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_millisecond_precision_and_utc_normalization() -> Result<(), TimestampError> {
        let samples = [
            (0_u64, "1970-01-01T00:00:00.000Z"),
            (951_782_400_123_u64, "2000-02-29T00:00:00.123Z"),
            (1_709_251_199_999_u64, "2024-02-29T23:59:59.999Z"),
            (1_795_180_800_456_u64, "2026-11-20T13:20:00.456Z"),
        ];
        for (ms, expected) in samples {
            let ts = UtcMillis::from_unix_millis(ms);
            let iso = utc_millis_to_iso8601(ts);
            assert_eq!(iso, expected);
            let parsed = iso8601_to_utc_millis(&iso)?;
            assert_eq!(parsed, ts);
        }

        // Accepts +00:00 UTC offset and rejects non-UTC offsets
        assert_eq!(
            iso8601_to_utc_millis("2026-11-20T13:20:00.456+00:00")?,
            UtcMillis::from_unix_millis(1_795_180_800_456)
        );
        assert!(iso8601_to_utc_millis("2026-11-20T13:20:00+03:00").is_err());
        assert!(iso8601_to_utc_millis("2025-02-29T00:00:00.000Z").is_err());
        Ok(())
    }
}
