//! Quoting for text that reaches an error or a log line.
//!
//! Names and addresses come from the vault file, which an attacker with
//! write access controls. Printed raw, a newline in one becomes its own
//! output line and can pose as a record safetybox wrote. Quoting keeps
//! the whole message on one line.

use std::fmt;

/// Whether `c` renders as itself. Space is the only whitespace that does.
pub(crate) fn is_printable(c: char) -> bool {
    c == ' ' || !(c.is_control() || c.is_whitespace() || is_invisible(c))
}

/// Characters that are neither control nor whitespace and still draw
/// nothing, or redirect how their neighbors draw: format controls such
/// as the zero-width space and the bidirectional overrides, the
/// replacement character, and private-use code points.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{61c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffd}'
            | '\u{e000}'..='\u{f8ff}'
            | '\u{e0000}'..='\u{10ffff}'
    )
}

/// Writes the escape for one character that must not render raw.
pub(crate) fn write_escaped(out: &mut impl fmt::Write, c: char) -> fmt::Result {
    match c {
        '\u{07}' => out.write_str("\\a"),
        '\u{08}' => out.write_str("\\b"),
        '\u{0c}' => out.write_str("\\f"),
        '\n' => out.write_str("\\n"),
        '\r' => out.write_str("\\r"),
        '\t' => out.write_str("\\t"),
        '\u{0b}' => out.write_str("\\v"),
        c if c < ' ' => write!(out, "\\x{:02x}", u32::from(c)),
        c if u32::from(c) < 0x1_0000 => write!(out, "\\u{:04x}", u32::from(c)),
        c => write!(out, "\\U{:08x}", u32::from(c)),
    }
}

/// Renders `text` in double quotes with every quote, backslash, and
/// non-printable character escaped, so it always occupies one line.
pub fn quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);

    quoted.push('"');

    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\x7f' => quoted.push_str("\\x7f"),
            c if is_printable(c) => quoted.push(c),
            c => write_escaped(&mut quoted, c).expect("writing to a String cannot fail"),
        }
    }

    quoted.push('"');

    quoted
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn plain_text_is_only_wrapped() {
        assert_eq!(quote("api/v1/testing/fake/1"), "\"api/v1/testing/fake/1\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("ÜBER 🔐"), "\"ÜBER 🔐\"");
    }

    #[test]
    fn a_newline_never_starts_a_new_line() {
        let quoted = quote("api/v1/spoof\nwarning: fake injected line/1");

        assert_eq!(quoted, "\"api/v1/spoof\\nwarning: fake injected line/1\"");
        assert_eq!(quoted.lines().count(), 1);
    }

    #[test]
    fn quotes_backslashes_and_controls_are_escaped() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("\t\r\x01\x7f"), "\"\\t\\r\\x01\\x7f\"");
        assert_eq!(quote("\u{2028}"), "\"\\u2028\"");
        assert_eq!(quote("a\u{202e}b\u{200b}"), "\"a\\u202eb\\u200b\"");
    }
}
