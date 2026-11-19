//! JSON string encoding that matches the reference byte for byte.
//!
//! Result output and JSON log records are a contract with whatever
//! parses them. The two escape differently, as they do in the
//! reference: results also escape the characters that are unsafe to
//! embed in HTML, and log records do not.

use std::fmt::Write as _;

use zeroize::Zeroize;

/// Which characters beyond the JSON minimum are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// For result output: `<`, `>`, and `&` are escaped too.
    Html,
    /// For log records.
    Minimal,
}

/// Appends `text` to `out` as a JSON string literal.
pub fn push_string(out: &mut String, text: &str, escape: Escape) {
    out.push('"');

    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '<' | '>' | '&' if escape == Escape::Html => push_unicode_escape(out, c),
            '\u{2028}' | '\u{2029}' => push_unicode_escape(out, c),
            c if c < ' ' => push_unicode_escape(out, c),
            c => out.push(c),
        }
    }

    out.push('"');
}

fn push_unicode_escape(out: &mut String, c: char) {
    write!(out, "\\u{:04x}", u32::from(c)).expect("writing to a String cannot fail");
}

/// A JSON value for result output. Object members keep the order they
/// are given in, which is part of the output contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Integer(i64),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl From<&str> for Json {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for Json {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<i64> for Json {
    fn from(number: i64) -> Self {
        Self::Integer(number)
    }
}

impl From<bool> for Json {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

/// How result output is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Indented by two spaces, one member per line.
    Pretty,
    /// On one line with no spaces, for pipes.
    Compact,
}

impl Json {
    /// Zeroes every string in the tree. Reveal output carries
    /// plaintext, and this cuts its lifetime to the write.
    pub fn wipe(&mut self) {
        match self {
            Self::Text(text) => text.zeroize(),
            Self::Array(items) => items.iter_mut().for_each(Self::wipe),
            Self::Object(members) => members.iter_mut().for_each(|(_, value)| value.wipe()),
            Self::Null | Self::Bool(_) | Self::Integer(_) => {}
        }
    }

    /// Renders the value with no trailing newline.
    pub fn render(&self, layout: Layout) -> String {
        let mut out = String::new();

        self.write(&mut out, layout, 0);

        out
    }

    fn write(&self, out: &mut String, layout: Layout, depth: usize) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Self::Integer(number) => out.push_str(&number.to_string()),
            Self::Text(text) => push_string(out, text, Escape::Html),
            Self::Array(items) => {
                write_items(out, layout, depth, ('[', ']'), items, |out, item| {
                    item.write(out, layout, depth + 1);
                });
            }
            Self::Object(members) => {
                write_items(
                    out,
                    layout,
                    depth,
                    ('{', '}'),
                    members,
                    |out, (key, value)| {
                        push_string(out, key, Escape::Html);
                        out.push(':');

                        if layout == Layout::Pretty {
                            out.push(' ');
                        }

                        value.write(out, layout, depth + 1);
                    },
                );
            }
        }
    }
}

/// Writes a bracketed, comma-separated run of items. An empty run is
/// the two brackets with nothing between, in either layout.
fn write_items<T>(
    out: &mut String,
    layout: Layout,
    depth: usize,
    (open, close): (char, char),
    items: &[T],
    mut write: impl FnMut(&mut String, &T),
) {
    out.push(open);

    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }

        break_line(out, layout, depth + 1);
        write(out, item);
    }

    if !items.is_empty() {
        break_line(out, layout, depth);
    }

    out.push(close);
}

fn break_line(out: &mut String, layout: Layout, depth: usize) {
    if layout == Layout::Pretty {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    }
}

#[cfg(test)]
mod tests {
    use super::{Escape, push_string};

    fn encode(text: &str, escape: Escape) -> String {
        let mut out = String::new();
        push_string(&mut out, text, escape);

        out
    }

    #[test]
    fn plain_text_is_only_wrapped() {
        assert_eq!(
            encode("secret expired", Escape::Minimal),
            "\"secret expired\""
        );
        assert_eq!(encode("ünïcödé 🔐", Escape::Html), "\"ünïcödé 🔐\"");
    }

    #[test]
    fn quotes_backslashes_and_controls_are_escaped() {
        assert_eq!(
            encode("a\"b\\c\n\t\x01", Escape::Minimal),
            "\"a\\\"b\\\\c\\n\\t\\u0001\""
        );
        assert_eq!(encode("\u{2028}", Escape::Minimal), "\"\\u2028\"");
    }

    #[test]
    fn html_characters_are_escaped_only_in_result_output() {
        assert_eq!(
            encode("<a> & b", Escape::Html),
            "\"\\u003ca\\u003e \\u0026 b\""
        );
        assert_eq!(encode("<a> & b", Escape::Minimal), "\"<a> & b\"");
    }

    #[test]
    fn values_render_in_both_layouts() {
        use super::{Json, Layout};

        let value = Json::Object(vec![
            ("name", "api/one".into()),
            ("version", 1.into()),
            ("expired", false.into()),
            ("tags", Json::Array(vec!["a<b".into(), "c".into()])),
            ("none", Json::Array(vec![])),
            ("empty", Json::Object(vec![])),
            ("inner", Json::Object(vec![("k", "v".into())])),
        ]);

        assert_eq!(
            value.render(Layout::Compact),
            r#"{"name":"api/one","version":1,"expired":false,"tags":["a\u003cb","c"],"none":[],"empty":{},"inner":{"k":"v"}}"#
        );
        assert_eq!(
            value.render(Layout::Pretty),
            r#"{
  "name": "api/one",
  "version": 1,
  "expired": false,
  "tags": [
    "a\u003cb",
    "c"
  ],
  "none": [],
  "empty": {},
  "inner": {
    "k": "v"
  }
}"#
        );
        assert_eq!(Json::Array(vec![]).render(Layout::Pretty), "[]");
    }
}
