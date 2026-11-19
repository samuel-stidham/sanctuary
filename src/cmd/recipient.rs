//! Reading the recipient a vault stores.
//!
//! The recipient is the one value a write verb needs, and it comes
//! from a file anyone with write access can edit. It is accepted only
//! in the exact form this program and the Go original write.

use age::x25519::Recipient;

use crate::quote::quote;

/// Parses a stored recipient, refusing anything but its canonical
/// text.
///
/// The age crate reads bech32 in either case, so an upper-case copy of
/// a recipient would parse here and be refused by the Go original. A
/// vault both programs open must be accepted or refused by both, so the
/// text has to match what the parsed key prints.
pub fn parse_stored(stored: &str) -> Result<Recipient, String> {
    let malformed = |reason: &str| {
        format!(
            "stored recipient does not parse: malformed recipient {}: {reason}",
            quote(stored)
        )
    };

    let recipient: Recipient = stored.parse().map_err(|reason: &str| malformed(reason))?;

    if recipient.to_string() != stored {
        let kind = stored.rsplit_once('1').map_or(stored, |(kind, _)| kind);

        return Err(malformed(&format!("invalid type {}", quote(kind))));
    }

    Ok(recipient)
}

#[cfg(test)]
mod tests {
    use super::parse_stored;

    #[test]
    fn only_the_canonical_text_is_accepted() {
        let recipient = age::x25519::Identity::generate().to_public().to_string();

        assert_eq!(
            parse_stored(&recipient).expect("canonical").to_string(),
            recipient
        );

        let upper = recipient.to_uppercase();

        assert_eq!(
            parse_stored(&upper).expect_err("upper case"),
            format!(
                "stored recipient does not parse: malformed recipient \"{upper}\": invalid type \
                 \"AGE\""
            )
        );

        for edited in [
            String::new(),
            "not-a-recipient".to_owned(),
            "age1qqqq".to_owned(),
            format!("{recipient} "),
            format!("A{}", &recipient[1..]),
            "AGE-SECRET-KEY-1FAKE".to_owned(),
        ] {
            let refused = parse_stored(&edited).expect_err("an edited recipient");

            assert!(
                refused.starts_with(&format!(
                    "stored recipient does not parse: malformed recipient {}: ",
                    crate::quote::quote(&edited)
                )),
                "{refused}"
            );
        }
    }
}
