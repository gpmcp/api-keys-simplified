use nom::{
    error::{ErrorKind, ParseError},
    Err as NomErr, IResult,
};

const EXPIRY_B64URL_LEN: usize = 11;

#[derive(Debug, Clone, Copy)]
pub struct Parts<'a> {
    pub key: &'a [u8],
    pub expiry_b64: Option<&'a [u8]>, // exactly 11 chars when present
    pub checksum: Option<&'a [u8]>,
}

#[inline]
fn is_b64url_no_pad(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn split_last_dot(i: &[u8]) -> Option<(&[u8], &[u8])> {
    i.iter()
        .rposition(|&b| b == b'.')
        .map(|pos| (&i[..pos], &i[pos + 1..]))
}

/// Parse token into parts: `<key>[.<expiry_11>][.<checksum>]`
///
/// When `has_checksum` is true, last segment is always checksum.
/// When false, last segment (if 11 valid base64url chars) is expiry.
pub fn parse_token(input: &[u8], has_checksum: bool) -> IResult<&[u8], Parts<'_>> {
    if input.is_empty() {
        return Err(NomErr::Error(ParseError::from_error_kind(
            input,
            ErrorKind::Eof,
        )));
    }

    // No dot at all → only key
    let (before_last, tail) = match split_last_dot(input) {
        None => {
            // No dots: just a key
            return Ok((
                &input[input.len()..],
                Parts {
                    key: input,
                    expiry_b64: None,
                    checksum: None,
                },
            ));
        }
        Some(x) => x,
    };

    if has_checksum {
        // Format: key[.expiry].checksum
        // Last segment is always checksum
        if before_last.is_empty() || tail.is_empty() {
            return Err(NomErr::Error(ParseError::from_error_kind(
                input,
                ErrorKind::Eof,
            )));
        }

        // Check if there's an expiry before the checksum
        let (key, expiry) = match split_last_dot(before_last) {
            Some((k, e)) => {
                // Format: key.expiry.checksum
                if k.is_empty() || e.is_empty() {
                    return Err(NomErr::Error(ParseError::from_error_kind(
                        input,
                        ErrorKind::Eof,
                    )));
                }
                // Validate expiry is exactly 11 valid base64url chars
                if e.len() != EXPIRY_B64URL_LEN || !e.iter().all(|&b| is_b64url_no_pad(b)) {
                    return Err(NomErr::Error(ParseError::from_error_kind(
                        input,
                        ErrorKind::Verify,
                    )));
                }
                (k, Some(e))
            }
            None => {
                // Format: key.checksum (no expiry)
                (before_last, None)
            }
        };

        Ok((
            &input[input.len()..],
            Parts {
                key,
                expiry_b64: expiry,
                checksum: Some(tail),
            },
        ))
    } else {
        // Format: key[.expiry]
        // No checksum expected
        if before_last.is_empty() {
            return Err(NomErr::Error(ParseError::from_error_kind(
                input,
                ErrorKind::Eof,
            )));
        }

        // Check if tail is a valid expiry (exactly 11 valid base64url chars)
        let tail_is_expiry =
            tail.len() == EXPIRY_B64URL_LEN && tail.iter().all(|&b| is_b64url_no_pad(b));

        if tail_is_expiry {
            // Format: key.expiry
            Ok((
                &input[input.len()..],
                Parts {
                    key: before_last,
                    expiry_b64: Some(tail),
                    checksum: None,
                },
            ))
        } else {
            // Not a valid expiry, so the whole input is the key (shouldn't have dots)
            // This is an error case - when has_checksum=false and we see a dot,
            // the segment after dot must be a valid expiry
            Err(NomErr::Error(ParseError::from_error_kind(
                input,
                ErrorKind::Verify,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiKey, ApiKeyManagerV0, Environment, Hash, HashConfig, KeyConfig, KeyVersion};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chrono::{DateTime, Utc};
    use secrecy::ExposeSecret;
    fn gen(
        with_version: bool,
        with_checksum: bool,
        with_expiry: bool,
        high_spec: bool,
    ) -> (ApiKey<Hash>, DateTime<Utc>) {
        let mut config = if high_spec {
            KeyConfig::high_security()
        } else {
            KeyConfig::default()
        };
        if with_version {
            config = config.with_version(KeyVersion::V1);
        }
        if !with_checksum {
            config = config.disable_checksum();
        }
        let hash_config = if high_spec {
            HashConfig::high_security()
        } else {
            HashConfig::default()
        };

        let generator = ApiKeyManagerV0::init("text", config, hash_config).unwrap();
        let ts = Utc::now();
        let key = if with_expiry {
            generator
                .generate_with_expiry(Environment::test(), ts.clone())
                .unwrap()
        } else {
            generator.generate(Environment::test()).unwrap()
        };

        (key, ts)
    }
    #[test]
    fn simple_test_parse_token() {
        let (key, ts) = gen(true, true, true, false);
        let token = key.key().expose_secret();
        let parts = parse_token(token.as_bytes(), true).unwrap().1;
        let exp = parts.expiry_b64.unwrap();
        let exp_be_by = URL_SAFE_NO_PAD.decode(exp).unwrap();
        assert_eq!(
            ts.timestamp(),
            i64::from_be_bytes(exp_be_by.try_into().unwrap())
        );
    }

    // Edge case tests
    #[test]
    fn test_empty_input() {
        let result = parse_token(b"", true);
        assert!(result.is_err(), "Empty input should fail");
    }

    #[test]
    fn test_single_dot_only() {
        let result = parse_token(b".", true);
        assert!(
            result.is_err(),
            "Single dot should fail (empty key and tail)"
        );
    }

    #[test]
    fn test_double_dot_only() {
        let result = parse_token(b"..", true);
        assert!(result.is_err(), "Double dot should fail (empty segments)");
    }

    #[test]
    fn test_triple_dot_only() {
        let result = parse_token(b"...", true);
        assert!(result.is_err(), "Triple dot should fail (empty segments)");
    }

    #[test]
    fn test_key_with_leading_dot() {
        let result = parse_token(b".mykey", true);
        // This will be parsed as empty key with "mykey" as tail
        // Should fail due to empty key
        assert!(result.is_err(), "Leading dot creates empty key segment");
    }

    #[test]
    fn test_key_with_trailing_dot() {
        let result = parse_token(b"mykey.", true);
        // This will be parsed as "mykey" with empty tail
        // Should fail due to empty checksum
        assert!(result.is_err(), "Trailing dot creates empty tail segment");
    }

    #[test]
    fn test_key_with_both_leading_and_trailing_dot() {
        let result = parse_token(b".mykey.", true);
        assert!(result.is_err(), "Dots on both sides should fail");
    }

    #[test]
    fn test_consecutive_dots() {
        let result = parse_token(b"key..checksum", true);
        // split_last_dot will find the last dot, before_last will be "key."
        // Then split again and get empty expiry
        assert!(result.is_err(), "Consecutive dots create empty segments");
    }

    #[test]
    fn test_expiry_with_invalid_base64url_chars_equals() {
        // 11 chars but contains '=' which is not valid base64url (no padding)
        let result = parse_token(b"mykey.12345678901=", true);
        // Should not be treated as expiry, will try to parse as checksum
        // This might succeed as key.checksum format
        match result {
            Ok((_, parts)) => {
                assert_eq!(parts.key, b"mykey");
                assert_eq!(parts.expiry_b64, None);
                assert_eq!(parts.checksum, Some(b"12345678901=" as &[u8]));
            }
            Err(_) => panic!("Should parse as key.checksum even with invalid chars"),
        }
    }

    #[test]
    fn test_expiry_with_invalid_base64url_chars_plus() {
        // 11 chars but contains '+' (standard base64, not base64url)
        let result = parse_token(b"mykey.1234567890+", true);
        match result {
            Ok((_, parts)) => {
                assert_eq!(parts.key, b"mykey");
                assert_eq!(parts.expiry_b64, None);
                assert_eq!(parts.checksum, Some(b"1234567890+" as &[u8]));
            }
            Err(_) => panic!("Should parse as key.checksum"),
        }
    }

    #[test]
    fn test_expiry_with_invalid_base64url_chars_slash() {
        // 11 chars but contains '/' (standard base64, not base64url)
        let result = parse_token(b"mykey.1234567890/", true);
        match result {
            Ok((_, parts)) => {
                assert_eq!(parts.key, b"mykey");
                assert_eq!(parts.expiry_b64, None);
                assert_eq!(parts.checksum, Some(b"1234567890/" as &[u8]));
            }
            Err(_) => panic!("Should parse as key.checksum"),
        }
    }

    #[test]
    fn test_expiry_with_special_chars() {
        // 11 chars with special characters
        let result = parse_token(b"mykey.12345!@#$%^", true);
        match result {
            Ok((_, parts)) => {
                assert_eq!(parts.key, b"mykey");
                assert_eq!(parts.expiry_b64, None);
                assert_eq!(parts.checksum, Some(b"12345!@#$%^" as &[u8]));
            }
            Err(_) => panic!("Should parse as key.checksum"),
        }
    }

    #[test]
    fn test_valid_11_char_expiry_no_checksum() {
        // Exactly 11 valid base64url chars - should be treated as expiry
        let result = parse_token(b"mykey.ABCDEFGHIJK", false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
        assert_eq!(parts.checksum, None);
    }

    #[test]
    fn test_valid_11_char_base64url_as_checksum() {
        // BUG FIX: key.expiry.checksum where checksum happens to be 11 valid base64url chars
        // With has_checksum=true, last segment is ALWAYS checksum, so this now parses correctly
        let result = parse_token(b"mykey.ABCDEFGHIJK.01234567890", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
        assert_eq!(parts.checksum, Some(b"01234567890" as &[u8]));
    }

    #[test]
    fn test_expiry_10_chars() {
        // 10 chars (one less than required 11) - should be treated as checksum
        let result = parse_token(b"mykey.ABCDEFGHIJ", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, None);
        assert_eq!(parts.checksum, Some(b"ABCDEFGHIJ" as &[u8]));
    }

    #[test]
    fn test_expiry_12_chars() {
        // 12 chars (one more than required 11) - should be treated as checksum
        let result = parse_token(b"mykey.ABCDEFGHIJKL", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, None);
        assert_eq!(parts.checksum, Some(b"ABCDEFGHIJKL" as &[u8]));
    }

    #[test]
    fn test_three_segments_with_invalid_expiry_length() {
        // key.something.checksum where "something" is not 11 chars
        let result = parse_token(b"mykey.short.checksum", true);
        // Last dot: "mykey.short" and "checksum"
        // "checksum" is 8 chars, not 11, so not expiry
        // Split "mykey.short" -> "mykey" and "short"
        // "short" is 5 chars, not 11, so error
        assert!(
            result.is_err(),
            "Middle segment must be exactly 11 chars for expiry"
        );
    }

    #[test]
    fn test_three_segments_with_invalid_expiry_chars() {
        // key.expiry.checksum where expiry is 11 chars but has invalid chars
        let result = parse_token(b"mykey.12345=78901.checksum", true);
        // Last dot: "mykey.12345=78901" and "checksum"
        // "checksum" is not 11 chars, so not expiry, so it's checksum
        // Split "mykey.12345=78901" -> "mykey" and "12345=78901"
        // "12345=78901" is 11 chars but contains '=', so error
        assert!(result.is_err(), "Expiry must be valid base64url chars");
    }

    #[test]
    fn test_valid_three_segment_token() {
        // BUG FIX: key.expiry.checksum where checksum is 11 chars
        // With has_checksum=true, the last segment is ALWAYS checksum, regardless of length
        let result = parse_token(b"mykey.ABCDEFGHIJK.checksum123", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
        assert_eq!(parts.checksum, Some(b"checksum123" as &[u8]));
    }

    #[test]
    fn test_valid_three_segment_token_proper() {
        // To have a proper key.expiry.checksum, checksum must NOT be 11 valid base64url chars
        let result = parse_token(b"mykey.ABCDEFGHIJK.chksum", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
        assert_eq!(parts.checksum, Some(b"chksum" as &[u8]));
    }

    #[test]
    fn test_unicode_in_key() {
        // Keys with unicode characters
        let result = parse_token("mykey🔑.ABCDEFGHIJK".as_bytes(), false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, "mykey🔑".as_bytes());
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
    }

    #[test]
    fn test_unicode_in_expiry() {
        // 11 "characters" but with unicode - byte length will be different
        let input = "mykey.ABC🔑EFGHIJK".as_bytes();
        let result = parse_token(input, true);
        // The emoji is 4 bytes, so total is 14 bytes, not 11
        // Should be treated as checksum
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.expiry_b64, None);
        assert_eq!(parts.checksum, Some("ABC🔑EFGHIJK".as_bytes()));
    }

    #[test]
    fn test_very_long_key() {
        let long_key = "a".repeat(10000);
        let input = format!("{}.ABCDEFGHIJK", long_key);
        let result = parse_token(input.as_bytes(), false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key.len(), 10000);
        assert_eq!(parts.expiry_b64, Some(b"ABCDEFGHIJK" as &[u8]));
    }

    #[test]
    fn test_very_long_checksum() {
        let long_checksum = "a".repeat(10000);
        let input = format!("mykey.{}", long_checksum);
        let result = parse_token(input.as_bytes(), true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"mykey");
        assert_eq!(parts.checksum.unwrap().len(), 10000);
    }

    #[test]
    fn test_four_dots() {
        // More than 3 segments
        let result = parse_token(b"seg1.seg2.seg3.seg4.seg5", true);
        // Last dot: "seg1.seg2.seg3.seg4" and "seg5"
        // "seg5" is 4 chars, not 11, so not expiry
        // Split "seg1.seg2.seg3.seg4" -> "seg1.seg2.seg3" and "seg4"
        // "seg4" is 4 chars, not 11, so error
        assert!(result.is_err(), "Invalid expiry length in middle segment");
    }

    #[test]
    fn test_only_key_no_dots() {
        let result = parse_token(b"justsimplekey", true);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"justsimplekey");
        assert_eq!(parts.expiry_b64, None);
        assert_eq!(parts.checksum, None);
    }

    #[test]
    fn test_whitespace_in_segments() {
        // Spaces in key
        let result = parse_token(b"my key.ABCDEFGHIJK", false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.key, b"my key");
    }

    #[test]
    fn test_all_valid_base64url_chars_in_expiry() {
        // Test with all valid base64url character types: A-Z, a-z, 0-9, -, _
        let result = parse_token(b"key.AZaz09-_123", false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.expiry_b64, Some(b"AZaz09-_123" as &[u8]));
    }

    #[test]
    fn test_empty_key_with_dots() {
        let result = parse_token(b".ABCDEFGHIJK.checksum", true);
        // Last dot: ".ABCDEFGHIJK" and "checksum"
        // "checksum" is not 11 chars, so checksum
        // Split ".ABCDEFGHIJK" -> "" and "ABCDEFGHIJK"
        // Empty key, should fail
        assert!(result.is_err(), "Empty key should fail");
    }

    #[test]
    fn test_empty_expiry_segment() {
        let result = parse_token(b"key..checksum", true);
        // Last dot splits at position 4: "key." and "checksum"
        // "checksum" is not 11 chars, so it's checksum
        // Split "key." -> "key" and ""
        // Empty expiry, should fail
        assert!(result.is_err(), "Empty expiry segment should fail");
    }

    #[test]
    fn test_case_sensitivity_base64url() {
        // base64url is case-sensitive, both upper and lower case are valid
        let result = parse_token(b"key.aBcDeFgHiJk", false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.expiry_b64, Some(b"aBcDeFgHiJk" as &[u8]));
    }

    #[test]
    fn test_dash_and_underscore_in_expiry() {
        // These are valid base64url chars
        let result = parse_token(b"key.ABC-DEF_HIJ", false);
        assert!(result.is_ok());
        let parts = result.unwrap().1;
        assert_eq!(parts.expiry_b64, Some(b"ABC-DEF_HIJ" as &[u8]));
    }
}
