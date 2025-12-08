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

/// Auto-detect `<key>[.<expiry_11>][.<checksum>]`:
/// - If tail is 11 base64url chars → treat as expiry (no checksum)
/// - Else treat tail as checksum and look for expiry before it
pub fn parse_token(input: &[u8]) -> IResult<&[u8], Parts<'_>> {
    // no dot at all → only key
    let (before_last, tail) = match split_last_dot(input) {
        None => {
            if input.is_empty() {
                return Err(NomErr::Error(ParseError::from_error_kind(
                    input,
                    ErrorKind::Eof,
                )));
            }
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

    let tail_is_expiry =
        tail.len() == EXPIRY_B64URL_LEN && tail.iter().all(|&b| is_b64url_no_pad(b));

    if tail_is_expiry {
        // key.expiry
        if before_last.is_empty() {
            return Err(NomErr::Error(ParseError::from_error_kind(
                input,
                ErrorKind::Eof,
            )));
        }
        return Ok((
            &input[input.len()..],
            Parts {
                key: before_last,
                expiry_b64: Some(tail),
                checksum: None,
            },
        ));
    }

    // Otherwise: key.expiry.checksum (checksum = tail)
    let (key, expiry) = match split_last_dot(before_last) {
        Some((k, e)) => (k, e),
        None => {
            // key.checksum (no expiry)
            if before_last.is_empty() || tail.is_empty() {
                return Err(NomErr::Error(ParseError::from_error_kind(
                    input,
                    ErrorKind::Eof,
                )));
            }
            return Ok((
                &input[input.len()..],
                Parts {
                    key: before_last,
                    expiry_b64: None,
                    checksum: Some(tail),
                },
            ));
        }
    };

    if key.is_empty() || expiry.is_empty() {
        return Err(NomErr::Error(ParseError::from_error_kind(
            input,
            ErrorKind::Eof,
        )));
    }
    if expiry.len() != EXPIRY_B64URL_LEN || !expiry.iter().all(|&b| is_b64url_no_pad(b)) {
        return Err(NomErr::Error(ParseError::from_error_kind(
            input,
            ErrorKind::Verify,
        )));
    }

    Ok((
        &input[input.len()..],
        Parts {
            key,
            expiry_b64: Some(expiry),
            checksum: Some(tail),
        },
    ))
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
        println!("{token}");
        let parts = parse_token(token.as_bytes()).unwrap().1;
        let exp = parts.expiry_b64.unwrap();
        let exp_be_by = URL_SAFE_NO_PAD.decode(exp).unwrap();
        assert_eq!(
            ts.timestamp(),
            i64::from_be_bytes(exp_be_by.try_into().unwrap())
        );
    }
}
