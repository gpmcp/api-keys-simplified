use api_keys_simplified::{ApiKeyManager, Environment, HashConfig, KeyConfig};
use api_keys_simplified::{ExposeSecret, SecureStringExt};
use std::collections::HashSet;

#[test]
fn test_verification_with_invalid_hash() {
    // After timing oracle fix: invalid hash returns Ok(false) instead of Err
    // to prevent timing-based user enumeration attacks
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let any_key = api_keys_simplified::SecureString::from("any_key".to_string());
    let result = generator.verify(&any_key, "invalid_hash_format");
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_different_keys_same_hash() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let key1 = generator.generate(Environment::production()).unwrap();
    let key2 = generator.generate(Environment::production()).unwrap();

    // Different keys should not validate against each other's hashes
    assert!(!generator.verify(key2.key(), key1.hash()).unwrap());
    assert!(!generator.verify(key1.key(), key2.hash()).unwrap());
}

#[test]
fn test_checksum_validation() {
    let config = KeyConfig::default();
    let generator = ApiKeyManager::init("chk", config, HashConfig::default()).unwrap();
    let with_checksum = generator.generate(Environment::test()).unwrap();
    assert!(generator.verify_checksum(with_checksum.key()).unwrap());

    // Corrupt the checksum
    let corrupted = format!(
        "{}_corrupt",
        &with_checksum.key().expose_secret()[..with_checksum.key().len() - 8]
    );
    let corrupted_key = api_keys_simplified::SecureString::from(corrupted);
    assert!(!generator.verify_checksum(&corrupted_key).unwrap());
}

#[test]
fn test_hash_uniqueness_with_same_key() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let hash1 = generator.generate(Environment::production()).unwrap();
    let hash2 = generator.generate(Environment::production()).unwrap();

    // Even with same key value, hashes should differ due to unique salts
    assert_ne!(hash1.hash(), hash2.hash());
}

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_collision_resistance() {
    let mut keys = HashSet::new();
    let count = 1000;

    let generator = ApiKeyManager::init_default_config("text").unwrap();
    for _ in 0..count {
        let key = generator.generate(Environment::test()).unwrap();
        keys.insert(key.key().expose_secret().to_string());
    }

    // All keys should be unique
    assert_eq!(keys.len(), count);
}

#[test]
fn test_key_format_consistency() {
    let config = KeyConfig::default();
    let generator = ApiKeyManager::init("format", config, HashConfig::default()).unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let key_str = key.key().expose_secret();

    // With dash separator and checksum (enabled by default): format-test-data.checksum = 1 dot
    assert_eq!(key_str.matches('.').count(), 1);

    // Should not contain spaces or special characters except . and base64url chars (A-Za-z0-9-_)
    assert!(key_str
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.'));
}

#[test]
fn test_argon2_phc_format() {
    let generator = ApiKeyManager::init_default_config("phc").unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let hash = key.hash();

    // Argon2 PHC format starts with $argon2id$
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.contains("$v=19$"));
    assert!(hash.contains("$m="));
    assert!(hash.contains(",t="));
    assert!(hash.contains(",p="));
}

#[test]
fn test_error_messages_dont_leak_info() {
    // After timing oracle fix: invalid hash format returns Ok(false) to prevent
    // timing attacks, so we test DoS protection errors instead

    // Test DoS protection error (oversized input) - this still returns Err
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let oversized_key = api_keys_simplified::SecureString::from("a".repeat(1000));
    let result = generator.verify(&oversized_key, "some_hash");
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // Error message should NOT contain:
    // - "argon2" or parameter names
    // - "salt" or "hash" details
    // - "password" or implementation details
    // - Specific format information
    assert!(!err_msg.contains("argon2"));
    assert!(!err_msg.contains("salt"));
    assert!(!err_msg.contains("parameter"));
    assert!(!err_msg.contains("PHC"));

    // Should be a generic error
    assert!(err_msg == "Operation failed" || err_msg == "Invalid input");
}

#[test]
fn test_oversized_input_error_is_generic() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let oversized_key = api_keys_simplified::SecureString::from("a".repeat(1000));
    let result = generator.verify(&oversized_key, "some_hash");

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "Invalid input");

    // Should not reveal max length or DOS prevention mechanism
    assert!(!err.to_string().contains("512"));
    assert!(!err.to_string().contains("length"));
    assert!(!err.to_string().contains("DoS"));
}
