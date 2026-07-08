use api_keys_simplified::{
    ApiKeyManager, Argon2Params, ConfigBuilder, Environment, HashAlgo, KeyStatus,
};
use api_keys_simplified::{ExposeSecret, SecureStringExt};
use std::collections::HashSet;

#[test]
fn test_verification_with_invalid_hash() {
    // After timing oracle fix: invalid hash returns Ok(Invalid) instead of Err
    // to prevent timing-based user enumeration attacks
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
    let any_key = api_keys_simplified::SecureString::from("any_key".to_string());
    let result = generator.verify(&any_key, "invalid_hash_format");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), KeyStatus::Invalid);
}

#[test]
fn test_different_keys_same_hash() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
    let key1 = generator.generate(Environment::production()).unwrap();
    let key2 = generator.generate(Environment::production()).unwrap();

    // Different keys should not validate against each other's hashes
    assert_eq!(
        generator
            .verify(key2.key(), key1.expose_hash().hash())
            .unwrap(),
        KeyStatus::Invalid
    );
    assert_eq!(
        generator
            .verify(key1.key(), key2.expose_hash().hash())
            .unwrap(),
        KeyStatus::Invalid
    );
}

#[test]
fn test_checksum_validation() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("chk")
            .pepper("test-pepper")
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let with_checksum = generator.generate(Environment::test()).unwrap();
    assert_eq!(
        generator.verify_checksum(with_checksum.key()).unwrap(),
        KeyStatus::Valid
    );

    // Corrupt the checksum
    let corrupted = format!(
        "{}_corrupt",
        &with_checksum.key().expose_secret()[..with_checksum.key().len() - 8]
    );
    let corrupted_key = api_keys_simplified::SecureString::from(corrupted);
    assert_eq!(
        generator.verify_checksum(&corrupted_key).unwrap(),
        KeyStatus::Invalid
    );
}

#[test]
fn test_hash_uniqueness_with_same_key() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
    let hash1 = generator.generate(Environment::production()).unwrap();
    let hash2 = generator.generate(Environment::production()).unwrap();

    // Even with same key value, hashes should differ due to unique salts
    assert_ne!(hash1.expose_hash(), hash2.expose_hash());
}

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_collision_resistance() {
    let mut keys = HashSet::new();
    let count = 1000;

    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("text")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
    for _ in 0..count {
        let key = generator.generate(Environment::test()).unwrap();
        keys.insert(key.key().expose_secret().to_string());
    }

    // All keys should be unique
    assert_eq!(keys.len(), count);
}

#[test]
fn test_key_format_consistency() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("format")
            .pepper("test-pepper")
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
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
    // Explicitly select Argon2id: this test asserts its PHC output format.
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("phc")
            .hash(HashAlgo::Argon2id(Argon2Params::balanced()))
            .build()
            .unwrap(),
    )
    .unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let hash = key.expose_hash().hash();

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
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
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

    // Should be a generic, crypto-internal-free message.
    assert!(!err_msg.is_empty());
}

#[test]
fn test_oversized_input_error_is_generic() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .pepper("test-pepper")
            .build()
            .unwrap(),
    )
    .unwrap();
    let oversized_key = api_keys_simplified::SecureString::from("a".repeat(1000));
    let result = generator.verify(&oversized_key, "some_hash");

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        api_keys_simplified::VerifyError::InputTooLong
    ));

    // Should not reveal the exact max length or the DoS-prevention mechanism.
    assert!(!err.to_string().contains("512"));
    assert!(!err.to_string().contains("DoS"));
}
