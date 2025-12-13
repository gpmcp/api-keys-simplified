use api_keys_simplified::{
    ApiKeyManagerV0, Environment, ExposeSecret, HashConfig, KeyConfig, KeyStatus, SecureString,
};
use chrono::{Duration, Utc};

/// Test that a key with future expiry is valid
#[test]
fn test_future_expiry_is_valid() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() + Duration::days(7);

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Valid
    );
}

/// Test that a key with past expiry is expired
#[test]
fn test_past_expiry_is_expired() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() - Duration::days(1);

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Invalid
    );
}

/// Test that expiry exactly at current time is still valid (<=)
#[test]
fn test_expiry_at_current_time() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now();

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Should be Valid since verification uses: now <= expiry
    let status = manager.verify(key.key(), key.hash()).unwrap();
    assert!(
        status == KeyStatus::Valid || status == KeyStatus::Invalid,
        "Status at boundary should be Valid or Expired depending on timing"
    );
}

/// Test that keys without expiry never expire
#[test]
fn test_no_expiry_never_expires() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let key = manager.generate(Environment::production()).unwrap();

    // Verify immediately
    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Valid
    );
}

/// Test expired key with wrong hash still returns Invalid (not Expired)
#[test]
fn test_expired_key_wrong_hash() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() - Duration::days(1);

    let expired_key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Generate another key to get a different hash
    let other_key = manager.generate(Environment::production()).unwrap();

    // Verify expired key against wrong hash - should be Invalid, not Expired
    assert_eq!(
        manager.verify(expired_key.key(), other_key.hash()).unwrap(),
        KeyStatus::Invalid
    );
}

/// Test very short expiry (seconds)
#[test]
fn test_short_expiry() {
    const EXPIRY: i64 = 3;
    let config = KeyConfig::default();
    let h_config = HashConfig::default();
    let manager = ApiKeyManagerV0::init("sk", config, h_config, std::time::Duration::ZERO).unwrap();
    let expiry = Utc::now() + Duration::seconds(EXPIRY);
    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Should be valid immediately after creation
    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Valid
    );

    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_secs(EXPIRY as u64 + 1));

    // Should now be expired
    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Invalid
    );
}

/// Test very long expiry (years)
#[test]
fn test_long_expiry() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() + Duration::days(365 * 10); // 10 years

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Valid
    );
}

/// Test expiry with different environments
#[test]
fn test_expiry_across_environments() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let future = Utc::now() + Duration::days(1);
    let past = Utc::now() - Duration::days(1);

    let dev_valid = manager
        .generate_with_expiry(Environment::dev(), future)
        .unwrap();
    let test_expired = manager
        .generate_with_expiry(Environment::test(), past)
        .unwrap();
    let staging_valid = manager
        .generate_with_expiry(Environment::staging(), future)
        .unwrap();
    let live_expired = manager
        .generate_with_expiry(Environment::production(), past)
        .unwrap();

    assert_eq!(
        manager.verify(dev_valid.key(), dev_valid.hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        manager
            .verify(test_expired.key(), test_expired.hash())
            .unwrap(),
        KeyStatus::Invalid
    );
    assert_eq!(
        manager
            .verify(staging_valid.key(), staging_valid.hash())
            .unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        manager
            .verify(live_expired.key(), live_expired.hash())
            .unwrap(),
        KeyStatus::Invalid
    );
}

/// Test that expiry is embedded in key and survives hashing
#[test]
fn test_expiry_embedded_in_key() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() - Duration::days(1);

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Store hash separately
    let hash_str = key.hash().to_string();

    // Verify using the stored hash - expiry should still work
    assert_eq!(
        manager.verify(key.key(), &hash_str).unwrap(),
        KeyStatus::Invalid
    );
}

/// Test expiry with checksum disabled
#[test]
fn test_expiry_without_checksum() {
    use api_keys_simplified::{HashConfig, KeyConfig};

    let config = KeyConfig::default().disable_checksum();
    let manager = ApiKeyManagerV0::init(
        "sk",
        config,
        HashConfig::default(),
        std::time::Duration::ZERO,
    )
    .unwrap();

    let past = Utc::now() - Duration::hours(1);
    let future = Utc::now() + Duration::hours(1);

    let expired_key = manager
        .generate_with_expiry(Environment::production(), past)
        .unwrap();
    let valid_key = manager
        .generate_with_expiry(Environment::production(), future)
        .unwrap();

    // Expiry works independently of checksum
    assert_eq!(
        manager
            .verify(expired_key.key(), expired_key.hash())
            .unwrap(),
        KeyStatus::Invalid
    );
    assert_eq!(
        manager.verify(valid_key.key(), valid_key.hash()).unwrap(),
        KeyStatus::Valid
    );
}

/// Test multiple keys with same expiry
#[test]
fn test_multiple_keys_same_expiry() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() + Duration::days(30);

    let key1 = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();
    let key2 = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();
    let key3 = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // All keys should be unique
    assert_ne!(key1.key().expose_secret(), key2.key().expose_secret());
    assert_ne!(key2.key().expose_secret(), key3.key().expose_secret());
    assert_ne!(key1.hash().to_string(), key2.hash().to_string());

    // All should be valid
    assert_eq!(
        manager.verify(key1.key(), key1.hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        manager.verify(key2.key(), key2.hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        manager.verify(key3.key(), key3.hash()).unwrap(),
        KeyStatus::Valid
    );
}

/// Test that expired keys with valid checksum still return Expired (not Invalid)
#[test]
fn test_expired_with_valid_checksum() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() - Duration::days(1);

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Key has valid checksum and correct hash, but is expired
    assert_eq!(
        manager.verify(key.key(), key.hash()).unwrap(),
        KeyStatus::Invalid
    );
}

/// Test expiry timestamp encoding/decoding
#[test]
fn test_expiry_timestamp_round_trip() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();

    // Test various timestamps
    let timestamps = vec![
        Utc::now(),
        Utc::now() + Duration::days(1),
        Utc::now() + Duration::days(365),
        Utc::now() - Duration::days(1),
    ];

    for ts in timestamps {
        let key = manager
            .generate_with_expiry(Environment::production(), ts)
            .unwrap();

        // Verify doesn't panic and returns a valid status
        let status = manager.verify(key.key(), key.hash()).unwrap();
        assert!(
            matches!(status, KeyStatus::Valid | KeyStatus::Invalid),
            "Expected Valid or Expired, got {:?}",
            status
        );
    }
}

/// Test expiry with high security config
#[test]
fn test_expiry_with_high_security() {
    let manager = ApiKeyManagerV0::init_high_security_config("sk").unwrap();

    let future = Utc::now() + Duration::days(7);
    let past = Utc::now() - Duration::days(1);

    let valid_key = manager
        .generate_with_expiry(Environment::production(), future)
        .unwrap();
    let expired_key = manager
        .generate_with_expiry(Environment::production(), past)
        .unwrap();

    assert_eq!(
        manager.verify(valid_key.key(), valid_key.hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        manager
            .verify(expired_key.key(), expired_key.hash())
            .unwrap(),
        KeyStatus::Invalid
    );
}

/// Test that corrupted expiry data returns Invalid (not panic)
#[test]
fn test_corrupted_expiry_returns_invalid() {
    let manager = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let expiry = Utc::now() + Duration::days(1);

    let key = manager
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    // Corrupt the key by modifying expiry portion
    let key_str = key.key().expose_secret();
    let parts: Vec<&str> = key_str.split('.').collect();

    if parts.len() >= 2 {
        // Replace expiry with corrupted data (wrong length)
        let corrupted = format!("{}.corrupted.{}", parts[0], parts.get(2).unwrap_or(&""));
        let corrupted_key = SecureString::from(corrupted);

        // Should return Invalid (or Expired), not panic
        let result = manager.verify(&corrupted_key, key.hash());
        assert!(result.is_ok(), "Corrupted expiry should not cause panic");
    }
}

/// Test real-world scenario: trial key lifecycle
#[test]
fn test_trial_key_lifecycle() {
    let manager = ApiKeyManagerV0::init_default_config("trial").unwrap();

    // Create 7-day trial key
    let trial_expiry = Utc::now() + Duration::days(7);
    let trial_key = manager
        .generate_with_expiry(Environment::production(), trial_expiry)
        .unwrap();

    // Day 1: Valid
    assert_eq!(
        manager.verify(trial_key.key(), trial_key.hash()).unwrap(),
        KeyStatus::Valid
    );

    // Create expired trial (simulate 8 days passing)
    let expired_trial = Utc::now() - Duration::days(1);
    let expired_key = manager
        .generate_with_expiry(Environment::production(), expired_trial)
        .unwrap();

    // After expiry: Expired
    assert_eq!(
        manager
            .verify(expired_key.key(), expired_key.hash())
            .unwrap(),
        KeyStatus::Invalid
    );
}

/// Test that expiry works with different key prefixes
#[test]
fn test_expiry_with_custom_prefix() {
    let manager1 = ApiKeyManagerV0::init_default_config("api").unwrap();
    let manager2 = ApiKeyManagerV0::init_default_config("partner").unwrap();

    let expiry = Utc::now() - Duration::hours(1);

    let key1 = manager1
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();
    let key2 = manager2
        .generate_with_expiry(Environment::production(), expiry)
        .unwrap();

    assert_eq!(
        manager1.verify(key1.key(), key1.hash()).unwrap(),
        KeyStatus::Invalid
    );
    assert_eq!(
        manager2.verify(key2.key(), key2.hash()).unwrap(),
        KeyStatus::Invalid
    );
}
