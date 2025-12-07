use api_keys_simplified::{ApiKeyManager, Environment, HashConfig, KeyConfig, SecureString};
use std::time::Instant;

#[test]
fn test_checksum_prevents_expensive_verification() {
    // This test verifies VULN-1 fix: checksum validation happens BEFORE Argon2
    let config = KeyConfig::default().with_checksum();
    let generator = ApiKeyManager::init("dos", config, HashConfig::default()).unwrap();

    // Generate a valid key with checksum
    let valid_key = generator.generate(Environment::test()).unwrap();
    let valid_hash = valid_key.hash().to_string();

    // Create invalid key with corrupted checksum (but valid format)
    let key_str = valid_key.key().as_ref();
    let parts: Vec<&str> = key_str.rsplitn(2, '.').collect();
    let key_without_checksum = parts[1];
    let invalid_key_with_bad_checksum = format!("{}.deadbeef", key_without_checksum);
    let invalid_key = SecureString::from(invalid_key_with_bad_checksum);

    // Measure time for invalid checksum verification
    let start = Instant::now();
    let result = generator.verify(&invalid_key, &valid_hash).unwrap();
    let duration = start.elapsed();

    // Should return false quickly (checksum validation, NOT Argon2)
    assert!(!result, "Invalid checksum should fail verification");

    // Should be MUCH faster than Argon2 (< 1ms vs ~100ms for Argon2)
    assert!(
        duration.as_millis() < 10,
        "Checksum validation should be fast (< 10ms), took {}ms. This suggests Argon2 was called!",
        duration.as_millis()
    );

    println!(
        "✅ Invalid checksum rejected in {}μs (Argon2 bypassed)",
        duration.as_micros()
    );
}

#[test]
fn test_valid_checksum_proceeds_to_argon2() {
    // Verify that valid checksums still go through Argon2 verification
    let config = KeyConfig::default().with_checksum();
    let generator = ApiKeyManager::init("verify", config, HashConfig::default()).unwrap();

    let key = generator.generate(Environment::production()).unwrap();

    let start = Instant::now();
    let result = generator.verify(key.key(), key.hash()).unwrap();
    let duration = start.elapsed();

    // Should succeed
    assert!(result, "Valid key should verify successfully");

    // Should take normal Argon2 time (> 10ms typically for balanced config)
    assert!(
        duration.as_millis() >= 10,
        "Valid checksum should proceed to Argon2 (> 10ms), took only {}ms",
        duration.as_millis()
    );

    println!(
        "✅ Valid key verified in {}ms (Argon2 executed)",
        duration.as_millis()
    );
}

#[test]
fn test_dos_protection_comparison() {
    // Compare DoS resistance: with vs without checksum
    let with_checksum = ApiKeyManager::init(
        "dos1",
        KeyConfig::default().with_checksum(),
        HashConfig::default(),
    )
    .unwrap();

    let without_checksum =
        ApiKeyManager::init("dos2", KeyConfig::default(), HashConfig::default()).unwrap();

    // Generate keys
    let key_with = with_checksum.generate(Environment::test()).unwrap();
    let key_without = without_checksum.generate(Environment::test()).unwrap();

    // Create invalid keys (random garbage)
    let invalid_keys: Vec<SecureString> = (0..10)
        .map(|i| SecureString::from(format!("dos1-test-random_garbage_{}", i)))
        .collect();

    // Test WITH checksum - should be fast
    let start = Instant::now();
    for invalid_key in &invalid_keys {
        let _ = with_checksum.verify(invalid_key, key_with.hash());
    }
    let with_checksum_time = start.elapsed();

    // Test WITHOUT checksum - should be slow (all Argon2)
    let invalid_keys_no_checksum: Vec<SecureString> = (0..10)
        .map(|i| SecureString::from(format!("dos2-test-random_garbage_{}", i)))
        .collect();

    let start = Instant::now();
    for invalid_key in &invalid_keys_no_checksum {
        let _ = without_checksum.verify(invalid_key, key_without.hash());
    }
    let without_checksum_time = start.elapsed();

    println!("📊 DoS Protection Comparison:");
    println!(
        "   With checksum:    {}ms for 10 invalid keys",
        with_checksum_time.as_millis()
    );
    println!(
        "   Without checksum: {}ms for 10 invalid keys",
        without_checksum_time.as_millis()
    );
    println!(
        "   Speedup: {}x faster",
        without_checksum_time.as_millis() / with_checksum_time.as_millis().max(1)
    );

    // With checksum should be SIGNIFICANTLY faster (at least 10x)
    assert!(
        with_checksum_time < without_checksum_time / 10,
        "Checksum protection should be at least 10x faster. With: {}ms, Without: {}ms",
        with_checksum_time.as_millis(),
        without_checksum_time.as_millis()
    );
}

#[test]
fn test_checksum_not_enabled_still_works() {
    // Verify that when checksum is NOT enabled, verify() still works
    // (but doesn't get DoS protection)
    let generator = ApiKeyManager::init(
        "nochk",
        KeyConfig::default(), // No checksum
        HashConfig::default(),
    )
    .unwrap();

    let key = generator.generate(Environment::test()).unwrap();

    // Should still verify correctly
    assert!(generator.verify(key.key(), key.hash()).unwrap());

    // Invalid key should still fail
    let invalid = SecureString::from("nochk-test-invalid".to_string());
    assert!(!generator.verify(&invalid, key.hash()).unwrap());
}

#[test]
fn test_manual_checksum_verification_still_available() {
    // Users can still manually call verify_checksum if they want
    let config = KeyConfig::default().with_checksum();
    let generator = ApiKeyManager::init("manual", config, HashConfig::default()).unwrap();

    let key = generator.generate(Environment::production()).unwrap();

    // Manual checksum check
    assert!(generator.verify_checksum(key.key()).unwrap());

    // Corrupted checksum
    let key_str = key.key().as_ref();
    let parts: Vec<&str> = key_str.rsplitn(2, '.').collect();
    let corrupted = format!("{}.ffffffff", parts[1]);
    let corrupted_key = SecureString::from(corrupted);

    assert!(!generator.verify_checksum(&corrupted_key).unwrap());
}
