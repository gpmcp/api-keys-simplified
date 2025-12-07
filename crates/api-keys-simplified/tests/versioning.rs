use api_keys_simplified::{
    ApiKeyManager, Environment, ExposeSecret, HashConfig, KeyConfig, KeyVersion,
};

#[test]
fn test_unversioned_key_format() {
    let manager = ApiKeyManager::init_default_config("sk").unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // Unversioned keys should have format: prefix-env-data.checksum
    assert!(key_str.starts_with("sk-live-"));
    assert!(key_str.contains('.'), "Should have checksum separator");

    // Should NOT contain version component
    assert!(!key_str.contains("-v1-"));
    assert!(!key_str.contains("-v2-"));
}

#[test]
fn test_versioned_key_v1_format() {
    let config = KeyConfig::default().with_version(KeyVersion::V1);
    let manager = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // V1 keys should have format: prefix-v1-env-data.checksum
    assert!(key_str.starts_with("sk-v1-live-"));
    assert!(key_str.contains('.'), "Should have checksum separator");
}

#[test]
fn test_versioned_key_v2_format() {
    let config = KeyConfig::default().with_version(KeyVersion::V2);
    let manager = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // V2 keys should have format: prefix-v2-env-data.checksum
    assert!(key_str.starts_with("sk-v2-live-"));
    assert!(key_str.contains('.'), "Should have checksum separator");
}

#[test]
fn test_custom_version_number() {
    let config = KeyConfig::default().with_version(KeyVersion::new(42));
    let manager = ApiKeyManager::init("api", config, HashConfig::default()).unwrap();
    let key = manager.generate(Environment::staging()).unwrap();
    let key_str = key.key().expose_secret();

    // Custom version keys should have format: prefix-v42-env-data.checksum
    assert!(key_str.starts_with("api-v42-staging-"));
    assert!(key_str.contains('.'), "Should have checksum separator");
}

#[test]
fn test_version_constants() {
    assert_eq!(KeyVersion::NONE.number(), 0);
    assert_eq!(KeyVersion::V1.number(), 1);
    assert_eq!(KeyVersion::V2.number(), 2);

    assert!(!KeyVersion::NONE.is_versioned());
    assert!(KeyVersion::V1.is_versioned());
    assert!(KeyVersion::V2.is_versioned());
}

#[test]
fn test_version_component_generation() {
    assert_eq!(KeyVersion::NONE.component(), "");
    assert_eq!(KeyVersion::V1.component(), "v1");
    assert_eq!(KeyVersion::V2.component(), "v2");
    assert_eq!(KeyVersion::new(100).component(), "v100");
}

#[test]
fn test_version_display() {
    assert_eq!(KeyVersion::NONE.to_string(), "unversioned");
    assert_eq!(KeyVersion::V1.to_string(), "v1");
    assert_eq!(KeyVersion::V2.to_string(), "v2");
    assert_eq!(KeyVersion::new(42).to_string(), "v42");
}

#[test]
fn test_different_versions_verify_correctly() {
    // Generate keys with different versions
    let manager_v0 = ApiKeyManager::init_default_config("sk").unwrap();
    let key_v0 = manager_v0.generate(Environment::production()).unwrap();

    let config_v1 = KeyConfig::default().with_version(KeyVersion::V1);
    let manager_v1 = ApiKeyManager::init("sk", config_v1, HashConfig::default()).unwrap();
    let key_v1 = manager_v1.generate(Environment::production()).unwrap();

    let config_v2 = KeyConfig::default().with_version(KeyVersion::V2);
    let manager_v2 = ApiKeyManager::init("sk", config_v2, HashConfig::default()).unwrap();
    let key_v2 = manager_v2.generate(Environment::production()).unwrap();

    // Each manager should successfully verify its own key
    assert!(manager_v0.verify(key_v0.key(), key_v0.hash()).unwrap());
    assert!(manager_v1.verify(key_v1.key(), key_v1.hash()).unwrap());
    assert!(manager_v2.verify(key_v2.key(), key_v2.hash()).unwrap());

    // Keys should not cross-verify (wrong hash)
    assert!(!manager_v0.verify(key_v1.key(), key_v0.hash()).unwrap());
    assert!(!manager_v1.verify(key_v2.key(), key_v1.hash()).unwrap());
}

#[test]
fn test_versioned_keys_support_all_environments() {
    let config = KeyConfig::default().with_version(KeyVersion::V1);
    let manager = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();

    let dev = manager.generate(Environment::dev()).unwrap();
    let test = manager.generate(Environment::test()).unwrap();
    let staging = manager.generate(Environment::staging()).unwrap();
    let prod = manager.generate(Environment::production()).unwrap();

    assert!(dev.key().expose_secret().starts_with("sk-v1-dev-"));
    assert!(test.key().expose_secret().starts_with("sk-v1-test-"));
    assert!(staging.key().expose_secret().starts_with("sk-v1-staging-"));
    assert!(prod.key().expose_secret().starts_with("sk-v1-live-"));

    // All should verify
    assert!(manager.verify(dev.key(), dev.hash()).unwrap());
    assert!(manager.verify(test.key(), test.hash()).unwrap());
    assert!(manager.verify(staging.key(), staging.hash()).unwrap());
    assert!(manager.verify(prod.key(), prod.hash()).unwrap());
}

#[test]
fn test_versioned_keys_with_different_separators() {
    use api_keys_simplified::Separator;

    let config = KeyConfig::default()
        .with_version(KeyVersion::V1)
        .with_separator(Separator::Slash);
    let manager = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // Should use slash separator but version format stays the same
    assert!(key_str.starts_with("sk/v1/live/"));
    assert!(manager.verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_versioned_keys_without_checksum() {
    let config = KeyConfig::default()
        .with_version(KeyVersion::V1)
        .disable_checksum();
    let manager = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // Should have version but no checksum separator
    assert!(key_str.starts_with("sk-v1-live-"));
    assert!(!key_str.contains('.'), "Should NOT have checksum separator");

    // Should still verify (checksum validation is skipped)
    assert!(manager.verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_versioned_keys_with_high_security() {
    let config = KeyConfig::high_security().with_version(KeyVersion::V2);
    let manager = ApiKeyManager::init("sk", config, HashConfig::high_security()).unwrap();
    let key = manager.generate(Environment::production()).unwrap();
    let key_str = key.key().expose_secret();

    // Should have version and be longer due to high security settings
    assert!(key_str.starts_with("sk-v2-live-"));
    assert!(key_str.len() > 100, "High security key should be longer");
    assert!(manager.verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_migration_scenario() {
    // Simulate old system
    let old_manager = ApiKeyManager::init_default_config("sk").unwrap();
    let old_key = old_manager.generate(Environment::production()).unwrap();

    // Simulate new system with versioning
    let new_config = KeyConfig::default().with_version(KeyVersion::V1);
    let new_manager = ApiKeyManager::init("sk", new_config, HashConfig::default()).unwrap();
    let new_key = new_manager.generate(Environment::production()).unwrap();

    // Both systems should work independently
    assert!(old_manager.verify(old_key.key(), old_key.hash()).unwrap());
    assert!(new_manager.verify(new_key.key(), new_key.hash()).unwrap());

    // Keys should look different
    assert!(!old_key.key().expose_secret().contains("-v1-"));
    assert!(new_key.key().expose_secret().contains("-v1-"));
}

#[test]
fn test_version_ordering() {
    assert!(KeyVersion::NONE < KeyVersion::V1);
    assert!(KeyVersion::V1 < KeyVersion::V2);
    assert!(KeyVersion::V2 < KeyVersion::new(100));
    assert!(KeyVersion::new(50) < KeyVersion::new(100));
}

#[test]
fn test_version_equality() {
    assert_eq!(KeyVersion::NONE, KeyVersion::new(0));
    assert_eq!(KeyVersion::V1, KeyVersion::new(1));
    assert_eq!(KeyVersion::V2, KeyVersion::new(2));

    assert_ne!(KeyVersion::V1, KeyVersion::V2);
    assert_ne!(KeyVersion::NONE, KeyVersion::V1);
}
