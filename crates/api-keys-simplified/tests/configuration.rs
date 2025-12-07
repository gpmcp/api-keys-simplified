use api_keys_simplified::{ApiKeyManager, Environment, HashConfig, KeyConfig};

#[test]
fn test_custom_entropy() {
    let config = KeyConfig::new().with_entropy(16).unwrap();
    let generator = ApiKeyManager::init("sk", config, HashConfig::default()).unwrap();
    let key = generator.generate(Environment::test()).unwrap();

    assert!(key.key().len() > 10);
}

#[test]
fn test_with_checksum() {
    let config = KeyConfig::default().with_checksum(true);
    let generator = ApiKeyManager::init("pk", config, HashConfig::default()).unwrap();
    let key = generator.generate(Environment::production()).unwrap();

    assert!(generator.verify_checksum(key.key()).unwrap());
}

#[test]
fn test_without_checksum() {
    let config = KeyConfig::default().with_checksum(false);
    let generator = ApiKeyManager::init("pk", config, HashConfig::default()).unwrap();
    let key = generator.generate(Environment::production()).unwrap();

    // Environment "live" means production, Base64URL can contain underscores and hyphens
    // Key format with dash separator: pk-live-{base64url_data}
    // No checksum, so no dot at the end
    assert!(key.key().as_ref().starts_with("pk-live-"));
    assert!(
        !key.key().as_ref().contains('.'),
        "Should not have checksum dot"
    );
}

#[test]
fn test_high_security_preset() {
    let generator = ApiKeyManager::init_high_security_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();

    assert!(key.key().len() > 50); // Higher entropy = longer key
    assert!(generator.verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_balanced_preset() {
    let balanced_gen = ApiKeyManager::init_default_config("sk").unwrap();
    let key = balanced_gen.generate(Environment::production()).unwrap();

    let high_gen = ApiKeyManager::init_high_security_config("sk").unwrap();
    let high = high_gen.generate(Environment::production()).unwrap();

    assert!(key.key().len() < high.key().len());
}

#[test]
fn test_custom_hash_config() {
    let hash_config = HashConfig::custom(8192, 1, 1).unwrap();

    let config = KeyConfig::default();
    let generator = ApiKeyManager::init("text", config, hash_config).unwrap();
    let key = generator.generate(Environment::dev()).unwrap();

    assert!(generator.verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_entropy_boundaries() {
    // Minimum entropy
    let config_min = KeyConfig::new().with_entropy(16).unwrap();
    let gen_min = ApiKeyManager::init("min", config_min, HashConfig::default()).unwrap();
    let key_min = gen_min.generate(Environment::test()).unwrap();
    assert!(!key_min.key().is_empty());

    // Maximum entropy
    let config_max = KeyConfig::new().with_entropy(64).unwrap();
    let gen_max = ApiKeyManager::init("max", config_max, HashConfig::default()).unwrap();
    let key_max = gen_max.generate(Environment::test()).unwrap();
    assert!(key_max.key().len() > key_min.key().len());
}

#[test]
fn test_invalid_entropy() {
    assert!(KeyConfig::new().with_entropy(8).is_err());
    assert!(KeyConfig::new().with_entropy(128).is_err());
}
