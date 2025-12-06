use api_keys_simplified::{ApiKey, Environment, HashConfig, KeyConfig};

#[test]
fn test_custom_entropy() {
    let config = KeyConfig::new().with_entropy(16).unwrap();
    let key = ApiKey::generate("sk", Environment::test(), config).unwrap();
    
    assert!(key.key().len() > 10);
}

#[test]
fn test_with_checksum() {
    let config = KeyConfig::default().with_checksum(true);
    let key = ApiKey::generate("pk", Environment::production(), config).unwrap();
    
    assert!(ApiKey::verify_checksum(key.key()).unwrap());
}

#[test]
fn test_without_checksum() {
    let config = KeyConfig::default().with_checksum(false);
    let key = ApiKey::generate("pk", Environment::production(), config).unwrap();
    
    // Environment "live" means production, Base64URL can contain underscores and hyphens
    // Key format: pk.live.{base64url_data} = 2 dots
    let parts: Vec<&str> = key.key().as_ref().split('.').collect();
    assert!(parts.len() >= 3); // prefix.env.data
    assert!(key.key().as_ref().starts_with("pk.live."));
}

#[test]
fn test_high_security_preset() {
    let key = ApiKey::generate_high_security("sk", Environment::production()).unwrap();
    
    assert!(key.key().len() > 50); // Higher entropy = longer key
    assert!(ApiKey::verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_balanced_preset() {
    let key = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let high = ApiKey::generate_high_security("sk", Environment::production()).unwrap();
    
    assert!(key.key().len() < high.key().len());
}

#[test]
fn test_custom_hash_config() {
    let hash_config = HashConfig::custom(8192, 1, 1).unwrap();
    
    let config = KeyConfig::default().with_hash_config(hash_config);
    let key = ApiKey::generate("test", Environment::dev(), config).unwrap();
    
    assert!(ApiKey::verify(key.key(), key.hash()).unwrap());
}

#[test]
fn test_entropy_boundaries() {
    // Minimum entropy
    let config_min = KeyConfig::new().with_entropy(16).unwrap();
    let key_min = ApiKey::generate("min", Environment::test(), config_min).unwrap();
    assert!(!key_min.key().is_empty());

    // Maximum entropy
    let config_max = KeyConfig::new().with_entropy(64).unwrap();
    let key_max = ApiKey::generate("max", Environment::test(), config_max).unwrap();
    assert!(key_max.key().len() > key_min.key().len());
}

#[test]
fn test_invalid_entropy() {
    assert!(KeyConfig::new().with_entropy(8).is_err());
    assert!(KeyConfig::new().with_entropy(128).is_err());
}
