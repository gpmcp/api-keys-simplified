use api_keys_simplified::{
    ApiKeyManager, Argon2Params, ConfigBuilder, Environment, HashAlgo, KeyStatus,
};
use api_keys_simplified::{ExposeSecret, SecureStringExt};

#[test]
fn test_custom_entropy() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("sk")
            .entropy(16)
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let key = generator.generate(Environment::test()).unwrap();

    assert!(key.key().len() > 10);
}

#[test]
fn test_without_checksum() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("pk")
            .no_checksum()
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let key = generator.generate(Environment::production()).unwrap();

    // Environment "live" means production, Base64URL can contain underscores and hyphens
    // Key format with dash separator: pk-live-{base64url_data}
    // No checksum, so no dot at the end
    assert!(key.key().expose_secret().starts_with("pk-live-"));
    assert!(
        !key.key().expose_secret().contains('.'),
        "Should not have checksum dot"
    );
}

#[test]
fn test_high_security_preset() {
    let generator =
        ApiKeyManager::new(ConfigBuilder::high_security().prefix("sk").build().unwrap()).unwrap();
    let key = generator.generate(Environment::production()).unwrap();

    assert!(key.key().len() > 50); // Higher entropy = longer key
    assert_eq!(
        generator
            .verify(key.key(), key.expose_hash().hash())
            .unwrap(),
        KeyStatus::Valid
    );
}

#[test]
fn test_balanced_preset() {
    let balanced_gen =
        ApiKeyManager::new(ConfigBuilder::new().prefix("sk").build().unwrap()).unwrap();
    let key = balanced_gen.generate(Environment::production()).unwrap();

    let high_gen =
        ApiKeyManager::new(ConfigBuilder::high_security().prefix("sk").build().unwrap()).unwrap();
    let high = high_gen.generate(Environment::production()).unwrap();

    assert!(key.key().len() < high.key().len());
}

#[test]
fn test_custom_hash_config() {
    let generator = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("text")
            .hash(HashAlgo::Argon2id(Argon2Params {
                memory_cost: 8192,
                time_cost: 1,
                parallelism: 1,
            }))
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let key = generator.generate(Environment::dev()).unwrap();

    assert_eq!(
        generator
            .verify(key.key(), key.expose_hash().hash())
            .unwrap(),
        KeyStatus::Valid
    );
}

#[test]
fn test_entropy_boundaries() {
    // Minimum entropy
    let gen_min = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("min")
            .entropy(16)
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let key_min = gen_min.generate(Environment::test()).unwrap();
    assert!(!key_min.key().is_empty());

    // Maximum entropy
    let gen_max = ApiKeyManager::new(
        ConfigBuilder::new()
            .prefix("max")
            .entropy(64)
            .grace_period(std::time::Duration::ZERO)
            .build()
            .unwrap(),
    )
    .unwrap();
    let key_max = gen_max.generate(Environment::test()).unwrap();
    assert!(key_max.key().len() > key_min.key().len());
}

#[test]
fn test_invalid_entropy() {
    assert!(ConfigBuilder::new()
        .prefix("sk")
        .entropy(8)
        .build()
        .is_err());
    assert!(ConfigBuilder::new()
        .prefix("sk")
        .entropy(128)
        .build()
        .is_err());
}
