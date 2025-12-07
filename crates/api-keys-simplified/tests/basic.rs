use api_keys_simplified::{ApiKeyManager, Environment};

#[test]
fn test_basic_flow() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let hash = key.hash();

    assert!(generator.verify(key.key(), hash).unwrap());

    // For verifying a different key against the same hash, create a new ApiKey
    let wrong_key = api_keys_simplified::SecureString::from("wrong_key".to_string());
    assert!(!generator.verify(&wrong_key, hash).unwrap());
}

#[test]
fn test_key_format() {
    let generator = ApiKeyManager::init_default_config("pk").unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let key_str = key.key().as_ref();

    assert!(key_str.starts_with("pk-test-"));
    assert!(key_str.len() > 20);
}

#[test]
fn test_different_environments() {
    let generator = ApiKeyManager::init_default_config("key").unwrap();

    let dev = generator.generate(Environment::dev()).unwrap();
    let test = generator.generate(Environment::test()).unwrap();
    let staging = generator.generate(Environment::staging()).unwrap();
    let live = generator.generate(Environment::production()).unwrap();

    assert!(dev.key().as_ref().contains("-dev-"));
    assert!(test.key().as_ref().contains("-test-"));
    assert!(staging.key().as_ref().contains("-staging-"));
    assert!(live.key().as_ref().contains("-live-"));
}

#[test]
fn test_verification_with_wrong_key() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let hash = key.hash();

    let wrong1 = api_keys_simplified::SecureString::from("completely_wrong_key".to_string());
    assert!(!generator.verify(&wrong1, hash).unwrap());

    let wrong2 = api_keys_simplified::SecureString::from("sk_live_wrongrandomdata".to_string());
    assert!(!generator.verify(&wrong2, hash).unwrap());
}

#[test]
fn test_key_uniqueness() {
    let generator = ApiKeyManager::init_default_config("sk").unwrap();
    let key1 = generator.generate(Environment::production()).unwrap();
    let key2 = generator.generate(Environment::production()).unwrap();

    assert_ne!(key1.key().as_ref(), key2.key().as_ref());
    assert_ne!(key1.hash(), key2.hash());
}
