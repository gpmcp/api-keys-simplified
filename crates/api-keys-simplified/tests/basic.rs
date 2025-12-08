use api_keys_simplified::ExposeSecret;
use api_keys_simplified::{ApiKeyManagerV0, Environment, KeyStatus};

#[test]
fn test_basic_flow() {
    let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let hash = key.hash();

    assert_eq!(generator.verify(key.key(), hash).unwrap(), KeyStatus::Valid);

    // For verifying a different key against the same hash, create a new ApiKey
    let wrong_key = api_keys_simplified::SecureString::from("wrong_key".to_string());
    assert_eq!(
        generator.verify(&wrong_key, hash).unwrap(),
        KeyStatus::Invalid
    );
}

#[test]
fn test_key_format() {
    let generator = ApiKeyManagerV0::init_default_config("pk").unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let key_str = key.key().expose_secret();

    assert!(key_str.starts_with("pk-test-"));
    assert!(key_str.len() > 20);
}

#[test]
fn test_different_environments() {
    let generator = ApiKeyManagerV0::init_default_config("key").unwrap();

    let dev = generator.generate(Environment::dev()).unwrap();
    let test = generator.generate(Environment::test()).unwrap();
    let staging = generator.generate(Environment::staging()).unwrap();
    let live = generator.generate(Environment::production()).unwrap();

    assert!(dev.key().expose_secret().contains("-dev-"));
    assert!(test.key().expose_secret().contains("-test-"));
    assert!(staging.key().expose_secret().contains("-staging-"));
    assert!(live.key().expose_secret().contains("-live-"));
}

#[test]
fn test_verification_with_wrong_key() {
    let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let hash = key.hash();

    let wrong1 = api_keys_simplified::SecureString::from("completely_wrong_key".to_string());
    assert_eq!(generator.verify(&wrong1, hash).unwrap(), KeyStatus::Invalid);

    let wrong2 = api_keys_simplified::SecureString::from("sk_live_wrongrandomdata".to_string());
    assert_eq!(generator.verify(&wrong2, hash).unwrap(), KeyStatus::Invalid);
}

#[test]
fn test_key_uniqueness() {
    let generator = ApiKeyManagerV0::init_default_config("sk").unwrap();
    let key1 = generator.generate(Environment::production()).unwrap();
    let key2 = generator.generate(Environment::production()).unwrap();

    assert_ne!(key1.key().expose_secret(), key2.key().expose_secret());
    assert_ne!(key1.hash(), key2.hash());
}
