use api_keys_simplified::{ApiKey, ApiKeyGenerator, Environment, Separator};

#[test]
fn test_basic_flow() {
    let generator = ApiKeyGenerator::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let _key_str = key.key().as_ref();
    let hash = key.hash();

    assert!(key.verify(hash).unwrap());
    
    // For verifying a different key against the same hash, create a new ApiKey
    let wrong_key = ApiKey::new(api_keys_simplified::SecureString::from("wrong_key".to_string()));
    assert!(!wrong_key.verify(hash).unwrap());
}

#[test]
fn test_key_format() {
    let generator = ApiKeyGenerator::init_default_config("pk").unwrap();
    let key = generator.generate(Environment::test()).unwrap();
    let key_str = key.key().as_ref();

    assert!(key_str.starts_with("pk-test-"));
    assert!(key_str.len() > 20);
}

#[test]
fn test_different_environments() {
    let generator = ApiKeyGenerator::init_default_config("key").unwrap();
    
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
    let generator = ApiKeyGenerator::init_default_config("sk").unwrap();
    let key = generator.generate(Environment::production()).unwrap();
    let hash = key.hash();

    let wrong1 = ApiKey::new(api_keys_simplified::SecureString::from("completely_wrong_key".to_string()));
    assert!(!wrong1.verify(hash).unwrap());
    
    let wrong2 = ApiKey::new(api_keys_simplified::SecureString::from("sk_live_wrongrandomdata".to_string()));
    assert!(!wrong2.verify(hash).unwrap());
}

#[test]
fn test_key_uniqueness() {
    let generator = ApiKeyGenerator::init_default_config("sk").unwrap();
    let key1 = generator.generate(Environment::production()).unwrap();
    let key2 = generator.generate(Environment::production()).unwrap();

    assert_ne!(key1.key().as_ref(), key2.key().as_ref());
    assert_ne!(key1.hash(), key2.hash());
}

#[test]
fn test_parse_key_components() {
    let prefixes = ["a", "a_b", "a_b_"];
    for prefix in prefixes {
        let generator = ApiKeyGenerator::init_default_config(prefix).unwrap();
        let api_key = generator.generate(Environment::staging()).unwrap();
        println!("{}", api_key.key().as_ref());
        let (prefix_ans, env) = api_key.parse_key(Separator::default()).unwrap();

        assert_eq!(prefix_ans, prefix);
        assert_eq!(env, "staging");
    }
}
