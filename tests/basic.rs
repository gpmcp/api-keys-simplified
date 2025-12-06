use api_keys_simplified::{ApiKey, Environment, Separator};

#[test]
fn test_basic_flow() {
    let key = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let key_str = key.key().as_ref();
    let hash = key.hash();

    assert!(ApiKey::verify(key_str, hash).unwrap());
    assert!(!ApiKey::verify("wrong_key", hash).unwrap());
}

#[test]
fn test_key_format() {
    let key = ApiKey::generate_default("pk", Environment::test()).unwrap();
    let key_str = key.key().as_ref();

    assert!(key_str.starts_with("pk.test."));
    assert!(key_str.len() > 20);
}

#[test]
fn test_different_environments() {
    let dev = ApiKey::generate_default("key", Environment::dev()).unwrap();
    let test = ApiKey::generate_default("key", Environment::test()).unwrap();
    let staging = ApiKey::generate_default("key", Environment::staging()).unwrap();
    let live = ApiKey::generate_default("key", Environment::production()).unwrap();

    assert!(dev.key().as_ref().contains(".dev."));
    assert!(test.key().as_ref().contains(".test."));
    assert!(staging.key().as_ref().contains(".staging."));
    assert!(live.key().as_ref().contains(".live."));
}

#[test]
fn test_verification_with_wrong_key() {
    let key = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let hash = key.hash();

    assert!(!ApiKey::verify("completely_wrong_key", hash).unwrap());
    assert!(!ApiKey::verify("sk_live_wrongrandomdata", hash).unwrap());
}

#[test]
fn test_key_uniqueness() {
    let key1 = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let key2 = ApiKey::generate_default("sk", Environment::production()).unwrap();

    assert_ne!(key1.key().as_ref(), key2.key().as_ref());
    assert_ne!(key1.hash(), key2.hash());
}

#[test]
fn test_parse_key_components() {
    let prefixes = [
        "a",
        "a_b",
        "a_b_",
    ];
    for prefix in prefixes {
        let key = ApiKey::generate_default(prefix, Environment::custom("foo".try_into().unwrap()))
            .unwrap();
        println!("{}", key.key().as_ref());
        let prefix_ans = ApiKey::parse_prefix(key.key(), Separator::default()).unwrap();
        let env = ApiKey::parse_environment(key.key(), Separator::default()).unwrap();

        assert_eq!(prefix_ans, prefix);
        assert_eq!(env, "foo");
    }
}
