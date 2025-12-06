use api_keys_simplified::{ApiKey, Environment};

#[test]
fn test_verification_with_invalid_hash() {
    let result = ApiKey::verify("any_key", "invalid_hash_format");
    assert!(result.is_err());
}

#[test]
fn test_different_keys_same_hash() {
    let key1 = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let key2 = ApiKey::generate_default("sk", Environment::production()).unwrap();
    
    // Different keys should not validate against each other's hashes
    assert!(!ApiKey::verify(key2.key(), key1.hash()).unwrap());
    assert!(!ApiKey::verify(key1.key(), key2.hash()).unwrap());
}

#[test]
fn test_checksum_validation() {
    let with_checksum = ApiKey::generate_default("chk", Environment::test()).unwrap();
    assert!(ApiKey::verify_checksum(with_checksum.key()).unwrap());
    
    // Corrupt the checksum
    let corrupted = format!("{}_corrupt", &with_checksum.key().as_ref()[..with_checksum.key().len() - 8]);
    assert!(!ApiKey::verify_checksum(&corrupted).unwrap());
}

#[test]
fn test_hash_uniqueness_with_same_key() {
    let hash1 = ApiKey::generate_default("sk", Environment::production()).unwrap();
    let hash2 = ApiKey::generate_default("sk", Environment::production()).unwrap();
    
    // Even with same key value, hashes should differ due to unique salts
    assert_ne!(hash1.hash(), hash2.hash());
}

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_collision_resistance() {
    use std::collections::HashSet;
    
    let mut keys = HashSet::new();
    let count = 1000;
    
    for _ in 0..count {
        let key = ApiKey::generate_default("test", Environment::test()).unwrap();
        keys.insert(key.key().to_string());
    }
    
    // All keys should be unique
    assert_eq!(keys.len(), count);
}

#[test]
fn test_key_format_consistency() {
    let key = ApiKey::generate_default("format", Environment::test()).unwrap();
    let key_str = key.key().as_ref();

    // With dot separator and checksum: format.test.data.checksum = 3 dots
    assert_eq!(key_str.matches('.').count(), 3);
    
    // Should not contain spaces or special characters except . and base64url chars (A-Za-z0-9-_)
    assert!(key_str.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.'));
}

#[test]
fn test_argon2_phc_format() {
    let key = ApiKey::generate_default("phc", Environment::test()).unwrap();
    let hash = key.hash();
    
    // Argon2 PHC format starts with $argon2id$
    assert!(hash.starts_with("$argon2id$"));
    assert!(hash.contains("$v=19$"));
    assert!(hash.contains("$m="));
    assert!(hash.contains(",t="));
    assert!(hash.contains(",p="));
}

#[test]
fn test_error_messages_dont_leak_info() {
    // Test that verification errors are generic
    let result = ApiKey::verify("test_key", "invalid_hash_format");
    assert!(result.is_err());
    
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    
    // Error message should NOT contain:
    // - "argon2" or parameter names
    // - "salt" or "hash" details  
    // - "password" or implementation details
    // - Specific format information
    assert!(!err_msg.contains("argon2"));
    assert!(!err_msg.contains("salt"));
    assert!(!err_msg.contains("parameter"));
    assert!(!err_msg.contains("PHC"));
    
    // Should be a generic error
    assert!(err_msg == "Operation failed" || err_msg == "Invalid input");
}

#[test]
fn test_oversized_input_error_is_generic() {
    let oversized_key = "a".repeat(1000);
    let result = ApiKey::verify(&oversized_key, "some_hash");
    
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "Invalid input");
    
    // Should not reveal max length or DOS prevention mechanism
    assert!(!err.to_string().contains("512"));
    assert!(!err.to_string().contains("length"));
    assert!(!err.to_string().contains("DoS"));
}
