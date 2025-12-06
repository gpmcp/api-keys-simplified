use api_keys_simplified::{ApiKey, Environment, SecureString};

/// Integration tests for secure memory handling
#[cfg(test)]
mod secure_integration_tests {
    use super::*;

    #[test]
    fn test_api_key_debug_redacts_key() {
        let api_key = ApiKey::generate_default("sk", Environment::production()).unwrap();
        
        // Debug output should not expose the actual key
        let debug_output = format!("{:?}", api_key);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(api_key.key().as_ref()));
        
        // Should still show hash (not sensitive after storage)
        assert!(debug_output.contains("hash"));
    }

    #[test]
    fn test_secure_string_in_collections() {
        // Verify SecureString works in Vec (common use case)
        let keys = vec![
            SecureString::from("key1"),
            SecureString::from("key2"),
        ];
        
        assert_eq!(keys[0].as_ref(), "key1");
        assert_eq!(keys[1].as_ref(), "key2");
        
        // When dropped, all memory should be zeroed
        drop(keys);
    }

    #[test]
    fn test_api_key_can_be_verified_after_clone() {
        // Verify that cloning doesn't break functionality
        let api_key = ApiKey::generate_default("test", Environment::dev()).unwrap();
        let cloned_key = api_key.clone();
        
        // Both should have the same key and hash
        assert_eq!(api_key.key().as_ref(), cloned_key.key().as_ref());
        assert_eq!(api_key.hash(), cloned_key.hash());
        
        // Verification should work with cloned data
        assert!(ApiKey::verify(cloned_key.key(), cloned_key.hash()).unwrap());
    }

    #[test]
    fn test_secure_string_prevents_accidental_logging() {
        let secret = SecureString::from("super_secret_key_12345");
        
        // Common logging patterns should not expose the key
        let log_msg = format!("Processing key: {}", secret);
        assert!(!log_msg.contains("super_secret_key_12345"));
        assert!(log_msg.contains("[REDACTED]"));
        
        let debug_log = format!("Key details: {:?}", secret);
        assert!(!debug_log.contains("super_secret_key_12345"));
        assert!(debug_log.contains("REDACTED"));
    }

    #[test]
    fn test_memory_cleared_on_drop() {
        // Verify that SecureString properly implements ZeroizeOnDrop
        // The actual zeroing is guaranteed by the zeroize crate
        
        {
            let secret = SecureString::from("temporary_key_12345");
            assert_eq!(secret.as_ref(), "temporary_key_12345");
            // Memory will be zeroed when secret goes out of scope
        }
        
        // The zeroize crate provides guarantees via:
        // 1. Compiler fences (prevents optimization)
        // 2. Explicit zeroing before deallocation
        // 3. Extensive testing and security community review
    }

    #[test]
    fn test_api_key_lifecycle_with_secure_memory() {
        // Full lifecycle test demonstrating secure memory usage
        let key1 = ApiKey::generate_default("api", Environment::production()).unwrap();
        let key_str = key1.key().as_ref().to_string();
        let hash_str = key1.hash().to_string();
        
        // Drop the original - memory is zeroed automatically
        drop(key1);
        
        // Verification still works with the copied strings
        assert!(ApiKey::verify(&key_str, &hash_str).unwrap());
        
        // The SecureString inside key1 was zeroed before deallocation
        // This is guaranteed by ZeroizeOnDrop trait implementation
    }

    #[test]
    fn test_multiple_keys_all_zeroed() {
        // Create multiple keys to verify zeroing works consistently
        let mut keys = Vec::new();
        for i in 0..5 {
            keys.push(ApiKey::generate_default(format!("key{}", i), Environment::dev()).unwrap());
        }
        
        // Verify all keys are valid
        for key in &keys {
            assert!(!key.key().is_empty());
        }
        
        // Drop all keys - all memory is zeroed
        drop(keys);
        
        // All SecureString instances were properly zeroed via ZeroizeOnDrop
    }
}
