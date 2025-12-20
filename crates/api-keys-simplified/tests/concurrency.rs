use api_keys_simplified::{
    ApiKeyManagerV0, Environment, HashConfig, KeyConfig, KeyStatus, SecureString,
};
use api_keys_simplified::{ExposeSecret, SecureStringExt};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_concurrent_generation_and_uniqueness() {
    // Tests: RNG thread safety, key uniqueness, synchronized starts
    let generator = Arc::new(ApiKeyManagerV0::init_default_config("sk").unwrap());
    let barrier = Arc::new(Barrier::new(10));
    let mut handles = vec![];

    for _ in 0..10 {
        let gen = Arc::clone(&generator);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier.wait(); // All threads start simultaneously
            let mut keys = Vec::new();
            for _ in 0..100 {
                let key = gen.generate(Environment::production()).unwrap();
                keys.push(key.key().expose_secret().to_string());
            }
            keys
        });
        handles.push(handle);
    }

    let mut all_keys = Vec::new();
    for handle in handles {
        all_keys.extend(handle.join().unwrap());
    }

    // Verify all 1000 keys are unique (no RNG races or collisions)
    let unique_count = all_keys
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(unique_count, all_keys.len(), "Found duplicate keys");

    // Verify random portions differ (no patterns from concurrent access)
    for i in 0..10.min(all_keys.len()) {
        for j in i + 1..10.min(all_keys.len()) {
            let parts1: Vec<&str> = all_keys[i].splitn(3, '-').collect();
            let parts2: Vec<&str> = all_keys[j].splitn(3, '-').collect();
            assert_ne!(parts1[2], parts2[2], "Random data must differ");
        }
    }
}

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_concurrent_verification_and_checksum() {
    // Tests: Argon2 thread safety, checksum verification (enabled by default), Arc-wrapped SecureString
    let config = KeyConfig::default();
    let generator = Arc::new(
        ApiKeyManagerV0::init(
            "pk",
            config,
            HashConfig::default(),
            std::time::Duration::ZERO,
        )
        .unwrap(),
    );

    // Generate test data
    let mut keys_and_hashes = Vec::new();
    for _ in 0..30 {
        let key = generator.generate(Environment::test()).unwrap();
        keys_and_hashes.push((
            key.key().expose_secret().to_string(),
            key.expose_hash().hash().to_string(),
        ));
    }
    let keys_and_hashes = Arc::new(keys_and_hashes);

    let mut handles = vec![];
    for _ in 0..5 {
        let gen = Arc::clone(&generator);
        let data = Arc::clone(&keys_and_hashes);

        let handle = thread::spawn(move || {
            let mut hash_ok = 0;
            let mut checksum_ok = 0;

            for (key_str, hash_str) in data.iter() {
                let key = SecureString::from(key_str.clone());
                // Test Argon2 verification
                if gen.verify(&key, hash_str).unwrap() == KeyStatus::Valid {
                    hash_ok += 1;
                }
                // Test checksum verification
                if gen.verify_checksum(&key).unwrap() {
                    checksum_ok += 1;
                }
            }
            (hash_ok, checksum_ok)
        });
        handles.push(handle);
    }

    for handle in handles {
        let (hash_ok, checksum_ok) = handle.join().unwrap();
        assert_eq!(hash_ok, 30, "All hash verifications should succeed");
        assert_eq!(checksum_ok, 30, "All checksum verifications should succeed");
    }
}

#[test]
fn test_clone_safety_and_config_isolation() {
    // Tests: Clone safety, different configs don't interfere, cross-verification
    let gen1 = ApiKeyManagerV0::init(
        "g1",
        KeyConfig::balanced(),
        HashConfig::balanced(),
        std::time::Duration::ZERO,
    )
    .unwrap();
    let gen2_cloned = gen1.clone();
    let gen3 = ApiKeyManagerV0::init(
        "g3",
        KeyConfig::high_security(),
        HashConfig::high_security(),
        std::time::Duration::ZERO,
    )
    .unwrap();

    let gen1 = Arc::new(gen1);
    let gen2 = Arc::new(gen2_cloned);
    let gen3 = Arc::new(gen3);

    let mut handles = vec![];

    // Thread 1: balanced config original
    handles.push({
        let gen = Arc::clone(&gen1);
        thread::spawn(move || gen.generate(Environment::production()).unwrap())
    });

    // Thread 2: balanced config clone
    handles.push({
        let gen = Arc::clone(&gen2);
        thread::spawn(move || gen.generate(Environment::production()).unwrap())
    });

    // Thread 3: high-security config
    handles.push({
        let gen = Arc::clone(&gen3);
        thread::spawn(move || gen.generate(Environment::production()).unwrap())
    });

    let key1 = handles.remove(0).join().unwrap();
    let key2 = handles.remove(0).join().unwrap();
    let key3 = handles.remove(0).join().unwrap();

    // All keys should be unique
    assert_ne!(key1.key().expose_secret(), key2.key().expose_secret());
    assert_ne!(key1.key().expose_secret(), key3.key().expose_secret());

    // Verify with own generators
    assert_eq!(
        gen1.verify(key1.key(), key1.expose_hash().hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        gen2.verify(key2.key(), key2.expose_hash().hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        gen3.verify(key3.key(), key3.expose_hash().hash()).unwrap(),
        KeyStatus::Valid
    );

    // Cross-verify clones (same config)
    assert_eq!(
        gen1.verify(key2.key(), key2.expose_hash().hash()).unwrap(),
        KeyStatus::Valid
    );
    assert_eq!(
        gen2.verify(key1.key(), key1.expose_hash().hash()).unwrap(),
        KeyStatus::Valid
    );

    // Different prefixes don't cross-verify
    assert!(key1.key().expose_secret().starts_with("g1-"));
    assert!(key2.key().expose_secret().starts_with("g1-"));
    assert!(key3.key().expose_secret().starts_with("g3-"));

    // High-security keys should be longer
    assert!(key3.key().len() > key1.key().len());
}

#[test]
#[cfg_attr(not(feature = "expensive_tests"), ignore)]
fn test_high_contention_mixed_operations() {
    // Tests: High load, mixed gen/verify operations, high-security config under stress
    let generator = Arc::new(ApiKeyManagerV0::init_high_security_config("stress").unwrap());

    let mut handles = vec![];
    for thread_id in 0..20 {
        let gen = Arc::clone(&generator);
        handles.push(thread::spawn(move || {
            for op_id in 0..10 {
                if (thread_id + op_id) % 2 == 0 {
                    // Generate key
                    let key = gen.generate(Environment::production()).unwrap();
                    assert!(key.key().len() > 0);
                } else {
                    // Generate and verify
                    let key = gen.generate(Environment::test()).unwrap();
                    assert_eq!(
                        gen.verify(key.key(), key.expose_hash().hash()).unwrap(),
                        KeyStatus::Valid
                    );
                }
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
