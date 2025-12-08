# API Keys Simplified

A secure, Rust library for generating and validating API keys with built-in security best practices.

[![Crates.io](https://img.shields.io/crates/v/api-keys-simplified.svg)](https://crates.io/crates/api-keys-simplified)
[![Documentation](https://docs.rs/api-keys-simplified/badge.svg)](https://docs.rs/api-keys-simplified)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/gpmcp/api-keys-simplified/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/gpmcp/api-keys-simplified/graph/badge.svg?token=BUE7WRJ1FP)](https://codecov.io/gh/gpmcp/api-keys-simplified)

## What It Does

- **Generate** cryptographically secure API keys (192-bit entropy default)
- **Hash** keys using Argon2id (memory-hard, OWASP recommended)
- **Checksum** keys with BLAKE3 for fast DoS protection (2900x speedup)
- **Verify** keys with constant-time comparison (prevents timing attacks)
- **Protect** sensitive data with automatic memory zeroing
- **Expire** keys automatically based on embedded timestamps
- **Revoke** keys instantly by marking hashes as invalid

## Quick Start

### Installation

```toml
[dependencies]
api-keys-simplified = "0.1"
```

### Basic Usage

```rust
use api_keys_simplified::{ApiKeyManager, Environment, KeyConfig, HashConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize with checksum (out of the box DoS protection)
    let manager = ApiKeyManager::init_default_config("gpmcp_sk")?;
    
    // 2. Generate a new API key
    let api_key = manager.generate(Environment::production())?;

    // 3. Show key to user ONCE (they must save it)
    println!("API Key: {}", api_key.key().expose_secret());

    // 4. Store only the hash in your database
    database::save_user_key_hash(user_id, api_key.hash())?;

    // 5. Later: verify an incoming key (checksum validated first!)
    let provided_key = request.headers().get("X-API-Key")?;
    let stored_hash = database::get_user_key_hash(user_id)?;

    match manager.verify(&provided_key, &stored_hash)? {
        KeyStatus::Valid => {
            // Key is valid - grant access
            handle_request(request)
        }
        KeyStatus::Invalid => {
            // Key is invalid or revoked - rejected in ~20μs (not ~300ms)
            Err("Invalid API key")
        }
        KeyStatus::Expired => {
            // Key has expired
            Err("API key expired")
        }
    }
}
```

### Key Format

```
prefix[-version]-environment-random_data[.expiry][.checksum]
     │     │           │            │       │         │
     │     │           │            │       │         └─ BLAKE3 (recommended, 16 hex chars)
     │     │           │            │       └─────────── Optional: 11-char base64url timestamp
     │     │           │            └─────────────────── Base64URL (192 bits default)
     │     │           └──────────────────────────────── dev/test/staging/live
     │     └──────────────────────────────────────────── Optional: vN (v1, v2, etc.)
     └────────────────────────────────────────────────── User-defined (e.g., acme_sk, stripe_pk)
```

**Examples:**

- Unversioned (default): `gpmcp_sk-live-Xf8kP2qW9zLmN4vC8aH5tJw1bQmK3rN9.a1b2c3d4e5f6g7h8`
- With version: `gpmcp_sk-v1-live-Xf8kP2qW9zLmN4vC8aH5tJw1bQmK3rN9.a1b2c3d4e5f6g7h8`
- With expiry: `acme_api-dev-Rt7jK3pV8wNmQ2uD4fG6hLk8nPqS2uW5.AAAAAGldxGE.9f8e7d6c5b4a3210`
- Full format: `api-v2-live-Rt7jK3pV8wNmQ2uD4fG6hLk8nPqS2uW5.AAAAAGldxGE.9f8e7d6c5b4a3210`

**Checksum provides:**
- 2900x faster rejection of invalid keys
- DoS protection against malformed requests
- Integrity verification before expensive Argon2

**Expiration provides:**
- Time-based access control (trial keys, temporary access)
- Stateless expiry (no database cleanup needed)
- Automatic rejection after timestamp

**Versioning provides:**
- Gradual migration between key formats
- Clear identification of key format version
- Backward compatibility (version 0 = unversioned)
- Future-proof format evolution

## Why Use This?

Common API key security mistakes:

❌ Weak random number generators → Predictable keys  
❌ Plaintext storage → Database breach = total compromise  
❌ Vulnerable hashing (MD5, SHA1) → Easy to crack  
❌ Timing-vulnerable comparisons → Leaks key information  
❌ Keys lingering in memory → Core dumps expose secrets

**This library solves all of these with secure defaults and minimal code.**

## Security Features

### 🔒 Cryptographic Strength

- **RNG:** OS-level CSPRNG via `getrandom` crate
- **Hashing:** Argon2id (Password Hashing Competition winner)
- **Entropy:** 192 bits default (NIST compliant through 2030+)
- **Memory-Hard:** Prevents GPU/ASIC brute force attacks

### 🛡️ Side-Channel Protection

- **Constant-Time Comparison:** Via `subtle` crate (timing-attack resistant)
- **No Early Returns:** Same verification time regardless of key differences
- **Memory Hardness:** Argon2 prevents cache-timing attacks

### 🔐 Memory Safety

- **Auto-Zeroing:** `SecureString` clears memory on drop via `zeroize` crate
- **No Accidental Logging:** Custom `Debug` impl redacts keys
- **Explicit Access:** No `Deref` trait (prevents silent leaks)

### 📊 DoS Protection

- **BLAKE3 Checksums:** Invalid keys rejected in ~20μs (vs ~300ms Argon2)
- **2900x Speedup:** Dramatically reduces DoS attack surface
- **Input Validation:** 512-byte max key length
- **Resource Limits:** Prevents hash complexity attacks

**Performance Comparison (10 invalid keys):**
- ✅ With checksum: 0ms (fast rejection)
- ❌ Without checksum: 2907ms (all Argon2)

### 🔍 Threat Model

**Protected Against:**
✅ Brute force • ✅ Timing attacks • ✅ Rainbow tables • ✅ Memory disclosure • ✅ Database breaches • ✅ GPU/ASIC attacks

**NOT Protected Against:**
❌ Compromised app server • ❌ User negligence • ❌ Network interception (use HTTPS) • ❌ Quantum computers

### Best Practices

```rust
use api_keys_simplified::{ApiKeyManager, Environment, KeyConfig, HashConfig, KeyStatus};

// ✅ Checksums enabled by default (DoS protection - use .disable_checksum() to turn off)
let manager = ApiKeyManager::init_default_config("myapp_sk")?;

// ✅ Never log keys (auto-redacted)
let key = manager.generate(Environment::production())?;
println!("{:?}", key);  // Prints: ApiKey { key: "[REDACTED]", ... }

// ✅ Show keys only once
display_to_user_once(key.key().expose_secret());
db.save(key.hash());  // Store hash only

// ✅ Always use HTTPS
let response = client.get("https://api.example.com")
    .header("X-API-Key", key.key().expose_secret())
    .send()?;

// ✅ Implement key rotation
fn rotate_key(manager: &ApiKeyManager, user_id: u64) -> Result<ApiKey> {
    let new_key = manager.generate(Environment::production())?;
    db.revoke_old_keys(user_id)?;
    db.save_new_hash(user_id, new_key.hash())?;
    Ok(new_key)
}

// ✅ Use expiration for temporary access (trials, partners)
let trial_expiry = Utc::now() + Duration::days(7);
let trial_key = manager.generate_with_expiry(Environment::production(), trial_expiry)?;
db.save(user_id, trial_key.hash())?;

// ✅ Implement key revocation for compromised keys
fn revoke_key(user_id: u64, key_hash: &str) -> Result<()> {
    // Mark hash as revoked in database
    db.mark_revoked(user_id, key_hash)?;
    Ok(())
}

// ✅ Check revocation status during verification
fn verify_with_revocation(manager: &ApiKeyManager, key: &SecureString, user_id: u64) -> Result<bool> {
    let stored_hash = db.get_user_key_hash(user_id)?;
    
    // Check if key is revoked first (fast database check)
    if db.is_revoked(user_id, &stored_hash)? {
        return Ok(false);
    }
    
    // Then verify key status
    match manager.verify(key, &stored_hash)? {
        KeyStatus::Valid => Ok(true),
        KeyStatus::Invalid | KeyStatus::Expired => Ok(false),
    }
}

// ✅ Rate limit verification (still important with checksums)
if rate_limiter.check(ip_address).is_err() {
    return Err("Too many failed attempts");
}
manager.verify(provided_key, stored_hash)?;
```

## Performance

| Preset             | Memory | Time   | Verification |
|--------------------|--------|--------|--------------|
| Balanced (default) | 19 MB  | 2 iter | ~50ms        |
| High Security      | 64 MB  | 3 iter | ~150ms       |

**Note:** Slow verification is intentional—it prevents brute force attacks.

## Testing

```bash
cargo test                              # All tests
cargo test --features expensive_tests  # Include timing analysis
```

## Error Handling

```rust
use api_keys_simplified::{ApiKey, Error};

match ApiKey::generate_default("", Environment::production()) {
Ok(key) => println ! ("Success: {}", key.key().expose_secret()),
Err(Error::InvalidConfig(msg)) => eprintln ! ("Config error: {}", msg),
Err(Error::InvalidFormat) => eprintln ! ("Invalid key format"),
Err(Error::HashingFailed(msg)) => eprintln ! ("Hashing error: {}", msg),
Err(e) => eprintln ! ("Error: {}", e),
}
```

**Error messages are intentionally generic** to prevent information leakage.

## Comparison

| Feature                | api-keys-simplified | uuid | nanoid   |
|------------------------|---------------------|------|----------|
| Cryptographic security | ✅ Argon2id          | ❌    | ⚠️ Basic |
| Hashed storage         | ✅ Built-in          | ❌    | ❌        |
| Constant-time verify   | ✅ Yes               | ❌    | ❌        |
| Memory protection      | ✅ Auto-zeroing      | ❌    | ❌        |
| Structured format      | ✅ prefix.env.data   | ❌    | ❌        |

## License

Licensed under the [Apache License, Version 2.0](https://github.com/gpmcp/api-keys-simplified/blob/main/LICENSE).

## Dependencies

All cryptographic implementations use well-audited crates:

- [`argon2`](https://crates.io/crates/argon2) - Official Argon2 implementation
- [`subtle`](https://crates.io/crates/subtle) - Constant-time primitives
- [`zeroize`](https://crates.io/crates/zeroize) - Secure memory zeroing
- [`getrandom`](https://crates.io/crates/getrandom) - OS-level CSPRNG

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) - Digital Identity Guidelines
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) - Argon2 Specification

## Reporting Vulnerabilities

Email security issues to: [sandip@ssdd.dev](mailto:sandip@ssdd.dev)


## Progress

- [x] Key expiration support
- [x] Key revocation support (via database hash marking)
- [x] Key versioning
- [x] Fix timing attack in dummy_load
- [x] Zero all intermediate string allocations
- [ ] Write e2e tests to ensure memory zeroization
- [ ] Write e2e tests to verify prevention of side-channel attacks

Contributions welcome! See [CONTRIBUTING.md](https://github.com/gpmcp/api-keys-simplified/blob/main/CONTRIBUTING.md) for guidelines.
