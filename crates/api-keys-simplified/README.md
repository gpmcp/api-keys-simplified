# API Keys Simplified

A secure, Rust library for generating and validating API keys with built-in security best practices.

[![Crates.io](https://img.shields.io/crates/v/api-keys-simplified.svg)](https://crates.io/crates/api-keys-simplified)
[![Documentation](https://docs.rs/api-keys-simplified/badge.svg)](https://docs.rs/api-keys-simplified)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/gpmcp/api-keys-simplified/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/gpmcp/api-keys-simplified/graph/badge.svg?token=BUE7WRJ1FP)](https://codecov.io/gh/gpmcp/api-keys-simplified)

## What It Does

- **Generate** cryptographically secure API keys (192-bit entropy default)
- **Hash** keys using Argon2id (memory-hard, OWASP recommended)
- **Verify** keys with constant-time comparison (prevents timing attacks)
- **Protect** sensitive data with automatic memory zeroing

## Quick Start

### Installation

```toml
[dependencies]
api-keys-simplified = "0.1"
```

### Basic Usage

```rust
use api_keys_simplified::{ApiKey, Environment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a new API key
    let api_key = ApiKey::generate_default("gpmcp_sk", Environment::production())?;

    // 2. Show key to user ONCE (they must save it)
    println!("API Key: {}", api_key.key().as_ref());

    // 3. Store only the hash in your database
    let hash = api_key.hash();
    database::save_user_key_hash(user_id, hash)?;

    // 4. Later: verify an incoming key
    let provided_key = request.headers().get("X-API-Key")?;
    let stored_hash = database::get_user_key_hash(user_id)?;

    if ApiKey::verify(provided_key, stored_hash)? {
        // Key is valid - grant access
        handle_request(request)
    } else {
        // Key is invalid - reject
        Err("Invalid API key")
    }
}
```

### Key Format

```
prefix.environment.random_data.checksum
     │         │            │         │
     │         │            │         └─ CRC32 (optional)
     │         │            └─────────── Base64URL (192 bits)
     │         └──────────────────────── dev/test/staging/live
     └────────────────────────────────── User-defined (e.g., acme_sk, stripe_pk)
```

**Examples:**

- `gpmcp_sk.live.Xf8kP2qW9zLmN4vC8aH5tJw1bQmK3rN9.a1b2c3d4`
- `acme_api.dev.Rt7jK3pV8wNmQ2uD4fG6hLk8nPqS2uW5.e5f6g7h8`

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

- **Input Validation:** 512-byte max key length
- **Resource Limits:** Prevents hash complexity attacks
- **Fast Rejection:** Optional CRC32 checksum for malformed keys

### 🔍 Threat Model

**Protected Against:**
✅ Brute force • ✅ Timing attacks • ✅ Rainbow tables • ✅ Memory disclosure • ✅ Database breaches • ✅ GPU/ASIC attacks

**NOT Protected Against:**
❌ Compromised app server • ❌ User negligence • ❌ Network interception (use HTTPS) • ❌ Quantum computers

### Best Practices

```rust
// ✅ Never log keys (auto-redacted)
println!("{:?}", api_key);  // Prints: ApiKey { key: "[REDACTED]", ... }

// ✅ Show keys only once
let key = ApiKey::generate_default("myapp_sk", Environment::production()) ?;
display_to_user_once(key.key().as_ref());
db.save(key.hash());  // Store hash only

// ✅ Always use HTTPS
let response = client.get("https://api.example.com")
.header("X-API-Key", key.as_ref())
.send() ?;

// ✅ Implement key rotation
fn rotate_key(user_id: u64) -> Result<ApiKey> {
    let new_key = ApiKey::generate_default("client_sk", Environment::production())?;
    db.revoke_old_keys(user_id)?;
    db.save_new_hash(user_id, new_key.hash())?;
    Ok(new_key)
}

// ✅ Rate limit verification
if rate_limiter.check(ip_address).is_err() {
return Err("Too many failed attempts");
}
ApiKey::verify(provided_key, stored_hash) ?;
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
Ok(key) => println ! ("Success: {}", key.key().as_ref()),
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
