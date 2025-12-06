use api_keys_simplified::*;
use std::time::{Duration, Instant};

// Helper functions
fn flip_char_at(s: &str, index: usize) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if index < chars.len() {
        chars[index] = match chars[index] {
            '0' => 'f',
            'f' => '0',
            c if c.is_ascii_hexdigit() && c.is_ascii_digit() => {
                char::from_digit((c.to_digit(10).unwrap() + 1) % 10, 10).unwrap()
            }
            c if c.is_ascii_hexdigit() => ((c as u8 + 1 - b'a') % 6 + b'a') as char,
            _ => 'x',
        };
    }
    chars.iter().collect()
}

#[derive(Debug)]
struct TimingStats {
    mean: Duration,
}

fn calculate_stats(timings: &[Duration]) -> TimingStats {
    let sum: Duration = timings.iter().sum();
    let mean = sum / timings.len() as u32;

    TimingStats { mean }
}

/// Test that checksum verification uses constant-time comparison
///
/// Note: We test checksum verification (fast) rather than Argon2 verification (slow)
/// because Argon2 takes ~100ms per verification, making timing analysis impractical.
#[test]
fn test_checksum_constant_time() {
    let config = KeyConfig::default().with_checksum(true);
    let generator = ApiKeyGenerator::init("text", config, HashConfig::default()).unwrap();
    let api_key = generator.generate(Environment::production()).unwrap();
    let key_str = api_key.key().as_ref();

    // Extract base key and checksum
    // With dot separator: test.live.data.checksum (4 parts)
    // Checksum is always the last part after the final dot
    let parts: Vec<&str> = key_str.rsplitn(2, '.').collect();
    assert_eq!(parts.len(), 2, "Should have checksum");
    let correct_checksum = parts[0]; // Last part is checksum
    let base_key = parts[1]; // Everything before the last dot

    // Create test cases: checksums that differ at different positions
    let checksum_diff_0 = flip_char_at(correct_checksum, 0);
    let checksum_diff_4 = flip_char_at(correct_checksum, 4);
    let checksum_diff_7 = flip_char_at(correct_checksum, 7);
    let checksum_all_wrong = "00000000".to_string();

    let test_cases = [
        (correct_checksum, true, "correct"),
        (checksum_diff_0.as_str(), false, "first_char_diff"),
        (checksum_diff_4.as_str(), false, "middle_diff"),
        (checksum_diff_7.as_str(), false, "last_char_diff"),
        (checksum_all_wrong.as_str(), false, "all_wrong"),
    ];

    // Measure timing for each case
    let iterations = 1000;
    let mut timings: Vec<Vec<Duration>> = vec![vec![]; test_cases.len()];

    for _ in 0..iterations {
        for (i, (checksum, _expected, _desc)) in test_cases.iter().enumerate() {
            let test_key = format!("{}.{}", base_key, checksum);
            let test_api_key = ApiKey::new(SecureString::from(test_key));

            let start = Instant::now();
            let _ = test_api_key.verify_checksum();
            let elapsed = start.elapsed();

            timings[i].push(elapsed);
        }
    }

    // Calculate statistics
    let stats: Vec<TimingStats> = timings.iter().map(|times| calculate_stats(times)).collect();

    // Verify all timings are similar (constant-time behavior)
    let mean_nanos: Vec<f64> = stats.iter().map(|s| s.mean.as_nanos() as f64).collect();

    let overall_mean = mean_nanos.iter().sum::<f64>() / mean_nanos.len() as f64;

    for (i, ((_, _, desc), stat)) in test_cases.iter().zip(stats.iter()).enumerate() {
        let deviation = ((mean_nanos[i] - overall_mean).abs() / overall_mean) * 100.0;
        println!(
            "{:15} - mean: {:6.2}µs, deviation: {:5.2}%",
            desc,
            stat.mean.as_micros(),
            deviation
        );
    }

    for (i, (_, _, desc)) in test_cases.iter().enumerate() {
        let deviation = ((mean_nanos[i] - overall_mean).abs() / overall_mean) * 100.0;
        assert!(
            deviation < 5.0,
            "{} shows timing deviation of {:.2}% (threshold: 5%)",
            desc,
            deviation
        );
    }
}
