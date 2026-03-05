use once_cell::sync::Lazy;
use regex::Regex;

use crate::finding::{Finding, OwaspCategory, Severity};
use super::{Rule, apply_rules};

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Use of MD5 hash - cryptographically broken",
            severity:       Severity::High,
            recommendation: "Replace MD5 with SHA-256 or SHA-3 for integrity; use Argon2 or bcrypt for passwords.",
            pattern: Regex::new(r"(?i)\b(md5|Md5|MD5)\b").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Use of SHA-1 hash - collision-vulnerable",
            severity:       Severity::High,
            recommendation: "Replace SHA-1 with SHA-256 or SHA-3.",
            pattern: Regex::new(r"(?i)\b(sha1|Sha1|SHA1|sha_1)\b").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Use of deprecated cipher: DES, RC4, or Blowfish",
            severity:       Severity::Critical,
            recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305 (available in the `ring` or `aes-gcm` crates).",
            pattern: Regex::new(r"(?i)\b(Des|DES|Rc4|RC4|Blowfish)\b").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "AES used in ECB mode - not semantically secure",
            severity:       Severity::High,
            recommendation: "Switch to AES-GCM or AES-CBC with a random IV and authentication tag.",
            pattern: Regex::new(r"(?i)(Ecb|ECB|aes.*ecb|ecb.*aes)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Non-cryptographic RNG used in security-sensitive context",
            severity:       Severity::Medium,
            recommendation: "Use rand::rngs::OsRng or ring::rand::SystemRandom for security-sensitive randomness.",
            pattern: Regex::new(r"(?i)(SmallRng|StdRng::seed_from_u64|thread_rng\(\)\.gen|rand::random)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Deprecated TLS version explicitly referenced (TLS 1.0/1.1 or SSL 2/3)",
            severity:       Severity::High,
            recommendation: "Enforce TLS 1.2 minimum (TLS 1.3 strongly preferred); remove legacy version constants.",
            pattern: Regex::new(r"(?i)(TlsV1_0|TlsV1_1|SslV2|SslV3|PROTOCOL_TLSv1\b|TLS1_0)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Hardcoded cryptographic key or IV in source",
            severity:       Severity::Critical,
            recommendation: "Load keys and IVs from a secrets manager or environment variable; never embed in source.",
            pattern: Regex::new(r#"(?i)(key|iv|nonce|salt)\s*[=:]\s*b?"[0-9a-fA-F]{16,}""#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Timing-attack risk: == operator used on secret/token/signature",
            severity:       Severity::Medium,
            recommendation: "Use a constant-time comparison such as `subtle::ConstantTimeEq` instead of ==.",
            pattern: Regex::new(r"(?i)(token|secret|password|hmac|signature)\s*==\s*").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Key size below 2048 bits",
            severity:       Severity::High,
            recommendation: "Use >=2048-bit RSA or >=256-bit ECC keys.",
            pattern: Regex::new(r"(?i)(key_size|key_length|bits)\s*[=:]\s*(512|768|1024)\b").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A04CryptographicFailures,
            title:          "Base64 encoding used on sensitive data - not encryption",
            severity:       Severity::Medium,
            recommendation: "Base64 is encoding, not encryption. Use authenticated encryption (AES-GCM) for confidential data.",
            pattern: Regex::new(r"(?i)(base64::encode|BASE64_STANDARD\.encode)\s*\(.*password|secret").unwrap(),
        },
    ]
});

pub fn scan(filepath: &str, lines: &[(usize, &str)]) -> Vec<Finding> {
    apply_rules(&RULES, filepath, lines)
}
