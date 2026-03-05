use once_cell::sync::Lazy;
use regex::Regex;

use crate::finding::{Finding, OwaspCategory, Severity};
use super::{Rule, apply_rules};

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "Debug mode enabled in configuration",
            severity:       Severity::High,
            recommendation: "Set DEBUG=false in production; control build profiles via environment variables.",
            pattern: Regex::new(r"(?i)(DEBUG|debug_mode)\s*[=:]\s*(true|True|1|yes)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "Weak or hard-coded secret key / API key",
            severity:       Severity::Critical,
            recommendation: "Generate a cryptographically random secret (>=32 bytes) and load it from env vars or a secrets manager.",
            pattern: Regex::new(r#"(?i)(secret_key|SECRET_KEY|api_key|API_KEY)\s*[=:]\s*["'][^"']{1,24}["']"#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "SSL/TLS certificate verification disabled",
            severity:       Severity::High,
            recommendation: "Never disable TLS verification; use a trusted CA bundle. Remove danger_accept_invalid_certs.",
            pattern: Regex::new(r"(?i)(danger_accept_invalid_certs|verify_ssl|ssl_verify|verify)\s*[=:]\s*(false|False|0|no)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "CORS configured to allow all origins (*)",
            severity:       Severity::Medium,
            recommendation: "Restrict CORS allowed_origins to known, trusted domains.",
            pattern: Regex::new(r#"(?i)(allowed_origins|cors_origin|Access-Control-Allow-Origin)\s*[=:]\s*["']?\*["']?"#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "Hard-coded empty password in source code",
            severity:       Severity::Critical,
            recommendation: "Use strong credentials stored in a vault or environment variable, never in source.",
            pattern: Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']{2}"#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "Default or well-known weak credential detected",
            severity:       Severity::High,
            recommendation: "Replace all default credentials before deploying; rotate any exposed secrets immediately.",
            pattern: Regex::new(r#"(?i)(password|passwd)\s*[=:]\s*["'](password|admin|123456|letmein|test|changeme|secret)["']"#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "Service listening on all interfaces (0.0.0.0)",
            severity:       Severity::Medium,
            recommendation: "Bind to a specific interface in production; only use 0.0.0.0 behind a firewall when strictly necessary.",
            pattern: Regex::new(r#"(?i)(bind|listen|host)\s*[=:]\s*["']?0\.0\.0\.0["']?"#).unwrap(),
        },
        Rule {
            category:       OwaspCategory::A02SecurityMisconfiguration,
            title:          "X-Frame-Options set to ALLOWALL - clickjacking risk",
            severity:       Severity::Medium,
            recommendation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
            pattern: Regex::new(r"(?i)X-Frame-Options\s*[=:]\s*ALLOWALL").unwrap(),
        },
    ]
});

pub fn scan(filepath: &str, lines: &[(usize, &str)]) -> Vec<Finding> {
    apply_rules(&RULES, filepath, lines)
}
