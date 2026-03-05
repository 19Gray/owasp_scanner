use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

use crate::finding::{Finding, OwaspCategory, Severity};
use super::{Rule, apply_rules};

// ── Source-code patterns ──────────────────────────────────────────────────────

static SOURCE_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule {
            category:       OwaspCategory::A03SupplyChainFailures,
            title:          "Dynamic library loading - potential supply-chain injection",
            severity:       Severity::High,
            recommendation: "Avoid loading libraries by name from untrusted input; use a static audited allow-list.",
            pattern: Regex::new(r"(?i)(libloading|dlopen|LoadLibrary|require\s*\(.*\$|import\s*\(.*\$)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A03SupplyChainFailures,
            title:          "eval() or exec() with potentially external data",
            severity:       Severity::High,
            recommendation: "Never eval/exec untrusted strings; use safe abstractions or a sandboxed interpreter.",
            pattern: Regex::new(r"(?i)\b(eval|exec)\s*\(").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A03SupplyChainFailures,
            title:          "Shell execution with string concatenation - command injection risk",
            severity:       Severity::High,
            recommendation: "Use Command::new() with explicit args; sanitise all user-supplied input before any shell call.",
            pattern: Regex::new(r"(?i)(Command::new|std::process::Command|shell_exec|popen)\s*\(.*\+").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A03SupplyChainFailures,
            title:          "Runtime HTTP fetch of executable or script",
            severity:       Severity::Medium,
            recommendation: "Verify SHA-256 checksums and signatures for any remotely fetched artifacts before execution.",
            pattern: Regex::new(r#"(?i)(reqwest|ureq|curl|wget).*\.(sh|exe|dll|so|py|rb)\b"#).unwrap(),
        },
    ]
});

// ── Known-vulnerable crate versions ──────────────────────────────────────────

static VULNERABLE_CRATES: Lazy<HashMap<&'static str, Vec<(&'static str, Severity, &'static str)>>> =
    Lazy::new(|| {
        let mut m: HashMap<&str, Vec<_>> = HashMap::new();
        m.insert("openssl", vec![
            ("0.9.",    Severity::Critical, "openssl 0.9.x - multiple memory-safety CVEs"),
            ("0.10.24", Severity::High,     "openssl 0.10.24 - CVE-2021-3711 buffer overflow"),
        ]);
        m.insert("hyper", vec![
            ("0.14.1",  Severity::Medium,   "hyper 0.14.1 - header injection risk"),
        ]);
        m.insert("actix-web", vec![
            ("1.",      Severity::High,     "actix-web 1.x - EOL, known vulnerability surface"),
        ]);
        m.insert("tokio", vec![
            ("1.0.0",   Severity::Medium,   "tokio 1.0.0 - CVE-2021-45710 data race"),
        ]);
        m.insert("reqwest", vec![
            ("0.10.0",  Severity::Medium,   "reqwest 0.10.0 - TLS downgrade possible"),
        ]);
        m.insert("ring", vec![
            ("0.16.11", Severity::High,     "ring 0.16.11 - ECDSA side-channel vulnerability"),
        ]);
        m.insert("diesel", vec![
            ("1.",      Severity::Medium,   "diesel 1.x - EOL; missing security patches"),
        ]);
        m
    });

// ── Cargo.toml / Cargo.lock scanning ─────────────────────────────────────────

static UNPINNED_RE:  Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*[\w\-]+\s*=\s*"\*""#).unwrap());
static WILDCARD_RE:  Lazy<Regex> = Lazy::new(|| Regex::new(r#""(\*|>=\s*\d)"#).unwrap());
static DEP_LINE_RE:  Lazy<Regex> = Lazy::new(|| Regex::new(r#"^\s*([\w\-]+)\s*=\s*"([^"]+)""#).unwrap());

fn scan_cargo_toml(filepath: &str, lines: &[(usize, &str)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (lineno, line) in lines {
        // Wildcard / unpinned version
        if UNPINNED_RE.is_match(line) || WILDCARD_RE.is_match(line) {
            findings.push(Finding {
                id:             0,
                category:       OwaspCategory::A03SupplyChainFailures,
                title:          "Unpinned or wildcard dependency version".to_owned(),
                severity:       Severity::Medium,
                file:           filepath.to_owned(),
                line:           *lineno,
                snippet:        line.trim().to_owned(),
                recommendation: "Pin every dependency to an exact version and commit Cargo.lock to VCS.".to_owned(),
            });
            continue;
        }

        // Known-vulnerable crate check
        if let Some(cap) = DEP_LINE_RE.captures(line) {
            let name    = cap.get(1).map(|m| m.as_str()).unwrap_or("").to_lowercase();
            let version = cap.get(2).map(|m| m.as_str()).unwrap_or("");

            if let Some(vuln_list) = VULNERABLE_CRATES.get(name.as_str()) {
                for (bad_prefix, severity, desc) in vuln_list {
                    if version.starts_with(bad_prefix) {
                        findings.push(Finding {
                            id:             0,
                            category:       OwaspCategory::A03SupplyChainFailures,
                            title:          format!("Known-vulnerable crate: {}={}", name, version),
                            severity:       severity.clone(),
                            file:           filepath.to_owned(),
                            line:           *lineno,
                            snippet:        format!("{} => {}", line.trim(), desc),
                            recommendation: "Upgrade to the latest stable release and review the advisory.".to_owned(),
                        });
                    }
                }
            }
        }
    }

    findings
}

pub fn scan(filepath: &str, lines: &[(usize, &str)]) -> Vec<Finding> {
    let fname = std::path::Path::new(filepath)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if fname == "Cargo.toml" || fname == "Cargo.lock" {
        return scan_cargo_toml(filepath, lines);
    }

    apply_rules(&SOURCE_RULES, filepath, lines)
}
