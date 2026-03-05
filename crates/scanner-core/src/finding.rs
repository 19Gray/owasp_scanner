use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;

// ──────────────────────────────────────────────
//  Severity
// ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info     => write!(f, "INFO"),
            Severity::Low      => write!(f, "LOW"),
            Severity::Medium   => write!(f, "MEDIUM"),
            Severity::High     => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ──────────────────────────────────────────────
//  OWASP Category
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OwaspCategory {
    A01BrokenAccessControl,
    A02SecurityMisconfiguration,
    A03SupplyChainFailures,
    A04CryptographicFailures,
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwaspCategory::A01BrokenAccessControl      => write!(f, "A01 - Broken Access Control"),
            OwaspCategory::A02SecurityMisconfiguration => write!(f, "A02 - Security Misconfiguration"),
            OwaspCategory::A03SupplyChainFailures      => write!(f, "A03 - Software Supply Chain Failures"),
            OwaspCategory::A04CryptographicFailures    => write!(f, "A04 - Cryptographic Failures"),
        }
    }
}

// ──────────────────────────────────────────────
//  Finding
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id:             usize,
    pub category:       OwaspCategory,
    pub title:          String,
    pub severity:       Severity,
    pub file:           String,
    pub line:           usize,
    pub snippet:        String,
    pub recommendation: String,
}

// ──────────────────────────────────────────────
//  ScanResult
// ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub target:     String,
    pub scanned_at: String,
    pub findings:   Vec<Finding>,
}

impl ScanResult {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target:     target.into(),
            scanned_at: Utc::now().to_rfc3339(),
            findings:   Vec::new(),
        }
    }

    pub fn summary(&self) -> SeveritySummary {
        let mut s = SeveritySummary::default();
        for f in &self.findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High     => s.high     += 1,
                Severity::Medium   => s.medium   += 1,
                Severity::Low      => s.low      += 1,
                Severity::Info     => s.info     += 1,
            }
        }
        s
    }

    pub fn has_blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= Severity::High)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub critical: usize,
    pub high:     usize,
    pub medium:   usize,
    pub low:      usize,
    pub info:     usize,
}
