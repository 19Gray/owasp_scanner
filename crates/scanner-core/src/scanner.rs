use std::path::Path;
use walkdir::WalkDir;
use anyhow::Result;

use crate::finding::{Finding, Severity, ScanResult};
use crate::rules::{a01, a02, a03, a04};

const SKIP_DIRS: &[&str] = &[
    ".git", "target", "node_modules", ".venv", "venv",
    "__pycache__", ".tox", "dist",
];

const SUPPORTED_EXT: &[&str] = &[
    "rs", "py", "go", "js", "ts", "java", "kt",
    "toml", "yaml", "yml", "json", "env", "cfg", "ini", "conf", "txt",
];

const SUPPORTED_NAMES: &[&str] = &[
    "Cargo.toml", "Cargo.lock", "requirements.txt",
    "Pipfile", "package.json", "go.mod", ".env",
];

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

pub fn scan_target(target: &str, min_severity: &Severity) -> Result<ScanResult> {
    let mut result = ScanResult::new(target);
    let path = Path::new(target);

    if path.is_file() {
        result.findings.extend(scan_file(target));
    } else if path.is_dir() {
        for entry in WalkDir::new(target)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !SKIP_DIRS.contains(&e.file_name().to_str().unwrap_or(""))
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let fp = entry.path().to_string_lossy().to_string();
                result.findings.extend(scan_file(&fp));
            }
        }
    } else {
        anyhow::bail!("Target not found: {}", target);
    }

    // Assign sequential IDs
    for (idx, f) in result.findings.iter_mut().enumerate() {
        f.id = idx + 1;
    }

    // Filter by minimum severity
    result.findings.retain(|f| f.severity >= *min_severity);

    Ok(result)
}

// ──────────────────────────────────────────────
//  Internal helpers
// ──────────────────────────────────────────────

fn should_scan(filepath: &str) -> bool {
    let path = Path::new(filepath);

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if SUPPORTED_NAMES.contains(&name) {
            return true;
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return SUPPORTED_EXT.contains(&ext);
    }

    false
}

fn scan_file(filepath: &str) -> Vec<Finding> {
    if !should_scan(filepath) {
        return vec![];
    }

    let content = match std::fs::read_to_string(filepath) {
        Ok(c)  => c,
        Err(_) => return vec![],
    };

    let lines: Vec<(usize, &str)> = content
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .collect();

    let mut findings = Vec::new();
    findings.extend(a01::scan(filepath, &lines));
    findings.extend(a02::scan(filepath, &lines));
    findings.extend(a03::scan(filepath, &lines));
    findings.extend(a04::scan(filepath, &lines));
    findings
}
