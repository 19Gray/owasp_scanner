use anyhow::Result;
use scanner_core::{ScanResult, finding::Severity};
use serde_json::{json, Value};
use std::fs;

pub fn report(result: &ScanResult, out: Option<&str>) -> Result<()> {
    let rules:   Vec<Value> = unique_rules(result);
    let results: Vec<Value> = result.findings.iter().map(|f| {
        json!({
            "ruleId": rule_id(&f.category.to_string()),
            "level": sarif_level(&f.severity),
            "message": { "text": format!("{} - {}", f.title, f.recommendation) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.file },
                    "region": {
                        "startLine": f.line,
                        "snippet": { "text": f.snippet }
                    }
                }
            }],
            "properties": {
                "severity": f.severity.to_string(),
                "category": f.category.to_string(),
            }
        })
    }).collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "owasp-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/your-org/owasp-scanner",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    let payload = serde_json::to_string_pretty(&sarif)?;

    match out {
        Some(path) => {
            fs::write(path, &payload)?;
            eprintln!("[+] SARIF report saved to: {}", path);
        }
        None => println!("{}", payload),
    }
    Ok(())
}

fn rule_id(category: &str) -> String {
    category.chars().filter(|c| c.is_alphanumeric() || *c == '-').collect()
}

fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium                    => "warning",
        Severity::Low | Severity::Info      => "note",
    }
}

fn unique_rules(result: &ScanResult) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();
    for f in &result.findings {
        let id = rule_id(&f.category.to_string());
        if seen.insert(id.clone()) {
            rules.push(json!({
                "id": id,
                "name": f.category.to_string(),
                "shortDescription": { "text": f.category.to_string() },
                "helpUri": "https://owasp.org/Top10/",
                "properties": { "tags": ["security", "owasp"] }
            }));
        }
    }
    rules
}
