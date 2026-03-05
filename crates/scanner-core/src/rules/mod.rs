pub mod a01;
pub mod a02;
pub mod a03;
pub mod a04;

use crate::finding::{Finding, OwaspCategory, Severity};

/// A single compiled detection rule.
pub struct Rule {
    pub category:       OwaspCategory,
    pub title:          &'static str,
    pub severity:       Severity,
    pub recommendation: &'static str,
    pub pattern:        regex::Regex,
}

/// Scan a slice of (line_number, line_text) pairs against a rule set.
pub fn apply_rules(
    rules:    &[Rule],
    filepath: &str,
    lines:    &[(usize, &str)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules {
        for (lineno, line) in lines {
            if rule.pattern.is_match(line) {
                findings.push(Finding {
                    id:             0,
                    category:       rule.category.clone(),
                    title:          rule.title.to_owned(),
                    severity:       rule.severity.clone(),
                    file:           filepath.to_owned(),
                    line:           *lineno,
                    snippet:        line.trim().to_owned(),
                    recommendation: rule.recommendation.to_owned(),
                });
            }
        }
    }
    findings
}
