use once_cell::sync::Lazy;
use regex::Regex;

use crate::finding::{Finding, OwaspCategory, Severity};
use super::{Rule, apply_rules};

static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Overly permissive file permissions (chmod 777)",
            severity:       Severity::High,
            recommendation: "Use least-privilege permissions (e.g. 0o640 for files, 0o750 for dirs).",
            pattern: Regex::new(r"(?i)chmod\s*\(.*0o?777").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Hard-coded bypass-auth or allow-all flag set to true",
            severity:       Severity::Critical,
            recommendation: "Remove bypass flags and enforce role-based access control on every endpoint.",
            pattern: Regex::new(r"(?i)(allow_all|ALLOW_ALL|permit_all|bypass_auth)\s*=\s*(true|True|1)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Route or handler defined without visible auth guard",
            severity:       Severity::Medium,
            recommendation: "Add an authentication middleware or guard to every non-public route.",
            pattern: Regex::new(r"(?i)(#\[get|#\[post|#\[put|#\[delete|#\[patch|app\.route|router\.(get|post|put|delete))").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Role or privilege derived directly from user-supplied request data",
            severity:       Severity::Critical,
            recommendation: "Never trust client-supplied role data; read it from the server-side session or JWT claims.",
            pattern: Regex::new(r"(?i)(is_admin|isAdmin|role|privilege)\s*=\s*.*(request|req|params|query|body|form)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Possible IDOR - direct object reference via user input in SQL query",
            severity:       Severity::High,
            recommendation: "Validate object ownership before accessing records; never trust raw user-supplied IDs.",
            pattern: Regex::new(r"(?i)(SELECT|UPDATE|DELETE).*WHERE.*id\s*=\s*\$?(req|request|params|user_id)").unwrap(),
        },
        Rule {
            category:       OwaspCategory::A01BrokenAccessControl,
            title:          "Path traversal pattern detected in file access",
            severity:       Severity::High,
            recommendation: "Canonicalize paths and validate they remain within the intended root directory.",
            pattern: Regex::new(r#"(?i)(open|read_to_string|File::open)\s*\(.*(\.\./|\.\.\\)"#).unwrap(),
        },
    ]
});

pub fn scan(filepath: &str, lines: &[(usize, &str)]) -> Vec<Finding> {
    apply_rules(&RULES, filepath, lines)
}
