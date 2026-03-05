use colored::Colorize;
use scanner_core::{ScanResult, finding::Severity};

pub fn report(result: &ScanResult) {
    let summary = result.summary();
    let total   = result.findings.len();

    println!("\n{}", "=".repeat(70).bright_blue());
    println!("{}", "  OWASP Vulnerability Scanner - Report".bold());
    println!("  Target   : {}", result.target.cyan());
    println!("  Scanned  : {}", result.scanned_at);
    println!("  Findings : {}", color_count(total));
    println!(
        "  Summary  : {}  {}  {}  {}  {}",
        format!("CRITICAL:{}", summary.critical).red().bold(),
        format!("HIGH:{}", summary.high).red(),
        format!("MEDIUM:{}", summary.medium).yellow(),
        format!("LOW:{}", summary.low).cyan(),
        format!("INFO:{}", summary.info).white(),
    );
    println!("{}", "=".repeat(70).bright_blue());

    if result.findings.is_empty() {
        println!("\n  No issues detected.\n");
        return;
    }

    println!();
    for f in &result.findings {
        let sev_label = severity_label(&f.severity);
        println!(
            "  [{:04}] {}  {}",
            f.id,
            sev_label,
            f.category.to_string().bold()
        );
        println!("         Title   : {}", f.title.yellow());
        println!("         File    : {}:{}", f.file.underline(), f.line);
        println!("         Snippet : {}", f.snippet.dimmed());
        println!("         Fix     : {}", f.recommendation.green());
        println!();
    }
}

fn severity_label(sev: &Severity) -> colored::ColoredString {
    match sev {
        Severity::Critical => "[CRITICAL]".on_red().bold(),
        Severity::High     => "[HIGH]    ".red().bold(),
        Severity::Medium   => "[MEDIUM]  ".yellow().bold(),
        Severity::Low      => "[LOW]     ".cyan().bold(),
        Severity::Info     => "[INFO]    ".white(),
    }
}

fn color_count(n: usize) -> colored::ColoredString {
    if n == 0 { "0".green() } else { n.to_string().red() }
}
