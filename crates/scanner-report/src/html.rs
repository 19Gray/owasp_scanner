use anyhow::Result;
use scanner_core::{ScanResult, finding::Severity};
use std::fs;

pub fn report(result: &ScanResult, out: Option<&str>) -> Result<()> {
    let path = out.unwrap_or("owasp-report.html");
    fs::write(path, render(result))?;
    eprintln!("[+] HTML report saved to: {}", path);
    Ok(())
}

fn sev_color(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "#e74c3c",
        Severity::High     => "#e67e22",
        Severity::Medium   => "#f1c40f",
        Severity::Low      => "#3498db",
        Severity::Info     => "#95a5a6",
    }
}

fn sev_bg(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "#fdecea",
        Severity::High     => "#fef5ec",
        Severity::Medium   => "#fefde7",
        Severity::Low      => "#eaf4fd",
        Severity::Info     => "#f5f5f5",
    }
}

fn render(result: &ScanResult) -> String {
    let summary = result.summary();

    let rows: String = result.findings.iter().map(|f| {
        let color = sev_color(&f.severity);
        let bg    = sev_bg(&f.severity);
        format!(
            r#"<tr style="background:{bg}">
  <td style="text-align:center;font-weight:bold">{id}</td>
  <td><span class="badge" style="background:{color}">{sev}</span></td>
  <td>{cat}</td>
  <td>{title}</td>
  <td><code>{file}:{line}</code></td>
  <td><code class="snippet">{snippet}</code></td>
  <td class="rec">{rec}</td>
</tr>"#,
            id      = f.id,
            sev     = f.severity,
            cat     = f.category,
            title   = escape(&f.title),
            file    = escape(&f.file),
            line    = f.line,
            snippet = escape(&f.snippet),
            rec     = escape(&f.recommendation),
        )
    }).collect();

    let body = if result.findings.is_empty() {
        r#"<div class="clean">No issues detected.</div>"#.to_owned()
    } else {
        format!(
            r#"<table>
<thead><tr>
  <th>#</th><th>Severity</th><th>Category</th><th>Title</th>
  <th>Location</th><th>Snippet</th><th>Recommendation</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"#
        )
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OWASP Scan Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",Arial,sans-serif;background:#f0f2f5;color:#222}}
header{{background:#1a1a2e;color:#fff;padding:24px 32px}}
header h1{{font-size:1.6rem;margin-bottom:4px}}
header p{{opacity:.7;font-size:.9rem}}
.summary{{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap}}
.card{{background:#fff;border-radius:8px;padding:16px 24px;min-width:120px;
       box-shadow:0 1px 4px rgba(0,0,0,.1);text-align:center}}
.card .num{{font-size:2rem;font-weight:700}}
.card .lbl{{font-size:.75rem;opacity:.6;text-transform:uppercase}}
.critical{{color:#e74c3c}}.high{{color:#e67e22}}.medium{{color:#d4ac0d}}
.low{{color:#3498db}}.info{{color:#95a5a6}}.total{{color:#1a1a2e}}
.container{{padding:0 32px 40px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
       overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);font-size:.85rem}}
th{{background:#1a1a2e;color:#fff;padding:10px 12px;text-align:left}}
td{{padding:10px 12px;border-bottom:1px solid #eee;vertical-align:top}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;color:#fff;
        font-size:.75rem;font-weight:600}}
code{{font-size:.8rem;background:#f4f4f4;padding:2px 5px;border-radius:4px}}
.snippet{{word-break:break-all}}
.rec{{font-size:.8rem;color:#27ae60}}
.clean{{text-align:center;padding:48px;font-size:1.2rem;color:#27ae60}}
</style>
</head>
<body>
<header>
  <h1>OWASP Vulnerability Scan Report</h1>
  <p>Target: {target} | Scanned: {scanned_at}</p>
</header>
<div class="summary">
  <div class="card"><div class="num total">{total}</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num critical">{critical}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num high">{high}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num medium">{medium}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num low">{low}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num info">{info}</div><div class="lbl">Info</div></div>
</div>
<div class="container">{body}</div>
</body>
</html>"#,
        target     = escape(&result.target),
        scanned_at = result.scanned_at,
        total      = result.findings.len(),
        critical   = summary.critical,
        high       = summary.high,
        medium     = summary.medium,
        low        = summary.low,
        info       = summary.info,
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
