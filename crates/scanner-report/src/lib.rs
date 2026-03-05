pub mod console;
pub mod json;
pub mod sarif;
pub mod html;

use anyhow::Result;
use scanner_core::ScanResult;

pub enum OutputFormat {
    Console,
    Json,
    Sarif,
    Html,
}

pub fn write_report(
    result: &ScanResult,
    format: &OutputFormat,
    out:    Option<&str>,
) -> Result<()> {
    match format {
        OutputFormat::Console => console::report(result),
        OutputFormat::Json    => json::report(result, out)?,
        OutputFormat::Sarif   => sarif::report(result, out)?,
        OutputFormat::Html    => html::report(result, out)?,
    }
    Ok(())
}
