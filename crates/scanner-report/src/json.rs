use anyhow::Result;
use scanner_core::ScanResult;
use std::{fs, io::{self, Write}};

pub fn report(result: &ScanResult, out: Option<&str>) -> Result<()> {
    let payload = serde_json::to_string_pretty(result)?;

    match out {
        Some(path) => {
            fs::write(path, &payload)?;
            eprintln!("[+] JSON report saved to: {}", path);
        }
        None => {
            io::stdout().write_all(payload.as_bytes())?;
            println!();
        }
    }
    Ok(())
}
