use std::env;
use std::fs;
use std::path::PathBuf;

use codeischeap_capture_policy::CapturePolicy;
use schemars::schema_for;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = schema_for!(CapturePolicy);
    let json = serde_json::to_string_pretty(&schema)?;

    if let Some(output) = env::args_os().nth(1) {
        let path = PathBuf::from(output);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, format!("{json}\n"))?;
    } else {
        println!("{json}");
    }

    Ok(())
}
