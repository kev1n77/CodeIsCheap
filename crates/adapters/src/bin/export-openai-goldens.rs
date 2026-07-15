use std::fs;
use std::path::{Path, PathBuf};

use codeischeap_adapters::AdapterRegistry;
use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::CapturePolicy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    export(
        &fixtures,
        "openai-responses-capture.json",
        "openai-responses-prompt-ir.json",
    )?;
    export(
        &fixtures,
        "openai-chat-capture.json",
        "openai-chat-prompt-ir.json",
    )?;
    export(
        &fixtures,
        "anthropic-messages-sse-capture.json",
        "anthropic-messages-sse-prompt-ir.json",
    )?;
    Ok(())
}

fn export(
    fixtures: &Path,
    capture_name: &str,
    golden_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let envelope: CaptureEnvelope =
        serde_json::from_str(&fs::read_to_string(fixtures.join(capture_name))?)?;
    let sanitized = CapturePolicy::load_default()?.sanitize_envelope(envelope)?;
    let result = AdapterRegistry::default().parse(&sanitized);
    let prompt = result
        .prompt_ir
        .ok_or("fixture did not produce Prompt IR")?;
    let mut encoded = serde_json::to_string_pretty(&prompt)?;
    encoded.push('\n');
    fs::write(fixtures.join(golden_name), encoded)?;
    Ok(())
}
