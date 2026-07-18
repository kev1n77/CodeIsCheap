use std::fs;
use std::path::PathBuf;

use codeischeap_desktop_api::{
    ExportPreview, ExportProfile, ExportReceipt, ExportRedaction, SupportBundlePreview,
    WorkspaceBootstrap,
};
use ts_rs::{Config, TS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let schema_path = repository.join("schemas/desktop-api/v0.1.schema.json");
    let bindings_path = repository.join("apps/desktop/src/generated/desktop-api");
    fs::create_dir_all(schema_path.parent().expect("schema path has a parent"))?;
    fs::create_dir_all(&bindings_path)?;

    let schema = schemars::schema_for!(WorkspaceBootstrap);
    let mut encoded = serde_json::to_string_pretty(&schema)?;
    encoded.push('\n');
    fs::write(schema_path, encoded)?;

    let config = Config::new()
        .with_out_dir(bindings_path)
        .with_large_int("number");
    WorkspaceBootstrap::export_all(&config)?;
    ExportProfile::export_all(&config)?;
    ExportRedaction::export_all(&config)?;
    ExportPreview::export_all(&config)?;
    ExportReceipt::export_all(&config)?;
    SupportBundlePreview::export_all(&config)?;
    Ok(())
}
