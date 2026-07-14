#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use codeischeap_storage::{DatabaseKeyStore, EncryptedStore, OsKeyStore};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use tempfile::tempdir;

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[test]
#[ignore = "writes a synthetic key to the ephemeral runner OS credential store"]
fn real_os_key_store_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let account = format!("ci-{}-{unique}", std::process::id());
    let key_store = OsKeyStore::new("com.codeischeap.storage-test", account)?;
    let directory = tempdir()?;
    let database_path = directory.path().join("credential-store.db");

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let first_key = key_store.load_or_create()?;
        let first = EncryptedStore::open(&database_path, first_key)?;
        first.integrity_check()?;
        drop(first);

        let loaded_key = key_store.load_or_create()?;
        let reopened = EncryptedStore::open(&database_path, loaded_key)?;
        reopened.integrity_check()?;
        Ok(())
    })();
    let cleanup = key_store.delete();
    result?;
    cleanup?;
    Ok(())
}
