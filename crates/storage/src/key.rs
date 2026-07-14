use std::fmt;

use zeroize::Zeroize;

pub const DATABASE_KEY_BYTES: usize = 32;

pub struct DatabaseKey([u8; DATABASE_KEY_BYTES]);

impl DatabaseKey {
    pub fn generate() -> Result<Self, KeyStoreError> {
        let mut bytes = [0_u8; DATABASE_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| KeyStoreError::RandomUnavailable)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; DATABASE_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn expose(&self) -> &[u8; DATABASE_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKey([REDACTED])")
    }
}

impl Drop for DatabaseKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    InvalidIdentifier,
    UnsupportedPlatform,
    RandomUnavailable,
    InvalidStoredKey,
    Backend(String),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => write!(formatter, "database key identifier is invalid"),
            Self::UnsupportedPlatform => {
                write!(
                    formatter,
                    "OS credential storage is unsupported on this platform"
                )
            }
            Self::RandomUnavailable => {
                write!(formatter, "cryptographic randomness is unavailable")
            }
            Self::InvalidStoredKey => write!(formatter, "stored database key is invalid"),
            Self::Backend(_) => write!(formatter, "OS credential storage operation failed"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

pub trait DatabaseKeyStore {
    fn load_or_create(&self) -> Result<DatabaseKey, KeyStoreError>;
    fn delete(&self) -> Result<(), KeyStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsKeyStore {
    service: String,
    account: String,
}

impl OsKeyStore {
    pub fn new(
        service: impl Into<String>,
        account: impl Into<String>,
    ) -> Result<Self, KeyStoreError> {
        let service = service.into();
        let account = account.into();
        if service.trim().is_empty() || account.trim().is_empty() {
            return Err(KeyStoreError::InvalidIdentifier);
        }
        Ok(Self { service, account })
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn entry(&self) -> Result<keyring::Entry, KeyStoreError> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|error| KeyStoreError::Backend(error.to_string()))
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
impl DatabaseKeyStore for OsKeyStore {
    fn load_or_create(&self) -> Result<DatabaseKey, KeyStoreError> {
        let entry = self.entry()?;
        match entry.get_secret() {
            Ok(mut stored) => {
                if stored.len() != DATABASE_KEY_BYTES {
                    stored.zeroize();
                    return Err(KeyStoreError::InvalidStoredKey);
                }
                let mut bytes = [0_u8; DATABASE_KEY_BYTES];
                bytes.copy_from_slice(&stored);
                stored.zeroize();
                Ok(DatabaseKey::from_bytes(bytes))
            }
            Err(keyring::Error::NoEntry) => {
                let key = DatabaseKey::generate()?;
                entry
                    .set_secret(key.expose())
                    .map_err(|error| KeyStoreError::Backend(error.to_string()))?;
                Ok(key)
            }
            Err(error) => Err(KeyStoreError::Backend(error.to_string())),
        }
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(KeyStoreError::Backend(error.to_string())),
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
impl DatabaseKeyStore for OsKeyStore {
    fn load_or_create(&self) -> Result<DatabaseKey, KeyStoreError> {
        Err(KeyStoreError::UnsupportedPlatform)
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_key_debug_output_never_contains_material() {
        let key = DatabaseKey::from_bytes([0xAB; DATABASE_KEY_BYTES]);
        let debug = format!("{key:?}");

        assert_eq!(debug, "DatabaseKey([REDACTED])");
    }

    #[test]
    fn key_store_identifiers_must_be_non_empty() {
        assert_eq!(
            OsKeyStore::new("", "database"),
            Err(KeyStoreError::InvalidIdentifier)
        );
        assert_eq!(
            OsKeyStore::new("CodeIsCheap", " "),
            Err(KeyStoreError::InvalidIdentifier)
        );
    }
}
