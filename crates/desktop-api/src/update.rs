use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub configured: bool,
    pub current_version: String,
    pub available_version: Option<String>,
    pub notes: Option<String>,
    pub published_at: Option<String>,
}

impl UpdateStatus {
    #[must_use]
    pub fn unconfigured(current_version: impl Into<String>) -> Self {
        Self {
            configured: false,
            current_version: current_version.into(),
            available_version: None,
            notes: None,
            published_at: None,
        }
    }

    #[must_use]
    pub fn current(current_version: impl Into<String>) -> Self {
        Self {
            configured: true,
            current_version: current_version.into(),
            available_version: None,
            notes: None,
            published_at: None,
        }
    }

    #[must_use]
    pub fn available(
        current_version: impl Into<String>,
        available_version: impl Into<String>,
        notes: Option<String>,
        published_at: Option<String>,
    ) -> Self {
        Self {
            configured: true,
            current_version: current_version.into(),
            available_version: Some(available_version.into()),
            notes,
            published_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_status_distinguishes_configuration_and_availability() {
        assert!(!UpdateStatus::unconfigured("0.1.0").configured);
        assert_eq!(UpdateStatus::current("0.1.0").available_version, None);
        let available = UpdateStatus::available(
            "0.1.0",
            "0.2.0",
            Some("Security fixes".to_owned()),
            Some("2026-07-21T00:00:00Z".to_owned()),
        );
        assert_eq!(available.available_version.as_deref(), Some("0.2.0"));
    }
}
