use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Describes how strongly a value is supported by captured evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Read directly from the captured request or response.
    Observed,
    /// Calculated deterministically from observed data.
    Derived,
    /// Guessed by a versioned rule and potentially incorrect.
    Inferred,
    /// Not visible to the client or not understood by the current adapter.
    Unknown,
}

/// A stable locator back to the captured source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceSource {
    JsonPointer { pointer: String },
    StreamEvent { index: u64 },
    Attribute { name: String },
    ByteRange { start: u64, end: u64 },
}

/// Evidence metadata attached to every semantically meaningful IR node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub level: EvidenceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<EvidenceSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}

impl Evidence {
    #[must_use]
    pub fn observed(source: EvidenceSource) -> Self {
        Self {
            level: EvidenceLevel::Observed,
            source: Some(source),
            rule_id: None,
            confidence: Some(1.0),
        }
    }

    #[must_use]
    pub fn inferred(rule_id: impl Into<String>, confidence: f32) -> Self {
        Self {
            level: EvidenceLevel::Inferred,
            source: None,
            rule_id: Some(rule_id.into()),
            confidence: Some(confidence),
        }
    }

    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            level: EvidenceLevel::Unknown,
            source: None,
            rule_id: None,
            confidence: None,
        }
    }
}
