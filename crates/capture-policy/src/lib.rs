//! Shared scope and credential policy enforced by capture sidecars and Core.

use std::collections::HashSet;
use std::fmt;

use codeischeap_capture_ipc::{
    CaptureEnvelope, CaptureRedaction, CapturedField, CapturedRequest, RedactionLocation,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CAPTURE_POLICY_VERSION: &str = "0.1";
pub const DEFAULT_POLICY_JSON: &str = include_str!("../../../policies/capture-policy.v0.1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturePolicy {
    pub version: String,
    pub targets: Vec<CaptureTarget>,
    pub sensitive_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTarget {
    pub id: String,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedCapture {
    envelope: CaptureEnvelope,
    target_id: String,
    newly_redacted: usize,
}

impl SanitizedCapture {
    #[must_use]
    pub const fn envelope(&self) -> &CaptureEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub const fn newly_redacted(&self) -> usize {
        self.newly_redacted
    }

    #[must_use]
    pub fn into_envelope(self) -> CaptureEnvelope {
        self.envelope
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidJson(String),
    UnsupportedVersion(String),
    EmptyTargets,
    InvalidTarget(String),
    DuplicateTarget(String),
    InvalidSensitiveName(String),
    DuplicateSensitiveName(String),
    OutOfScope,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(_) => write!(formatter, "capture policy JSON is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "capture policy version {version} is unsupported")
            }
            Self::EmptyTargets => write!(formatter, "capture policy has no targets"),
            Self::InvalidTarget(id) => write!(formatter, "capture target {id} is invalid"),
            Self::DuplicateTarget(id) => write!(formatter, "capture target {id} is duplicated"),
            Self::InvalidSensitiveName(name) => {
                write!(formatter, "sensitive field name {name} is invalid")
            }
            Self::DuplicateSensitiveName(name) => {
                write!(formatter, "sensitive field name {name} is duplicated")
            }
            Self::OutOfScope => write!(formatter, "capture request is outside the active policy"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl CapturePolicy {
    pub fn load_default() -> Result<Self, PolicyError> {
        Self::from_json(DEFAULT_POLICY_JSON)
    }

    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_json::from_str(json)
            .map_err(|error| PolicyError::InvalidJson(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != CAPTURE_POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(self.version.clone()));
        }
        if self.targets.is_empty() {
            return Err(PolicyError::EmptyTargets);
        }

        let mut target_ids = HashSet::new();
        for target in &self.targets {
            if !target_ids.insert(target.id.as_str()) {
                return Err(PolicyError::DuplicateTarget(target.id.clone()));
            }
            if target.id.is_empty()
                || target.hosts.is_empty()
                || target.methods.is_empty()
                || target.paths.is_empty()
                || target.hosts.iter().any(|host| !valid_host(host))
                || target.methods.iter().any(|method| !valid_method(method))
                || target.paths.iter().any(|path| !valid_path_pattern(path))
            {
                return Err(PolicyError::InvalidTarget(target.id.clone()));
            }
        }

        let mut sensitive_names = HashSet::new();
        for name in &self.sensitive_names {
            let normalized = normalize_name(name);
            if normalized.is_empty() {
                return Err(PolicyError::InvalidSensitiveName(name.clone()));
            }
            if !sensitive_names.insert(normalized) {
                return Err(PolicyError::DuplicateSensitiveName(name.clone()));
            }
        }
        Ok(())
    }

    pub fn matching_target<'a>(&'a self, request: &CapturedRequest) -> Option<&'a CaptureTarget> {
        let host = normalize_host(&request.host);
        self.targets.iter().find(|target| {
            target.hosts.iter().any(|allowed| allowed == &host)
                && target
                    .methods
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(&request.method))
                && target
                    .paths
                    .iter()
                    .any(|pattern| wildcard_match(pattern, &request.path))
        })
    }

    pub fn sanitize_envelope(
        &self,
        mut envelope: CaptureEnvelope,
    ) -> Result<SanitizedCapture, PolicyError> {
        self.validate()?;
        let target_id = self
            .matching_target(&envelope.request)
            .map(|target| target.id.clone())
            .ok_or(PolicyError::OutOfScope)?;
        let sensitive_names: HashSet<String> = self
            .sensitive_names
            .iter()
            .map(|name| normalize_name(name))
            .collect();
        let mut newly_redacted = 0;

        scrub_fields(
            &mut envelope.request.headers,
            RedactionLocation::Header,
            &sensitive_names,
            &mut envelope.redactions,
            &mut newly_redacted,
        );
        scrub_fields(
            &mut envelope.request.query,
            RedactionLocation::Query,
            &sensitive_names,
            &mut envelope.redactions,
            &mut newly_redacted,
        );
        if let Some(content) = envelope.request.body.content.as_mut() {
            scrub_json(
                content,
                &sensitive_names,
                &mut envelope.redactions,
                &mut newly_redacted,
            );
        }

        Ok(SanitizedCapture {
            envelope,
            target_id,
            newly_redacted,
        })
    }

    pub fn is_sensitive_name(&self, name: &str) -> bool {
        let normalized = normalize_name(name);
        self.sensitive_names
            .iter()
            .any(|candidate| normalize_name(candidate) == normalized)
    }
}

fn scrub_fields(
    fields: &mut Vec<CapturedField>,
    location: RedactionLocation,
    sensitive_names: &HashSet<String>,
    redactions: &mut Vec<CaptureRedaction>,
    newly_redacted: &mut usize,
) {
    fields.retain(|field| {
        if sensitive_names.contains(&normalize_name(&field.name)) {
            redactions.push(CaptureRedaction {
                location,
                name: field.name.clone(),
            });
            *newly_redacted += 1;
            false
        } else {
            true
        }
    });
}

fn scrub_json(
    value: &mut serde_json::Value,
    sensitive_names: &HashSet<String>,
    redactions: &mut Vec<CaptureRedaction>,
    newly_redacted: &mut usize,
) {
    match value {
        serde_json::Value::Object(object) => {
            let removed: Vec<String> = object
                .keys()
                .filter(|name| sensitive_names.contains(&normalize_name(name)))
                .cloned()
                .collect();
            for name in removed {
                object.remove(&name);
                redactions.push(CaptureRedaction {
                    location: RedactionLocation::Body,
                    name,
                });
                *newly_redacted += 1;
            }
            for child in object.values_mut() {
                scrub_json(child, sensitive_names, redactions, newly_redacted);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_json(item, sensitive_names, redactions, newly_redacted);
            }
        }
        _ => {}
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host == normalize_host(host)
        && !host.contains(['/', '*', ' ', '\t', '\r', '\n'])
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
        && !method.contains(' ')
}

fn valid_path_pattern(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['?', '#', '\r', '\n'])
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pattern_index, mut text_index) = (0, 0);
    let (mut star_index, mut retry_text_index) = (None, 0);

    while text_index < text.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == text[text_index] {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            retry_text_index = text_index;
        } else if let Some(star) = star_index {
            retry_text_index += 1;
            text_index = retry_text_index;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_patterns_are_anchored() {
        assert!(wildcard_match(
            "/v1beta/models/*:generateContent",
            "/v1beta/models/gemini-pro:generateContent"
        ));
        assert!(!wildcard_match(
            "/v1beta/models/*:generateContent",
            "/prefix/v1beta/models/gemini-pro:generateContent"
        ));
        assert!(!wildcard_match(
            "/v1beta/models/*:generateContent",
            "/v1beta/models/gemini-pro:streamGenerateContent"
        ));
    }
}
