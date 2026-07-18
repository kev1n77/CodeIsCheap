//! Shared scope and credential policy enforced by capture sidecars and Core.

use std::collections::HashSet;
use std::fmt;

use codeischeap_capture_ipc::{
    AttributionConfidence, AttributionSource, CLIENT_LABEL_HEADER, CaptureAttribution,
    CaptureEnvelope, CaptureOutcome, CaptureRedaction, CaptureSource, CapturedField,
    CapturedRequest, RedactionLocation,
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
    #[serde(default)]
    pub attribution: AttributionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTarget {
    pub id: String,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionPolicy {
    pub client_label_header: String,
    pub max_label_bytes: usize,
    pub user_agents: Vec<UserAgentRule>,
    pub gateway_fallback: String,
    pub proxy_fallback: String,
}

impl Default for AttributionPolicy {
    fn default() -> Self {
        Self {
            client_label_header: CLIENT_LABEL_HEADER.to_owned(),
            max_label_bytes: 64,
            user_agents: vec![
                user_agent_rule("Cursor", &["cursor/", "cursor "]),
                user_agent_rule("VS Code", &["vscode/", "visual studio code"]),
                user_agent_rule("Claude Code", &["claude-code", "claude code"]),
                user_agent_rule("Codex CLI", &["codex-cli", "openai-codex", "codex/"]),
                user_agent_rule(
                    "JetBrains",
                    &["jetbrains", "intellij", "pycharm", "webstorm"],
                ),
                user_agent_rule("Microsoft Edge", &["edg/"]),
                user_agent_rule("Google Chrome", &["chrome/"]),
                user_agent_rule("Mozilla Firefox", &["firefox/"]),
                user_agent_rule("Apple Safari", &["safari/"]),
                user_agent_rule("curl", &["curl/"]),
                user_agent_rule("Python", &["python-requests/", "aiohttp/"]),
                user_agent_rule("Node.js", &["node-fetch", "undici"]),
            ],
            gateway_fallback: "Gateway client".to_owned(),
            proxy_fallback: "Proxy client".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserAgentRule {
    pub application: String,
    pub contains: Vec<String>,
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
    InvalidAttribution(String),
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
            Self::InvalidAttribution(detail) => {
                write!(formatter, "capture attribution policy is invalid: {detail}")
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
        self.validate_attribution_policy()?;
        Ok(())
    }

    fn validate_attribution_policy(&self) -> Result<(), PolicyError> {
        let attribution = &self.attribution;
        if attribution.client_label_header != CLIENT_LABEL_HEADER {
            return Err(PolicyError::InvalidAttribution(
                "client label header is unsupported".to_owned(),
            ));
        }
        if attribution.max_label_bytes == 0 || attribution.max_label_bytes > 128 {
            return Err(PolicyError::InvalidAttribution(
                "client label size is out of range".to_owned(),
            ));
        }
        if !valid_application_label(&attribution.gateway_fallback, attribution.max_label_bytes)
            || !valid_application_label(&attribution.proxy_fallback, attribution.max_label_bytes)
        {
            return Err(PolicyError::InvalidAttribution(
                "fallback application label is invalid".to_owned(),
            ));
        }
        for rule in &attribution.user_agents {
            if !valid_application_label(&rule.application, attribution.max_label_bytes)
                || rule.contains.is_empty()
                || rule.contains.iter().any(|pattern| {
                    pattern.is_empty()
                        || pattern.len() > 128
                        || pattern != &pattern.to_ascii_lowercase()
                })
            {
                return Err(PolicyError::InvalidAttribution(
                    "user-agent rule is invalid".to_owned(),
                ));
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

        if let Some(attribution) = envelope.attribution.as_ref() {
            if !valid_application_label(&attribution.application, self.attribution.max_label_bytes)
                || attribution.process_id == Some(0)
            {
                return Err(PolicyError::InvalidAttribution(
                    "capture attribution is invalid".to_owned(),
                ));
            }
        } else {
            envelope.attribution =
                Some(self.attribution_for(envelope.source, &envelope.request.headers));
        }
        envelope.request.headers.retain(|field| {
            !field
                .name
                .eq_ignore_ascii_case(&self.attribution.client_label_header)
        });

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
                RedactionLocation::Body,
                &sensitive_names,
                &mut envelope.redactions,
                &mut newly_redacted,
            );
        }
        if let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() {
            scrub_fields(
                &mut response.headers,
                RedactionLocation::ResponseHeader,
                &sensitive_names,
                &mut envelope.redactions,
                &mut newly_redacted,
            );
            if let Some(content) = response.body.content.as_mut() {
                scrub_json(
                    content,
                    RedactionLocation::ResponseBody,
                    &sensitive_names,
                    &mut envelope.redactions,
                    &mut newly_redacted,
                );
            }
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

    #[must_use]
    pub fn attribution_for(
        &self,
        source: CaptureSource,
        headers: &[CapturedField],
    ) -> CaptureAttribution {
        if let Some(label) = header_value(headers, &self.attribution.client_label_header)
            .and_then(|value| normalized_application_label(value, self.attribution.max_label_bytes))
        {
            return CaptureAttribution {
                application: label,
                source: AttributionSource::ClientLabel,
                confidence: AttributionConfidence::High,
                process_id: None,
            };
        }

        if let Some(user_agent) = header_value(headers, "user-agent") {
            let normalized = user_agent.to_ascii_lowercase();
            if let Some(rule) = self.attribution.user_agents.iter().find(|rule| {
                rule.contains
                    .iter()
                    .any(|pattern| normalized.contains(pattern))
            }) {
                return CaptureAttribution {
                    application: rule.application.clone(),
                    source: AttributionSource::UserAgent,
                    confidence: AttributionConfidence::Medium,
                    process_id: None,
                };
            }
        }

        CaptureAttribution {
            application: match source {
                CaptureSource::Gateway => self.attribution.gateway_fallback.clone(),
                CaptureSource::Mitmproxy => self.attribution.proxy_fallback.clone(),
            },
            source: AttributionSource::CaptureMode,
            confidence: AttributionConfidence::Low,
            process_id: None,
        }
    }
}

fn user_agent_rule(application: &str, contains: &[&str]) -> UserAgentRule {
    UserAgentRule {
        application: application.to_owned(),
        contains: contains
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
    }
}

fn header_value<'a>(headers: &'a [CapturedField], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case(name))
        .map(|field| field.value.as_str())
}

fn normalized_application_label(value: &str, max_bytes: usize) -> Option<String> {
    let trimmed = value.trim();
    valid_application_label(trimmed, max_bytes).then(|| trimmed.to_owned())
}

fn valid_application_label(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.is_ascii()
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
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
    location: RedactionLocation,
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
                redactions.push(CaptureRedaction { location, name });
                *newly_redacted += 1;
            }
            for child in object.values_mut() {
                scrub_json(child, location, sensitive_names, redactions, newly_redacted);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_json(item, location, sensitive_names, redactions, newly_redacted);
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
