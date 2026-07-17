use std::sync::OnceLock;

use regex::{Captures, Regex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ts_rs::TS;

use crate::{CapturedRequest, DESKTOP_API_VERSION};

pub const EXPORT_FORMAT_VERSION: &str = "0.1";
pub const EXPORT_POLICY_VERSION: &str = "0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ExportProfile {
    Minimal,
    Reproducible,
    Forensic,
}

impl ExportProfile {
    const fn slug(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Reproducible => "reproducible",
            Self::Forensic => "forensic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct ExportRedaction {
    pub category: String,
    pub pointer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct ExportPreview {
    pub profile: ExportProfile,
    pub suggested_filename: String,
    pub content: String,
    pub byte_count: u64,
    pub content_sha256: String,
    pub exported_at_unix_ms: u64,
    pub redactions: Vec<ExportRedaction>,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct ExportReceipt {
    pub path: String,
    pub byte_count: u64,
    pub redaction_count: u64,
}

pub fn build_export_preview(
    request: &CapturedRequest,
    profile: ExportProfile,
    exported_at_unix_ms: u64,
) -> Result<ExportPreview, serde_json::Error> {
    let payload = match profile {
        ExportProfile::Minimal => minimal_payload(request),
        ExportProfile::Reproducible => reproducible_payload(request)?,
        ExportProfile::Forensic => forensic_payload(request)?,
    };
    let mut document = json!({
        "formatVersion": EXPORT_FORMAT_VERSION,
        "policyVersion": EXPORT_POLICY_VERSION,
        "desktopApiVersion": DESKTOP_API_VERSION,
        "profile": profile,
        "exportedAtUnixMs": exported_at_unix_ms,
        "request": payload,
    });
    let mut redactions = Vec::new();
    scrub_value(&mut document, "", &mut redactions);
    document
        .as_object_mut()
        .expect("export document is always an object")
        .insert("redactionCount".to_owned(), json!(redactions.len()));
    let mut content = serde_json::to_string_pretty(&document)?;
    content.push('\n');
    let byte_count = u64::try_from(content.len()).unwrap_or(u64::MAX);
    let content_sha256 = format!("{:x}", Sha256::digest(content.as_bytes()));
    Ok(ExportPreview {
        profile,
        suggested_filename: suggested_filename(request, profile),
        content,
        byte_count,
        content_sha256,
        exported_at_unix_ms,
        redactions,
        policy_version: EXPORT_POLICY_VERSION.to_owned(),
    })
}

fn minimal_payload(request: &CapturedRequest) -> Value {
    let anatomy = request
        .detail
        .anatomy
        .iter()
        .map(|section| {
            let items = section
                .items
                .iter()
                .map(|item| {
                    json!({
                        "label": item.label,
                        "role": item.role,
                        "content": item.content,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": section.id,
                "title": section.title,
                "count": section.count,
                "evidence": section.evidence,
                "items": items,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "metadata": request_metadata(request),
        "promptPreview": request.prompt_preview,
        "anatomy": anatomy,
    })
}

fn reproducible_payload(request: &CapturedRequest) -> Result<Value, serde_json::Error> {
    Ok(json!({
        "metadata": request_metadata(request),
        "promptPreview": request.prompt_preview,
        "anatomy": serde_json::to_value(&request.detail.anatomy)?,
        "parameters": reproduction_parameters(&request.detail.raw),
    }))
}

fn forensic_payload(request: &CapturedRequest) -> Result<Value, serde_json::Error> {
    Ok(json!({
        "metadata": request_metadata(request),
        "promptPreview": request.prompt_preview,
        "anatomy": serde_json::to_value(&request.detail.anatomy)?,
        "timeline": serde_json::to_value(&request.detail.timeline)?,
        "raw": request.detail.raw,
    }))
}

fn request_metadata(request: &CapturedRequest) -> Value {
    json!({
        "id": request.id,
        "observedAtUnixMs": request.observed_at_unix_ms,
        "application": request.application,
        "provider": request.provider,
        "operation": request.operation,
        "model": request.model,
        "tokens": request.tokens,
        "durationMs": request.duration_ms,
        "status": request.status,
        "hasTools": request.has_tools,
    })
}

fn reproduction_parameters(raw: &Value) -> Value {
    const PARAMETER_KEYS: [&str; 10] = [
        "model",
        "temperature",
        "top_p",
        "max_tokens",
        "max_output_tokens",
        "stream",
        "tool_choice",
        "parallel_tool_calls",
        "response_format",
        "tools",
    ];
    let Some(body) = raw.pointer("/request/body").and_then(Value::as_object) else {
        return Value::Object(Map::new());
    };
    let selected = PARAMETER_KEYS
        .iter()
        .filter_map(|key| {
            body.get(*key)
                .cloned()
                .map(|value| ((*key).to_owned(), value))
        })
        .collect::<Map<_, _>>();
    Value::Object(selected)
}

fn suggested_filename(request: &CapturedRequest, profile: ExportProfile) -> String {
    let mut identifier = request
        .id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(64)
        .collect::<String>();
    if identifier.is_empty() {
        identifier.push_str("request");
    }
    format!("codeischeap-{identifier}-{}.json", profile.slug())
}

fn scrub_value(value: &mut Value, pointer: &str, redactions: &mut Vec<ExportRedaction>) {
    match value {
        Value::String(text) => scrub_text(text, pointer, redactions),
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                scrub_value(item, &format!("{pointer}/{index}"), redactions);
            }
        }
        Value::Object(object) => {
            for (key, child) in object {
                scrub_value(
                    child,
                    &format!("{pointer}/{}", escape_pointer_segment(key)),
                    redactions,
                );
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn scrub_text(text: &mut String, pointer: &str, redactions: &mut Vec<ExportRedaction>) {
    let mut sanitized = text.clone();
    for pattern in credential_patterns() {
        sanitized = pattern
            .regex
            .replace_all(&sanitized, |_: &Captures<'_>| {
                redactions.push(ExportRedaction {
                    category: pattern.category.to_owned(),
                    pointer: pointer.to_owned(),
                });
                format!("[REDACTED:{}]", pattern.category)
            })
            .into_owned();
    }
    *text = sanitized;
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

struct CredentialPattern {
    category: &'static str,
    regex: Regex,
}

fn credential_patterns() -> &'static [CredentialPattern] {
    static PATTERNS: OnceLock<Vec<CredentialPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            (
                "private_key",
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            ),
            ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
            (
                "openai_api_key",
                r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}\b",
            ),
            ("google_api_key", r"\bAIza[0-9A-Za-z_-]{20,}\b"),
            ("bearer_token", r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
            (
                "jwt",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            ),
        ]
        .into_iter()
        .map(|(category, expression)| CredentialPattern {
            category,
            regex: Regex::new(expression).expect("credential scanner pattern must compile"),
        })
        .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnatomyItem, AnatomySection, CaptureStatus, EvidenceLevel, RequestDetail, TimelineEvent,
    };

    fn request() -> CapturedRequest {
        CapturedRequest {
            id: "capture/unsafe".to_owned(),
            observed_at_unix_ms: 1_700_000_000_000,
            application: "Terminal".to_owned(),
            provider: "OpenAI".to_owned(),
            operation: "responses".to_owned(),
            model: "gpt-4.1".to_owned(),
            tokens: Some(42),
            token_source: Some(crate::MetricSource::Reported),
            cost_usd: Some(0.000_123),
            cost_source: Some(crate::MetricSource::Reported),
            pricing_version: Some("test.v1".to_owned()),
            semantic_fingerprint: Some("a".repeat(64)),
            duration_ms: Some(120),
            status: CaptureStatus::Complete,
            has_tools: true,
            prompt_preview: "Use Bearer abcdefghijklmnop safely".to_owned(),
            detail: RequestDetail {
                anatomy: vec![AnatomySection {
                    id: "messages".to_owned(),
                    title: "Messages".to_owned(),
                    token_count: Some(8),
                    count: 1,
                    evidence: EvidenceLevel::Observed,
                    items: vec![AnatomyItem {
                        id: "message-0".to_owned(),
                        label: "User".to_owned(),
                        role: Some("user".to_owned()),
                        content: "key sk-proj-abcdefghijklmnop1234".to_owned(),
                        source: "/input/0".to_owned(),
                    }],
                }],
                timeline: vec![TimelineEvent {
                    id: "request".to_owned(),
                    offset_ms: Some(0),
                    sequence: None,
                    kind: "request".to_owned(),
                    title: "Request observed".to_owned(),
                    detail: "Captured locally".to_owned(),
                    locator: None,
                }],
                raw: json!({
                    "request": {
                        "body": {
                            "model": "gpt-4.1",
                            "temperature": 0.2,
                            "tools": [{"name": "lookup"}],
                            "input": "AIzaabcdefghijklmnopqrstuvwxyz123456"
                        }
                    }
                }),
            },
        }
    }

    #[test]
    fn profiles_expand_from_summary_to_sanitized_forensics() {
        let request = request();
        let minimal = build_export_preview(&request, ExportProfile::Minimal, 10).unwrap();
        let reproducible = build_export_preview(&request, ExportProfile::Reproducible, 10).unwrap();
        let forensic = build_export_preview(&request, ExportProfile::Forensic, 10).unwrap();

        let minimal_json: Value = serde_json::from_str(&minimal.content).unwrap();
        let reproducible_json: Value = serde_json::from_str(&reproducible.content).unwrap();
        let forensic_json: Value = serde_json::from_str(&forensic.content).unwrap();
        assert!(minimal_json.pointer("/request/raw").is_none());
        assert!(minimal_json.pointer("/request/parameters").is_none());
        assert_eq!(
            reproducible_json.pointer("/request/parameters/temperature"),
            Some(&json!(0.2))
        );
        assert!(reproducible_json.pointer("/request/raw").is_none());
        assert!(forensic_json.pointer("/request/raw").is_some());
        assert!(forensic_json.pointer("/request/timeline").is_some());
    }

    #[test]
    fn known_credentials_are_replaced_without_entering_the_preview() {
        let preview = build_export_preview(&request(), ExportProfile::Forensic, 10).unwrap();

        for secret in [
            "Bearer abcdefghijklmnop",
            "sk-proj-abcdefghijklmnop1234",
            "AIzaabcdefghijklmnopqrstuvwxyz123456",
        ] {
            assert!(!preview.content.contains(secret));
        }
        assert!(preview.content.contains("[REDACTED:bearer_token]"));
        assert!(preview.content.contains("[REDACTED:openai_api_key]"));
        assert!(preview.content.contains("[REDACTED:google_api_key]"));
        assert_eq!(preview.redactions.len(), 3);
        assert!(
            preview
                .redactions
                .iter()
                .all(|redaction| redaction.pointer.starts_with("/request/"))
        );
        assert_eq!(preview.policy_version, EXPORT_POLICY_VERSION);
        assert_eq!(preview.byte_count, preview.content.len() as u64);
        assert_eq!(preview.content_sha256.len(), 64);
        assert_eq!(preview.exported_at_unix_ms, 10);
        assert_eq!(
            preview.suggested_filename,
            "codeischeap-capture_unsafe-forensic.json"
        );
    }

    #[test]
    fn every_declared_credential_pattern_has_a_stable_placeholder() {
        let mut text = [
            "sk-ant-abcdefghijklmnop1234",
            "sk-proj-abcdefghijklmnop1234",
            "AIzaabcdefghijklmnopqrstuvwxyz123456",
            "Bearer abcdefghijklmnop",
            "eyJabcdefghijk.abcdefghijk.abcdefghijk",
            "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----",
        ]
        .join("\n");
        let mut redactions = Vec::new();

        scrub_text(&mut text, "/request/test", &mut redactions);

        for category in [
            "anthropic_api_key",
            "openai_api_key",
            "google_api_key",
            "bearer_token",
            "jwt",
            "private_key",
        ] {
            assert!(text.contains(&format!("[REDACTED:{category}]")));
            assert!(
                redactions
                    .iter()
                    .any(|redaction| redaction.category == category)
            );
        }
        assert_eq!(redactions.len(), 6);
    }
}
