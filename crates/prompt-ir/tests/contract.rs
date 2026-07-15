use std::collections::BTreeMap;

use codeischeap_prompt_ir::{
    Evidence, EvidenceLevel, Message, MessageRole, PromptIr, PromptPart, ResponseEvent,
    ResponseTrace, Validate, ValidationError,
};
use schemars::schema_for;

const BASIC_OPENAI: &str = include_str!("fixtures/basic-openai.json");
const BASIC_ANTHROPIC: &str = include_str!("fixtures/basic-anthropic.json");
const CHECKED_IN_SCHEMA: &str = include_str!("../../../schemas/prompt-ir/v0.1.schema.json");

#[test]
fn fixture_round_trips_and_validates() {
    let prompt: PromptIr = serde_json::from_str(BASIC_OPENAI).expect("fixture must deserialize");
    prompt
        .validate()
        .expect("fixture must satisfy semantic invariants");

    let encoded = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let decoded: PromptIr = serde_json::from_value(encoded).expect("Prompt IR must deserialize");

    assert_eq!(decoded, prompt);
    assert_eq!(prompt.provider.id, "openai");
    assert_eq!(prompt.messages.len(), 1);
    assert_eq!(prompt.tools.len(), 1);
}

#[test]
fn anthropic_fixture_preserves_tool_use_and_tool_result() {
    let prompt: PromptIr = serde_json::from_str(BASIC_ANTHROPIC).expect("fixture must deserialize");
    prompt
        .validate()
        .expect("fixture must satisfy semantic invariants");

    assert_eq!(prompt.provider.id, "anthropic");
    assert_eq!(prompt.messages.len(), 3);
    assert_eq!(prompt.messages[1].parts[0].id(), "toolu_example_1");
    assert!(matches!(
        prompt.messages[1].parts[0],
        PromptPart::ToolUse { ref name, .. } if name == "read_file"
    ));
    assert!(matches!(
        prompt.messages[2].parts[0],
        PromptPart::ToolResult { ref tool_use_id, .. } if tool_use_id == "toolu_example_1"
    ));

    let encoded = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let decoded: PromptIr = serde_json::from_value(encoded).expect("Prompt IR must deserialize");
    assert_eq!(decoded, prompt);
}

#[test]
fn observed_evidence_requires_a_source_locator() {
    let mut prompt = PromptIr::new("req_missing_source", "openai");
    prompt.messages.push(Message {
        id: "message_1".to_owned(),
        role: MessageRole::User,
        parts: vec![PromptPart::Text {
            id: "part_1".to_owned(),
            text: "hello".to_owned(),
            evidence: Evidence {
                level: EvidenceLevel::Observed,
                source: None,
                rule_id: None,
                confidence: Some(1.0),
            },
        }],
        evidence: Evidence::unknown(),
    });

    let errors = prompt
        .validate()
        .expect_err("missing source must be rejected");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::ObservedEvidenceMissingSource { path }
        if path == "messages[0].parts[0].evidence"
    )));
}

#[test]
fn response_events_require_observed_source_locators() {
    let mut prompt = PromptIr::new("req_response_source", "anthropic");
    prompt.response = Some(ResponseTrace {
        id: Some("msg_1".to_owned()),
        model: Some("claude-sonnet".to_owned()),
        role: MessageRole::Assistant,
        parts: Vec::new(),
        stop_reason: None,
        stop_sequence: None,
        usage: BTreeMap::new(),
        error: None,
        events: vec![ResponseEvent {
            index: 0,
            kind: "message_start".to_owned(),
            content_index: None,
            delta_kind: None,
            evidence: Evidence {
                level: EvidenceLevel::Observed,
                source: None,
                rule_id: None,
                confidence: Some(1.0),
            },
        }],
        evidence: Evidence::unknown(),
    });

    let errors = prompt
        .validate()
        .expect_err("response event without source must be rejected");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::ObservedEvidenceMissingSource { path }
        if path == "response.events[0].evidence"
    )));
}

#[test]
fn duplicate_ids_are_rejected() {
    let mut prompt = PromptIr::new("req_duplicate", "openai");
    prompt.messages.push(Message {
        id: "duplicate".to_owned(),
        role: MessageRole::User,
        parts: vec![PromptPart::Text {
            id: "duplicate".to_owned(),
            text: "hello".to_owned(),
            evidence: Evidence::unknown(),
        }],
        evidence: Evidence::unknown(),
    });

    let errors = prompt
        .validate()
        .expect_err("duplicate ids must be rejected");
    assert!(errors.0.contains(&ValidationError::DuplicateId {
        id: "duplicate".to_owned()
    }));
}

#[test]
fn confidence_must_be_between_zero_and_one() {
    let mut prompt = PromptIr::new("req_confidence", "openai");
    prompt.provider.confidence = Some(1.1);

    let errors = prompt
        .validate()
        .expect_err("invalid confidence must be rejected");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidConfidence { path, value }
        if path == "provider.confidence" && (*value - 1.1).abs() < f32::EPSILON
    )));
}

#[test]
fn generated_schema_contains_the_public_contract() {
    let schema = serde_json::to_value(schema_for!(PromptIr)).expect("schema must serialize");
    let schema_text = serde_json::to_string(&schema).expect("schema must encode");

    assert!(schema_text.contains("ir_version"));
    assert!(schema_text.contains("messages"));
    assert!(schema_text.contains("observed"));
    assert!(schema_text.contains("json_pointer"));
    assert!(schema_text.contains("response"));
    assert!(schema_text.contains("stream_event"));
}

#[test]
fn checked_in_schema_matches_the_rust_contract() {
    let generated = serde_json::to_value(schema_for!(PromptIr)).expect("schema must serialize");
    let checked_in: serde_json::Value =
        serde_json::from_str(CHECKED_IN_SCHEMA).expect("checked-in schema must be valid JSON");

    assert_eq!(
        checked_in, generated,
        "schema drifted; run `cargo run -p codeischeap-prompt-ir --bin export-schema -- schemas/prompt-ir/v0.1.schema.json`"
    );
}
