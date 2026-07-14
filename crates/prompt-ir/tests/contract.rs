use codeischeap_prompt_ir::{
    Evidence, EvidenceLevel, Message, MessageRole, PromptIr, PromptPart, Validate, ValidationError,
};
use schemars::schema_for;

const BASIC_OPENAI: &str = include_str!("fixtures/basic-openai.json");
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
