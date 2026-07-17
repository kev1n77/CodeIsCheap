use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use codeischeap_adapters::{AdapterRegistry, ParseIssueCode};
use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_prompt_ir::{EvidenceSource, PromptIr, PromptPart};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct CapabilityMatrix {
    version: String,
    adapters: Vec<AdapterCases>,
}

#[derive(Debug, Deserialize)]
struct AdapterCases {
    id: String,
    operations: Vec<String>,
    cases: Vec<CapabilityCase>,
}

#[derive(Debug, Deserialize)]
struct CapabilityCase {
    id: String,
    capture: String,
    #[serde(default)]
    golden: Option<String>,
    operation: Option<String>,
    outcome: ExpectedOutcome,
    capabilities: Vec<String>,
    #[serde(default)]
    issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    Parsed,
    RawFallback,
}

#[test]
fn declared_adapter_capabilities_have_fixture_and_golden_evidence() {
    let fixtures = fixtures();
    let matrix: CapabilityMatrix = read_json(&fixtures.join("capability-matrix.json"));
    assert_eq!(matrix.version, "0.1");
    let mut case_ids = HashSet::new();

    for adapter in matrix.adapters {
        let mut covered_operations = BTreeSet::new();
        for case in adapter.cases {
            assert!(
                case_ids.insert(case.id.clone()),
                "duplicate case id: {}",
                case.id
            );
            assert_fixture_name(&case.capture);
            let envelope: CaptureEnvelope = read_json(&fixtures.join(&case.capture));
            let sanitized = CapturePolicy::load_default()
                .expect("policy must load")
                .sanitize_envelope(envelope)
                .expect("capability fixture must be in scope");
            let result = AdapterRegistry::default().parse(&sanitized);

            match case.outcome {
                ExpectedOutcome::Parsed => {
                    assert_eq!(
                        result.adapter_id.as_deref(),
                        Some(adapter.id.as_str()),
                        "{}",
                        case.id
                    );
                    assert!(!result.raw_fallback, "{}", case.id);
                    let prompt = result
                        .prompt_ir
                        .as_ref()
                        .unwrap_or_else(|| panic!("{} must produce Prompt IR", case.id));
                    assert_eq!(prompt.operation, case.operation, "{}", case.id);
                    covered_operations.insert(
                        prompt
                            .operation
                            .clone()
                            .unwrap_or_else(|| panic!("{} needs an operation", case.id)),
                    );
                    assert_golden(&fixtures, &case, prompt);
                    for capability in &case.capabilities {
                        assert!(
                            supports(prompt, capability),
                            "{} does not prove {capability}",
                            case.id
                        );
                    }
                }
                ExpectedOutcome::RawFallback => {
                    assert!(result.raw_fallback, "{}", case.id);
                    assert!(result.prompt_ir.is_none(), "{}", case.id);
                }
            }

            let actual_issues = result
                .issues
                .iter()
                .map(|issue| issue_code(&issue.code))
                .collect::<HashSet<_>>();
            for issue in &case.issues {
                assert!(
                    actual_issues.contains(issue.as_str()),
                    "{} is missing issue {issue}",
                    case.id
                );
            }
            if case
                .capabilities
                .iter()
                .any(|value| value == "fallback.invalid_body")
            {
                assert!(
                    actual_issues.contains("invalid_body"),
                    "{} must prove invalid-body fallback",
                    case.id
                );
            }
        }

        assert_eq!(
            covered_operations,
            adapter.operations.into_iter().collect(),
            "{} declared operations must each have a parsed fixture",
            adapter.id
        );
    }
}

fn assert_golden(fixtures: &Path, case: &CapabilityCase, prompt: &PromptIr) {
    let golden = case
        .golden
        .as_ref()
        .unwrap_or_else(|| panic!("{} parsed cases require a golden", case.id));
    assert_fixture_name(golden);
    let expected: Value = read_json(&fixtures.join(golden));
    let actual = serde_json::to_value(prompt).expect("Prompt IR must serialize");
    assert_eq!(actual, expected, "{} golden mismatch", case.id);
}

fn supports(prompt: &PromptIr, capability: &str) -> bool {
    let request_parts = prompt
        .instructions
        .iter()
        .flat_map(|item| item.parts.iter())
        .chain(prompt.messages.iter().flat_map(|item| item.parts.iter()))
        .collect::<Vec<_>>();
    let response = prompt.response.as_ref();
    match capability {
        "request.instructions" => !prompt.instructions.is_empty(),
        "request.messages" => !prompt.messages.is_empty(),
        "request.multimodal.image" => request_parts
            .iter()
            .any(|part| matches!(part, PromptPart::ImageRef { .. })),
        "request.tool_use" => request_parts
            .iter()
            .any(|part| matches!(part, PromptPart::ToolUse { .. })),
        "request.tool_result" => request_parts
            .iter()
            .any(|part| matches!(part, PromptPart::ToolResult { .. })),
        "request.tool_definitions" => !prompt.tools.is_empty(),
        "request.generation" => {
            prompt.generation.temperature.is_some()
                || prompt.generation.top_p.is_some()
                || prompt.generation.max_output_tokens.is_some()
                || !prompt.generation.stop.is_empty()
                || !prompt.generation.extra.is_empty()
        }
        "request.streaming_flag" => prompt.vendor.get("stream") == Some(&Value::Bool(true)),
        "request.batch_prompts" => prompt.messages.len() > 1,
        "response.json" => response.is_some_and(|trace| {
            matches!(
                trace.evidence.source,
                Some(EvidenceSource::JsonPointer { .. })
            )
        }),
        "response.sse" => response.is_some_and(|trace| {
            trace.events.iter().any(|event| {
                matches!(
                    event.evidence.source,
                    Some(EvidenceSource::StreamEvent { .. })
                )
            })
        }),
        "response.ndjson" => response.is_some_and(|trace| {
            trace
                .events
                .iter()
                .any(|event| matches!(event.kind.as_str(), "chat_chunk" | "generate_chunk"))
        }),
        "response.text" => response.is_some_and(|trace| {
            trace
                .parts
                .iter()
                .any(|part| matches!(part, PromptPart::Text { .. }))
        }),
        "response.tool_use" => response.is_some_and(|trace| {
            trace
                .parts
                .iter()
                .any(|part| matches!(part, PromptPart::ToolUse { .. }))
        }),
        "response.usage" => response.is_some_and(|trace| !trace.usage.is_empty()),
        "response.stop_reason" => response.is_some_and(|trace| trace.stop_reason.is_some()),
        "response.unknown_event" => response.is_some_and(|trace| {
            trace
                .events
                .iter()
                .any(|event| event.kind == "future_event")
        }),
        "response.error" => response.is_some_and(|trace| trace.error.is_some()),
        "fallback.invalid_body" => true,
        _ => panic!("unknown capability: {capability}"),
    }
}

fn issue_code(code: &ParseIssueCode) -> &'static str {
    match code {
        ParseIssueCode::NoAdapter => "no_adapter",
        ParseIssueCode::AdapterRejected => "adapter_rejected",
        ParseIssueCode::AdapterPanicked => "adapter_panicked",
        ParseIssueCode::AllAdaptersFailed => "all_adapters_failed",
        ParseIssueCode::InvalidBody => "invalid_body",
        ParseIssueCode::InvalidStreamEvent => "invalid_stream_event",
        ParseIssueCode::UnsupportedOperation => "unsupported_operation",
        ParseIssueCode::MissingField => "missing_field",
        ParseIssueCode::UnsupportedContent => "unsupported_content",
        ParseIssueCode::InvalidField => "invalid_field",
        ParseIssueCode::InvalidPromptIr => "invalid_prompt_ir",
    }
}

fn assert_fixture_name(name: &str) {
    assert!(
        !name.contains('/') && !name.contains('\\'),
        "fixture names must stay in the fixture directory"
    );
    assert!(name.ends_with(".json"), "fixture names must be JSON");
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_str(&fs::read_to_string(path).expect("fixture must be readable"))
        .expect("fixture must be valid JSON")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
