use std::cmp::Ordering;
use std::panic::{AssertUnwindSafe, catch_unwind};

use codeischeap_capture_policy::SanitizedCapture;
use codeischeap_prompt_ir::Validate;

use crate::anthropic::AnthropicAdapter;
use crate::gemini::GeminiAdapter;
use crate::model::{AdapterInput, ParseIssue, ParseIssueCode, ParseResult, PromptAdapter};
use crate::openai::OpenAiAdapter;

pub struct AdapterRegistry {
    adapters: Vec<Box<dyn PromptAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(OpenAiAdapter);
        registry.register(AnthropicAdapter);
        registry.register(GeminiAdapter);
        registry
    }
}

impl AdapterRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            adapters: Vec::new(),
        }
    }

    pub fn register(&mut self, adapter: impl PromptAdapter + 'static) {
        self.adapters.push(Box::new(adapter));
    }

    #[must_use]
    pub fn parse(&self, capture: &SanitizedCapture) -> ParseResult {
        let input = AdapterInput::from(capture);
        let mut candidates = self
            .adapters
            .iter()
            .filter_map(|adapter| {
                adapter.detect(input).and_then(|confidence| {
                    (confidence.is_finite() && (0.0..=1.0).contains(&confidence))
                        .then_some((confidence, adapter))
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| right.0.partial_cmp(&left.0).unwrap_or(Ordering::Equal));

        if candidates.is_empty() {
            return ParseResult {
                adapter_id: None,
                confidence: None,
                prompt_ir: None,
                issues: vec![ParseIssue {
                    adapter_id: None,
                    code: ParseIssueCode::NoAdapter,
                    path: None,
                }],
                raw_fallback: true,
            };
        }

        let mut issues = Vec::new();
        for (confidence, adapter) in candidates {
            let adapter_id = adapter.id();
            match catch_unwind(AssertUnwindSafe(|| adapter.parse(input))) {
                Ok(Ok(mut output)) => {
                    if output.prompt_ir.validate().is_err() {
                        issues.push(ParseIssue::adapter(
                            adapter_id,
                            ParseIssueCode::InvalidPromptIr,
                        ));
                        continue;
                    }
                    issues.append(&mut output.issues);
                    return ParseResult {
                        adapter_id: Some(adapter_id.to_owned()),
                        confidence: Some(confidence),
                        prompt_ir: Some(output.prompt_ir),
                        issues,
                        raw_fallback: false,
                    };
                }
                Ok(Err(error)) => {
                    let mut issue = ParseIssue::adapter(adapter_id, error.code);
                    issue.path = error.path;
                    issues.push(issue);
                    issues.push(ParseIssue::adapter(
                        adapter_id,
                        ParseIssueCode::AdapterRejected,
                    ));
                }
                Err(_) => issues.push(ParseIssue::adapter(
                    adapter_id,
                    ParseIssueCode::AdapterPanicked,
                )),
            }
        }
        issues.push(ParseIssue {
            adapter_id: None,
            code: ParseIssueCode::AllAdaptersFailed,
            path: None,
        });
        ParseResult {
            adapter_id: None,
            confidence: None,
            prompt_ir: None,
            issues,
            raw_fallback: true,
        }
    }
}
