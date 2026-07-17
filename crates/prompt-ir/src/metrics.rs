use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::OnceLock;

use crate::{
    MetricSource, PricingCost, PromptIr, PromptMetrics, PromptPart, SemanticFingerprint,
    TokenMeasurement,
};

pub const PRICING_CATALOG_VERSION: &str = "2026-07-17.v1";
const ESTIMATOR_METHOD: &str = "unicode_chars_div_4.v1";
const FINGERPRINT_CANONICALIZATION: &str = "prompt_semantics.v1";

#[derive(Deserialize)]
struct PricingCatalog {
    version: String,
    prices: Vec<Price>,
}

#[derive(Deserialize)]
struct Price {
    provider: String,
    model_prefix: String,
    input_per_million: f64,
    output_per_million: f64,
    id: String,
}

pub fn enrich_metrics(prompt: &mut PromptIr) {
    let usage = prompt.response.as_ref().map(|response| &response.usage);
    let input_tokens = reported(
        usage,
        &[
            "input_tokens",
            "prompt_tokens",
            "promptTokenCount",
            "prompt_eval_count",
        ],
    )
    .unwrap_or_else(|| estimated(estimate_value(&canonical_request(prompt))));
    let output_tokens = reported(
        usage,
        &[
            "output_tokens",
            "completion_tokens",
            "candidatesTokenCount",
            "eval_count",
        ],
    )
    .or_else(|| estimated_output(prompt));
    let total_tokens = reported(usage, &["total_tokens", "totalTokenCount"]).or_else(|| {
        output_tokens.as_ref().map(|output| TokenMeasurement {
            value: input_tokens.value.saturating_add(output.value),
            source: if input_tokens.source == MetricSource::Reported
                && output.source == MetricSource::Reported
            {
                MetricSource::Reported
            } else {
                MetricSource::Estimated
            },
            method: "input_plus_output.v1".to_owned(),
        })
    });
    let cost = price(prompt, &input_tokens, output_tokens.as_ref());
    prompt.metrics = Some(PromptMetrics {
        input_tokens: Some(input_tokens),
        output_tokens,
        total_tokens,
        cost,
        fingerprint: fingerprint(prompt),
    });
}

fn reported(
    usage: Option<&std::collections::BTreeMap<String, Value>>,
    keys: &[&str],
) -> Option<TokenMeasurement> {
    let usage = usage?;
    keys.iter().find_map(|key| {
        usage
            .get(*key)
            .and_then(Value::as_u64)
            .map(|value| TokenMeasurement {
                value,
                source: MetricSource::Reported,
                method: format!("provider_usage.{key}"),
            })
    })
}

fn estimated(value: u64) -> TokenMeasurement {
    TokenMeasurement {
        value,
        source: MetricSource::Estimated,
        method: ESTIMATOR_METHOD.to_owned(),
    }
}

fn estimated_output(prompt: &PromptIr) -> Option<TokenMeasurement> {
    let response = prompt.response.as_ref()?;
    (!response.parts.is_empty()).then(|| {
        estimated(estimate_value(&json!(
            response
                .parts
                .iter()
                .map(canonical_part)
                .collect::<Vec<_>>()
        )))
    })
}

fn estimate_value(value: &Value) -> u64 {
    let chars = serde_json::to_string(value).map_or(0, |encoded| encoded.chars().count());
    u64::try_from(chars.div_ceil(4)).unwrap_or(u64::MAX)
}

fn price(
    prompt: &PromptIr,
    input: &TokenMeasurement,
    output: Option<&TokenMeasurement>,
) -> Option<PricingCost> {
    if prompt.provider.id.eq_ignore_ascii_case("ollama") {
        return Some(PricingCost {
            usd: 0.0,
            source: input.source,
            catalog_version: PRICING_CATALOG_VERSION.to_owned(),
            price_id: "ollama:local:no_external_api_cost".to_owned(),
        });
    }
    let model = prompt.model.as_deref()?;
    let catalog = pricing_catalog();
    debug_assert_eq!(catalog.version, PRICING_CATALOG_VERSION);
    let entry = catalog.prices.iter().find(|entry| {
        prompt.provider.id.eq_ignore_ascii_case(&entry.provider)
            && model.starts_with(&entry.model_prefix)
    })?;
    let output_value = output.map_or(0, |measurement| measurement.value);
    let usd = (input.value as f64 * entry.input_per_million
        + output_value as f64 * entry.output_per_million)
        / 1_000_000.0;
    Some(PricingCost {
        usd,
        source: output.map_or(input.source, |measurement| {
            if input.source == MetricSource::Reported
                && measurement.source == MetricSource::Reported
            {
                MetricSource::Reported
            } else {
                MetricSource::Estimated
            }
        }),
        catalog_version: PRICING_CATALOG_VERSION.to_owned(),
        price_id: entry.id.clone(),
    })
}

fn pricing_catalog() -> &'static PricingCatalog {
    static CATALOG: OnceLock<PricingCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../../../policies/model-pricing.v0.1.json"))
            .expect("checked-in pricing catalog must be valid")
    })
}

fn fingerprint(prompt: &PromptIr) -> SemanticFingerprint {
    let canonical = canonical_request(prompt);
    let encoded = serde_json::to_vec(&canonical).expect("semantic prompt value must serialize");
    SemanticFingerprint {
        algorithm: "blake3-256".to_owned(),
        canonicalization_version: FINGERPRINT_CANONICALIZATION.to_owned(),
        digest: blake3::hash(&encoded).to_hex().to_string(),
    }
}

fn canonical_request(prompt: &PromptIr) -> Value {
    json!({
        "provider": prompt.provider.id.to_ascii_lowercase(),
        "operation": prompt.operation,
        "model": prompt.model,
        "instructions": prompt.instructions.iter().map(|item| json!({
            "role": item.role,
            "parts": item.parts.iter().map(canonical_part).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "messages": prompt.messages.iter().map(|item| json!({
            "role": item.role,
            "parts": item.parts.iter().map(canonical_part).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "context": prompt.context.iter().map(|item| json!({
            "kind": item.kind,
            "source_label": item.source_label,
            "parts": item.parts.iter().map(canonical_part).collect::<Vec<_>>()
        })).collect::<Vec<_>>(),
        "tools": prompt.tools.iter().map(|tool| json!({
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema
        })).collect::<Vec<_>>(),
        "generation": prompt.generation,
    })
}

fn canonical_part(part: &PromptPart) -> Value {
    match part {
        PromptPart::Text { text, .. } => json!({"kind": "text", "text": text}),
        PromptPart::Json { value, .. } => json!({"kind": "json", "value": value}),
        PromptPart::ImageRef {
            location,
            media_type,
            ..
        } => json!({"kind": "image_ref", "location": location, "media_type": media_type}),
        PromptPart::AudioRef {
            location,
            media_type,
            ..
        } => json!({"kind": "audio_ref", "location": location, "media_type": media_type}),
        PromptPart::FileRef {
            location,
            media_type,
            ..
        } => json!({"kind": "file_ref", "location": location, "media_type": media_type}),
        PromptPart::ToolUse { name, input, .. } => {
            json!({"kind": "tool_use", "name": name, "input": input})
        }
        PromptPart::ToolResult { value, .. } => json!({"kind": "tool_result", "value": value}),
        PromptPart::Unknown { value, .. } => json!({"kind": "unknown", "value": value}),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{Evidence, Message, MessageRole, ResponseTrace};

    use super::*;

    #[test]
    fn reported_usage_is_never_labeled_estimated() {
        let mut prompt = fixture();
        prompt.response = Some(ResponseTrace {
            id: None,
            model: None,
            role: MessageRole::Assistant,
            parts: Vec::new(),
            stop_reason: None,
            stop_sequence: None,
            usage: BTreeMap::from([
                ("input_tokens".to_owned(), json!(12)),
                ("output_tokens".to_owned(), json!(4)),
            ]),
            error: None,
            events: Vec::new(),
            evidence: Evidence::unknown(),
        });
        enrich_metrics(&mut prompt);
        let metrics = prompt.metrics.expect("metrics must exist");
        assert_eq!(
            metrics.total_tokens.expect("total").source,
            MetricSource::Reported
        );
    }

    #[test]
    fn provider_usage_key_variants_remain_reported() {
        for (input_key, output_key, total_key) in [
            ("input_tokens", "output_tokens", "total_tokens"),
            ("prompt_tokens", "completion_tokens", "total_tokens"),
            (
                "promptTokenCount",
                "candidatesTokenCount",
                "totalTokenCount",
            ),
            ("prompt_eval_count", "eval_count", "total_tokens"),
        ] {
            let mut prompt = fixture();
            prompt.response = Some(ResponseTrace {
                id: None,
                model: None,
                role: MessageRole::Assistant,
                parts: Vec::new(),
                stop_reason: None,
                stop_sequence: None,
                usage: BTreeMap::from([
                    (input_key.to_owned(), json!(12)),
                    (output_key.to_owned(), json!(4)),
                    (total_key.to_owned(), json!(16)),
                ]),
                error: None,
                events: Vec::new(),
                evidence: Evidence::unknown(),
            });
            enrich_metrics(&mut prompt);
            let metrics = prompt.metrics.expect("metrics must exist");
            assert_eq!(
                metrics.input_tokens.expect("input").source,
                MetricSource::Reported
            );
            assert_eq!(
                metrics.output_tokens.expect("output").source,
                MetricSource::Reported
            );
            assert_eq!(
                metrics.total_tokens.expect("total").source,
                MetricSource::Reported
            );
        }
    }

    #[test]
    fn fingerprint_ignores_request_and_evidence_ids() {
        let mut first = fixture();
        let mut second = first.clone();
        second.request_id = "another-request".to_owned();
        second.messages[0].id = "another-message".to_owned();
        if let PromptPart::Text { id, .. } = &mut second.messages[0].parts[0] {
            *id = "another-part".to_owned();
        }
        enrich_metrics(&mut first);
        enrich_metrics(&mut second);
        assert_eq!(
            first.metrics.unwrap().fingerprint.digest,
            second.metrics.unwrap().fingerprint.digest
        );
    }

    #[test]
    fn unknown_prices_remain_unknown() {
        let mut prompt = fixture();
        prompt.model = Some("unpriced-model".to_owned());
        enrich_metrics(&mut prompt);
        assert!(prompt.metrics.unwrap().cost.is_none());
    }

    fn fixture() -> PromptIr {
        let mut prompt = PromptIr::new("request", "openai");
        prompt.model = Some("gpt-5-mini".to_owned());
        prompt.messages.push(Message {
            id: "message".to_owned(),
            role: MessageRole::User,
            parts: vec![PromptPart::Text {
                id: "part".to_owned(),
                text: "hello".to_owned(),
                evidence: Evidence::unknown(),
            }],
            evidence: Evidence::unknown(),
        });
        prompt
    }
}
