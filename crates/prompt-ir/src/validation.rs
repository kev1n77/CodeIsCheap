use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{Evidence, EvidenceLevel, PROMPT_IR_VERSION, PromptIr};

pub trait Validate {
    /// Validates semantic invariants that JSON Schema cannot express.
    fn validate(&self) -> Result<(), ValidationErrors>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    UnsupportedVersion { expected: String, actual: String },
    EmptyField { path: String },
    DuplicateId { id: String },
    InvalidConfidence { path: String, value: f32 },
    ObservedEvidenceMissingSource { path: String },
    InferredEvidenceMissingRule { path: String },
    InvalidMetric { path: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl Display for ValidationErrors {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Prompt IR validation failed with {} error(s)",
            self.0.len()
        )
    }
}

impl Error for ValidationErrors {}

impl Validate for PromptIr {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        let mut ids = HashSet::new();

        if self.ir_version != PROMPT_IR_VERSION {
            errors.push(ValidationError::UnsupportedVersion {
                expected: PROMPT_IR_VERSION.to_owned(),
                actual: self.ir_version.clone(),
            });
        }
        check_non_empty(&self.request_id, "request_id", &mut errors);
        check_non_empty(&self.provider.id, "provider.id", &mut errors);
        check_confidence(self.provider.confidence, "provider.confidence", &mut errors);

        for (index, instruction) in self.instructions.iter().enumerate() {
            let path = format!("instructions[{index}]");
            register_id(&instruction.id, &path, &mut ids, &mut errors);
            check_evidence(
                &instruction.evidence,
                &format!("{path}.evidence"),
                &mut errors,
            );
            check_parts(&instruction.parts, &path, &mut ids, &mut errors);
        }

        for (index, message) in self.messages.iter().enumerate() {
            let path = format!("messages[{index}]");
            register_id(&message.id, &path, &mut ids, &mut errors);
            check_evidence(&message.evidence, &format!("{path}.evidence"), &mut errors);
            check_parts(&message.parts, &path, &mut ids, &mut errors);
        }

        for (index, context) in self.context.iter().enumerate() {
            let path = format!("context[{index}]");
            register_id(&context.id, &path, &mut ids, &mut errors);
            check_evidence(&context.evidence, &format!("{path}.evidence"), &mut errors);
            check_parts(&context.parts, &path, &mut ids, &mut errors);
        }

        for (index, tool) in self.tools.iter().enumerate() {
            let path = format!("tools[{index}]");
            register_id(&tool.id, &path, &mut ids, &mut errors);
            check_non_empty(&tool.name, &format!("{path}.name"), &mut errors);
            check_evidence(&tool.evidence, &format!("{path}.evidence"), &mut errors);
        }

        if let Some(response) = &self.response {
            check_evidence(&response.evidence, "response.evidence", &mut errors);
            check_parts(&response.parts, "response", &mut ids, &mut errors);
            for (index, event) in response.events.iter().enumerate() {
                let path = format!("response.events[{index}]");
                check_non_empty(&event.kind, &format!("{path}.kind"), &mut errors);
                check_evidence(&event.evidence, &format!("{path}.evidence"), &mut errors);
            }
        }

        if let Some(metrics) = &self.metrics {
            for (name, measurement) in [
                ("input_tokens", metrics.input_tokens.as_ref()),
                ("output_tokens", metrics.output_tokens.as_ref()),
                ("total_tokens", metrics.total_tokens.as_ref()),
            ] {
                if measurement.is_some_and(|measurement| measurement.method.trim().is_empty()) {
                    errors.push(ValidationError::InvalidMetric {
                        path: format!("metrics.{name}.method"),
                    });
                }
            }
            if metrics.fingerprint.algorithm != "blake3-256"
                || metrics.fingerprint.digest.len() != 64
                || !metrics
                    .fingerprint
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                errors.push(ValidationError::InvalidMetric {
                    path: "metrics.fingerprint".to_owned(),
                });
            }
            if metrics
                .fingerprint
                .canonicalization_version
                .trim()
                .is_empty()
            {
                errors.push(ValidationError::InvalidMetric {
                    path: "metrics.fingerprint.canonicalization_version".to_owned(),
                });
            }
            if let Some(cost) = &metrics.cost
                && (!cost.usd.is_finite()
                    || cost.usd < 0.0
                    || cost.catalog_version.trim().is_empty()
                    || cost.price_id.trim().is_empty())
            {
                errors.push(ValidationError::InvalidMetric {
                    path: "metrics.cost".to_owned(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

fn check_parts(
    parts: &[crate::PromptPart],
    parent_path: &str,
    ids: &mut HashSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    for (index, part) in parts.iter().enumerate() {
        let path = format!("{parent_path}.parts[{index}]");
        register_id(part.id(), &path, ids, errors);
        check_evidence(part.evidence(), &format!("{path}.evidence"), errors);
    }
}

fn register_id(id: &str, path: &str, ids: &mut HashSet<String>, errors: &mut Vec<ValidationError>) {
    if id.trim().is_empty() {
        errors.push(ValidationError::EmptyField {
            path: format!("{path}.id"),
        });
    } else if !ids.insert(id.to_owned()) {
        errors.push(ValidationError::DuplicateId { id: id.to_owned() });
    }
}

fn check_non_empty(value: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if value.trim().is_empty() {
        errors.push(ValidationError::EmptyField {
            path: path.to_owned(),
        });
    }
}

fn check_confidence(value: Option<f32>, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(value) = value
        && (!(0.0..=1.0).contains(&value) || !value.is_finite())
    {
        errors.push(ValidationError::InvalidConfidence {
            path: path.to_owned(),
            value,
        });
    }
}

fn check_evidence(evidence: &Evidence, path: &str, errors: &mut Vec<ValidationError>) {
    check_confidence(evidence.confidence, &format!("{path}.confidence"), errors);

    if evidence.level == EvidenceLevel::Observed && evidence.source.is_none() {
        errors.push(ValidationError::ObservedEvidenceMissingSource {
            path: path.to_owned(),
        });
    }

    if evidence.level == EvidenceLevel::Inferred
        && evidence
            .rule_id
            .as_deref()
            .is_none_or(|rule_id| rule_id.trim().is_empty())
    {
        errors.push(ValidationError::InferredEvidenceMissingRule {
            path: path.to_owned(),
        });
    }
}
