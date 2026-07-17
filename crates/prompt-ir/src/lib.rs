//! Provider-neutral Prompt IR used by every CodeIsCheap capture adapter.
//!
//! The crate deliberately distinguishes observed data from derived or inferred
//! data. Consumers must not present inference as wire-level evidence.

mod evidence;
mod metrics;
mod model;
mod validation;

pub use evidence::{Evidence, EvidenceLevel, EvidenceSource};
pub use metrics::{PRICING_CATALOG_VERSION, enrich_metrics};
pub use model::{
    BodyState, Completeness, ContextItem, ContextKind, GenerationOptions, Instruction,
    InstructionRole, Message, MessageRole, MetricSource, PROMPT_IR_VERSION, PricingCost, PromptIr,
    PromptMetrics, PromptPart, ProviderRef, ResponseEvent, ResponseTrace, SemanticFingerprint,
    TokenMeasurement, ToolDefinition,
};
pub use validation::{Validate, ValidationError, ValidationErrors};
