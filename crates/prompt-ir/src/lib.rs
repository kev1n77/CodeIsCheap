//! Provider-neutral Prompt IR used by every CodeIsCheap capture adapter.
//!
//! The crate deliberately distinguishes observed data from derived or inferred
//! data. Consumers must not present inference as wire-level evidence.

mod evidence;
mod model;
mod validation;

pub use evidence::{Evidence, EvidenceLevel, EvidenceSource};
pub use model::{
    BodyState, Completeness, ContextItem, ContextKind, GenerationOptions, Instruction,
    InstructionRole, Message, MessageRole, PROMPT_IR_VERSION, PromptIr, PromptPart, ProviderRef,
    ResponseEvent, ResponseTrace, ToolDefinition,
};
pub use validation::{Validate, ValidationError, ValidationErrors};
