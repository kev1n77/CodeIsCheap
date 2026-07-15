//! Isolated provider adapters that turn sanitized captures into Prompt IR.

mod model;
mod openai;
mod registry;

pub use model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, ParseResult,
    PromptAdapter,
};
pub use openai::{OPENAI_ADAPTER_ID, OpenAiAdapter};
pub use registry::AdapterRegistry;
