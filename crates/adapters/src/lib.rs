//! Isolated provider adapters that turn sanitized captures into Prompt IR.

mod anthropic;
mod anthropic_response;
mod gemini;
mod gemini_response;
mod model;
mod openai;
mod registry;

pub use anthropic::{ANTHROPIC_ADAPTER_ID, AnthropicAdapter};
pub use gemini::{GEMINI_ADAPTER_ID, GeminiAdapter};
pub use model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, ParseResult,
    PromptAdapter,
};
pub use openai::{OPENAI_ADAPTER_ID, OpenAiAdapter};
pub use registry::AdapterRegistry;
