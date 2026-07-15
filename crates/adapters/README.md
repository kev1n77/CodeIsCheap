# CodeIsCheap Adapters

Provider adapters receive only `SanitizedCapture` values and emit validated Prompt IR. The registry orders candidates by confidence, isolates adapter errors and panics, and falls back to Raw when no valid adapter succeeds.

[`tests/fixtures/capability-matrix.json`](tests/fixtures/capability-matrix.json) is the source of truth for declared adapter operations and capabilities. Every parsed case names a capture fixture and a checked-in Prompt IR golden; fallback cases name the expected parse issues. The executable matrix test verifies that each declaration is observable in Prompt IR.

The OpenAI-compatible adapter currently covers:

- `/v1/responses`
- `/v1/chat/completions`
- `/v1/completions`
- system/developer/user/assistant/tool messages
- text, image, audio, file, tool call, and tool result parts
- function definitions and common generation parameters

The Anthropic adapter covers Messages and legacy Complete requests, non-streaming JSON responses, and SSE response traces. SSE text, tool input fragments, cumulative usage, stop reasons, errors, and unknown future events retain source evidence.

OpenAI-compatible support currently covers request reconstruction only. Response reconstruction is not declared in the capability matrix.

Regenerate every golden declared by the capability matrix after an intentional mapping change:

```powershell
cargo run -p codeischeap-adapters --bin export-openai-goldens
cargo test -p codeischeap-adapters --test capabilities
```
