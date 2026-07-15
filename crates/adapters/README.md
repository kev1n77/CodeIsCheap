# CodeIsCheap Adapters

Provider adapters receive only `SanitizedCapture` values and emit validated Prompt IR. The registry orders candidates by confidence, isolates adapter errors and panics, and falls back to Raw when no valid adapter succeeds.

The OpenAI-compatible adapter currently covers:

- `/v1/responses`
- `/v1/chat/completions`
- `/v1/completions`
- system/developer/user/assistant/tool messages
- text, image, audio, file, tool call, and tool result parts
- function definitions and common generation parameters

Regenerate checked-in golden Prompt IR after an intentional mapping change:

```powershell
cargo run -p codeischeap-adapters --bin export-openai-goldens
cargo test -p codeischeap-adapters --all-targets
```
