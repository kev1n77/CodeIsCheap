# CodeIsCheap

产品设计文档为纯静态 HTML，无需安装依赖或启动服务。

直接打开 [`docs/index.html`](./docs/index.html) 即可阅读。

开发执行参考 [`docs/development-plan.html`](./docs/development-plan.html)，日常状态维护在 [`docs/progress.html`](./docs/progress.html)。

## 当前实现

当前 Rust workspace 包含版本化 Prompt IR 契约，以及可双向流式转发的本地 AI Gateway：

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Rust crate 位于 `crates/prompt-ir`，公开 JSON Schema 位于 `schemas/prompt-ir/v0.1.schema.json`。

捕获 sidecar 位于 `sidecars/mitmproxy`，跨进程契约位于 `crates/capture-ipc`，公开 CaptureEnvelope Schema 位于 `schemas/capture-envelope/v0.1.schema.json`。sidecar 的安装、测试与打包命令见 [`sidecars/mitmproxy/README.md`](./sidecars/mitmproxy/README.md)。

系统代理事务与独立恢复 watchdog 的平台无关核心位于 `crates/proxy-recovery`；当前使用文件 backend 做强杀故障注入，真实 Windows/macOS backend 尚在开发。

启动 Gateway Spike：

```powershell
$env:CIC_GATEWAY_UPSTREAM = "https://api.openai.com"
$env:CIC_GATEWAY_LISTEN = "127.0.0.1:3210" # 可选
cargo run -p codeischeap-gateway --bin gateway-spike
```

发送到 `http://127.0.0.1:3210` 的 method、path、query、headers 与 body 会流式转发至上游；Gateway 不记录请求头或请求体。当前 Spike 用于验证技术路径，捕获、脱敏与持久化尚未接入。
