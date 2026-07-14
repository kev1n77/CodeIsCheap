# CodeIsCheap

产品设计文档为纯静态 HTML，无需安装依赖或启动服务。

直接打开 [`docs/index.html`](./docs/index.html) 即可阅读。

开发执行参考 [`docs/development-plan.html`](./docs/development-plan.html)，日常状态维护在 [`docs/progress.html`](./docs/progress.html)。

## 当前实现

首个工程提交实现了版本化 Prompt IR 核心契约：

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Rust crate 位于 `crates/prompt-ir`，公开 JSON Schema 位于 `schemas/prompt-ir/v0.1.schema.json`。
