# CodeIsCheap

产品设计文档为纯静态 HTML，无需安装依赖或启动服务。

直接打开 [`docs/index.html`](./docs/index.html) 即可阅读。

开发执行参考 [`docs/development-plan.html`](./docs/development-plan.html)，日常状态维护在 [`docs/progress.html`](./docs/progress.html)。

## 当前实现

当前实现包含版本化 Prompt IR、隔离式 OpenAI-compatible 适配器注册表、共享捕获策略、可信 Core 入口、SQLCipher 加密存储、可双向流式转发的本地 AI Gateway，以及 React + Tauri 桌面工作台。

启动桌面工作台：

```powershell
npm ci
npm run desktop:dev
```

校验前端与原生壳：

```powershell
npm run desktop:check
npm run desktop:build
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

校验核心 Rust workspace：

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Rust crate 位于 `crates/prompt-ir`，公开 JSON Schema 位于 `schemas/prompt-ir/v0.1.schema.json`。

解析器注册表位于 `crates/adapters`。OpenAI Responses、Chat Completions 与 Completions 使用固定 capture/golden 样本；适配器错误、panic、未知内容和无匹配协议均会隔离并降级 Raw。

加密存储位于 `crates/storage`：使用 SQLCipher、WAL、版本化迁移与 FTS5，数据库 key 由 Windows Credential Manager 或 macOS Keychain 持有，并覆盖错误密钥拒绝、加密备份恢复与落盘明文 canary 测试。

桌面应用位于 `apps/desktop`。Tauri 通过 OS 凭据库打开 SQLCipher，并从加密数据库加载三栏工作台；桌面运行时接入实时 Gateway/Proxy 捕获，浏览器开发模式使用无凭据 fixture。

桌面 command DTO 定义在 `crates/desktop-api`，公开 Schema 位于 `schemas/desktop-api/v0.1.schema.json`，React 使用的 TypeScript 类型由 Rust 生成。契约变更后执行：

```powershell
cargo run -p codeischeap-desktop-api --bin export-desktop-contract
```

捕获 sidecar 位于 `sidecars/mitmproxy`，跨进程契约位于 `crates/capture-ipc`，公开 CaptureEnvelope Schema 位于 `schemas/capture-envelope/v0.1.schema.json`。sidecar 的安装、测试与打包命令见 [`sidecars/mitmproxy/README.md`](./sidecars/mitmproxy/README.md)。

捕获范围与敏感字段由 `policies/capture-policy.v0.1.json` 定义，公开 schema 位于 `schemas/capture-policy/v0.1.schema.json`。Python sidecar 在 IPC 前执行策略，`crates/core` 在进入持久化前再次拒绝越界请求并删除遗漏凭据。

sidecar IPC 协议为 `0.4`：仅监听 loopback，使用每次 Proxy 会话重新生成的 256-bit token，认证帧限制为 1 KiB，并要求 `mitmproxy` 来源声明；认证、数据帧、Windows/macOS/Linux 首连接 sidecar PID 校验与服务端 ACK 共用 2 秒截止时间，sidecar 在收到 ACK 前保持连接。认证帧可携带严格校验的临时 loopback 端点用于进程归因，端点不会进入 CaptureEnvelope、持久化或导出。sidecar manifest 分别声明 IPC、Envelope 和 Policy 版本，不兼容 bundle 会在启动前被拒绝。

Gateway 和 Proxy 捕获会按显式客户端标签、User-Agent 规则或捕获模式回退生成带置信度的应用归因。Gateway 客户端可设置 `x-codeischeap-client: <application>` 提供高置信度标签；该内部请求头会在持久化和转发上游前删除。Windows、macOS 与 Linux 上的 Gateway 和 Proxy 会用操作系统 TCP 连接表精确匹配客户端 PID，查询失败时保持未知，不做启发式推断；Linux 通过 `/proc/net/tcp{,6}` 的精确四元组定位 socket inode，并只接受唯一进程 owner。sidecar 自报 PID 会被忽略，用于匹配的临时 socket 端点不会进入持久化或导出。未知客户端会明确显示为低置信度的 `Gateway client` 或 `Proxy client`。

Connection 设置页会按 Proxy bundle、loopback 端点、本地 CA、系统信任和当前会话捕获事件生成兼容诊断。Proxy 全部就绪但仍无事件时，只提示低置信度的代理绕过/证书固定可能性，并提供 Gateway 回退；产品不会尝试绕过证书固定。

系统代理事务与独立恢复 watchdog 位于 `crates/proxy-recovery`；Windows WinINet 与 macOS networksetup backend 均已通过临时 CI runner 的真实强杀恢复实验。

启动 Gateway Spike：

```powershell
$env:CIC_GATEWAY_UPSTREAM = "https://api.openai.com"
$env:CIC_GATEWAY_LISTEN = "127.0.0.1:3210" # 可选
cargo run -p codeischeap-gateway --bin gateway-spike
```

发送到 `http://127.0.0.1:3210` 的 method、path、query、headers 与 body 会流式转发至上游。该独立 Spike 不持久化请求；桌面运行时使用同一 Gateway 转发链路，并额外接入有界捕获、共享 Capture Policy 与本地加密存储。
