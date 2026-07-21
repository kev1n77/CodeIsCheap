# CodeIsCheap

产品设计文档为纯静态 HTML，无需安装依赖或启动服务。

直接打开 [`docs/index.html`](./docs/index.html) 即可阅读。

开发执行参考 [`docs/development-plan.html`](./docs/development-plan.html)，日常状态维护在 [`docs/progress.html`](./docs/progress.html)。

支持包接收与分流见 [`docs/support.html`](./docs/support.html)。接收端必须先执行 `python scripts/inspect_support_bundle.py validate <file>`，再使用 `summarize` 生成不含请求内容的工单摘要。

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
npx playwright install chromium
npm run desktop:e2e
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

浏览器质量门禁在 Chromium 中覆盖 960x620 与 1440x900 两种桌面尺寸、明暗主题截图、千条请求虚拟列表、滚动/筛选预算和横向溢出。Linux 基线需要更新时执行 `npm run desktop:e2e:update`。Gateway 延迟预算可独立复测：

```powershell
cargo test -p codeischeap-gateway --test performance -- --ignored --nocapture --test-threads=1
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

捕获 sidecar 位于 `sidecars/mitmproxy`，跨进程契约位于 `crates/capture-ipc`，公开 CaptureEnvelope Schema 位于 `schemas/capture-envelope/v0.1.schema.json`。打包探针会验证 HTTP/1.1、HTTP/2、压缩、流式脱敏、客户端取消与捕获 IPC 背压；捕获队列满时只丢弃记录，不阻塞代理转发。sidecar 的安装、测试与打包命令见 [`sidecars/mitmproxy/README.md`](./sidecars/mitmproxy/README.md)。

捕获范围与敏感字段由 `policies/capture-policy.v0.1.json` 定义，公开 schema 位于 `schemas/capture-policy/v0.1.schema.json`。Python sidecar 在 IPC 前执行策略，`crates/core` 在进入持久化前再次拒绝越界请求并删除遗漏凭据。

sidecar IPC 协议为 `0.6`：Windows 桌面使用随机命名、拒绝远端连接且 DACL 仅允许当前用户与 SYSTEM 的 named pipe；macOS/Linux 使用当前 eUID 所有的 `0700` 私有目录内、权限固定为 `0600` 的 POSIX Unix socket。Windows 每条连接从内核读取客户端 PID，Unix 每条连接读取 peer eUID/PID，并与已启动 sidecar 严格匹配。每次 Proxy 会话重新生成 256-bit token，认证帧限制为 1 KiB，并要求 `mitmproxy` 来源声明；认证、数据帧和服务端 ACK 共用 2 秒截止时间，sidecar 在收到 ACK 前保持连接。桌面另生成独立 256-bit readiness token，只有返回该 token 的打包 sidecar 才会被视为启动成功。认证帧可携带严格校验的临时 loopback 端点用于被代理应用的进程归因，该端点不会进入 CaptureEnvelope、持久化或导出。sidecar manifest 分别声明 IPC、Envelope 和 Policy 版本，不兼容 bundle 会在启动前被拒绝。

Gateway 和 Proxy 捕获会按显式客户端标签、User-Agent 规则或捕获模式回退生成带置信度的应用归因。Gateway 客户端可设置 `x-codeischeap-client: <application>` 提供高置信度标签；该内部请求头会在持久化和转发上游前删除。Windows、macOS 与 Linux 上的 Gateway 和 Proxy 会用操作系统 TCP 连接表精确匹配客户端 PID，查询失败时保持未知，不做启发式推断；Linux 通过 `/proc/net/tcp{,6}` 的精确四元组定位 socket inode，并只接受唯一进程 owner。sidecar 自报 PID 会被忽略，用于匹配的临时 socket 端点不会进入持久化或导出。未知客户端会明确显示为低置信度的 `Gateway client` 或 `Proxy client`。

Connection 设置页会按 Proxy bundle、loopback 端点、本地 CA、系统信任和当前会话捕获事件生成兼容诊断。Proxy 全部就绪但仍无事件时，只提示低置信度的代理绕过/证书固定可能性，并提供 Gateway 回退；产品不会尝试绕过证书固定。

## 签名更新

桌面设置页通过 Tauri updater 检查固定的 GitHub Release `latest.json`。安装命令会重新核对版本、切回 Gateway、恢复受管系统代理，并在应用数据目录写入 SQLCipher 备份和版本化恢复 journal 后才下载签名制品。若升级后主库无法打开，应用只接受版本、固定文件名和字节数均匹配的加密快照，并以禁止捕获和系统变更的只读模式开放搜索、检查与脱敏导出。未配置可信公钥的构建会明确禁用更新。

正式 bundle 构建必须在环境中提供：

```powershell
$env:CODEISCHEAP_UPDATER_PUBLIC_KEY = "Tauri minisign public key content"
$env:TAURI_SIGNING_PRIVATE_KEY = "Path or content of the matching private key"
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = "Private key password" # 私钥无密码时可留空
npm run desktop:tauri -- build
```

私钥和密码不得写入仓库、`.env`、构建日志或支持包。正式发布使用受保护的 GitHub `release` environment 和 `.github/workflows/release.yml`；它只接受 main 中版本一致的 tag，要求已签名 sidecar、Windows Authenticode、macOS notarization 与 updater 私钥，并在公开草稿前生成和复核 `latest.json`、`.sig` 与 `release-manifest.v0.1.json`。操作与回滚证据见 [`docs/release.html`](./docs/release.html)。

每个版本还必须提交 `release/notes/v<version>.md` 和 `release/readiness.v0.1.json`。普通 CI 允许 gate 保持 pending 但验证契约；正式发布要求兼容矩阵、支持流程、事故响应、真实管理员矩阵、屏幕阅读器、Beta 指标、独立安全评审与签名回滚证据全部通过，并把 readiness 快照纳入发布清单：

```powershell
python scripts/verify_release_readiness.py --repository-root . --allow-pending
python scripts/verify_release_readiness.py --repository-root . --tag v0.1.0
```

六个人工 gate 的首项证据必须是场景完整、执行人与复核人分离的本地 JSON 包；模板与单包校验命令如下：

```powershell
python scripts/verify_readiness_evidence.py init-manual --gate windows_admin_matrix --release-version 0.1.0 --output path/to/new-evidence.json
python scripts/verify_readiness_evidence.py verify-manual --repository-root . --evidence path/to/completed-evidence.json
```

Beta 参与者从应用 Metrics 页主动导出本机聚合值；Release Owner 使用版本化策略离线去重和汇总，原始文件不进入仓库：

```powershell
python scripts/aggregate_beta_metrics.py --policy release/beta-metrics-policy.v0.1.json --input-directory path/to/reviewed-exports --output path/to/new-beta-report.json --require-ready
python scripts/verify_readiness_evidence.py verify-beta --repository-root . --evidence path/to/new-beta-report.json
```

流程与最小样本量见 [`docs/beta-evidence.html`](./docs/beta-evidence.html)。

系统代理事务与独立恢复 watchdog 位于 `crates/proxy-recovery`；Windows WinINet 与 macOS networksetup backend 均已通过临时 CI runner 的真实强杀恢复实验。

启动 Gateway Spike：

```powershell
$env:CIC_GATEWAY_UPSTREAM = "https://api.openai.com"
$env:CIC_GATEWAY_LISTEN = "127.0.0.1:3210" # 可选
cargo run -p codeischeap-gateway --bin gateway-spike
```

发送到 `http://127.0.0.1:3210` 的 method、path、query、headers 与 body 会流式转发至上游。该独立 Spike 不持久化请求；桌面运行时使用同一 Gateway 转发链路，并额外接入有界捕获、共享 Capture Policy 与本地加密存储。
