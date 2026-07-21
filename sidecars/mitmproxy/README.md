# CodeIsCheap mitmproxy sidecar

This component pins mitmproxy and packages a single-file `mitmdump` executable that always loads the CodeIsCheap capture addon. Artifacts use Tauri target-triple names such as `codeischeap-mitmproxy-x86_64-pc-windows-msvc.exe`.

The parent process must provide:

```text
CIC_CAPTURE_IPC_ADDR=127.0.0.1:<ephemeral-port>
# POSIX desktop transport:
CIC_CAPTURE_IPC_ADDR=unix:/absolute/private/path/capture.sock
CIC_CAPTURE_IPC_TOKEN=<random-per-launch-token>
CIC_CAPTURE_STARTUP_TOKEN=<independent-random-per-launch-token>
CIC_CAPTURE_HOSTS=api.openai.com,api.anthropic.com
```

The addon loads `policies/capture-policy.v0.1.json` and only records exact target hosts, approved POST paths, and methods. `CIC_CAPTURE_HOSTS` can opt an OpenAI-compatible host into the same approved path set; it does not disable path checks. The addon removes credential headers, sensitive query fields, and recursively named JSON secret fields before sending an authenticated NDJSON envelope. Unsupported request body formats are omitted. The original network request is not modified. IPC 0.6 accepts non-zero loopback TCP, a bounded absolute Unix socket on POSIX, or a local `\\.\pipe\CodeIsCheap-capture-*` named pipe on Windows. Relative or oversized Unix paths, foreign/remote pipe namespaces, and platform-incompatible endpoints fail closed.

Startup is authenticated separately from capture IPC. The reserved `codeischeap.invalid` readiness route is always terminated inside the addon and returns the per-launch startup token only for the versioned probe. The desktop rejects a listener that merely occupies the selected port, returns the wrong token, or runs an older addon.

Capture delivery uses a bounded non-blocking queue. A full queue drops only the capture event. The first IPC delivery failure discards the pending backlog and opens a 10-second retry circuit; proxy forwarding continues, and the next event after the cooldown probes IPC recovery.

```powershell
python -m pip install -r sidecars/mitmproxy/requirements-build.txt
python -m unittest discover -s sidecars/mitmproxy/tests -v
python sidecars/mitmproxy/package_sidecar.py
python sidecars/mitmproxy/verify_sidecar_bundle.py sidecars/mitmproxy/dist
python sidecars/mitmproxy/install_sidecar_bundle.py sidecars/mitmproxy/dist apps/desktop/src-tauri/resources/sidecar
```

The bundle contains the executable, capture policy, CycloneDX SBOM, and `sidecar-manifest.json`. The manifest fixes the app, mitmproxy, protocol, envelope and policy versions; records hashes, size, target triple, allowed environment variables, startup/forwarding probes and platform signature status.

CI artifacts are intentionally unsigned. A release pipeline must sign first, rebuild the manifest so the platform verifier records `valid`, then enforce:

```powershell
python sidecars/mitmproxy/verify_sidecar_bundle.py sidecars/mitmproxy/dist --require-signature
```

Release builds install the verified bundle into `apps/desktop/src-tauri/resources/sidecar` before `tauri build`. Installation stages and revalidates all four declared files, restores the Unix executable bit, then atomically replaces the previous resource bundle.
