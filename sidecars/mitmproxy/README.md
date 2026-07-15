# CodeIsCheap mitmproxy sidecar

This component pins mitmproxy and packages a single-file `mitmdump` executable that always loads the CodeIsCheap capture addon. Artifacts use Tauri target-triple names such as `codeischeap-mitmproxy-x86_64-pc-windows-msvc.exe`.

The parent process must provide:

```text
CIC_CAPTURE_IPC_ADDR=127.0.0.1:<ephemeral-port>
CIC_CAPTURE_IPC_TOKEN=<random-per-launch-token>
CIC_CAPTURE_HOSTS=api.openai.com,api.anthropic.com
```

The addon loads `policies/capture-policy.v0.1.json` and only records exact target hosts, approved POST paths, and methods. `CIC_CAPTURE_HOSTS` can opt an OpenAI-compatible host into the same approved path set; it does not disable path checks. The addon removes credential headers, sensitive query fields, and recursively named JSON secret fields before sending an authenticated NDJSON envelope. Unsupported request body formats are omitted. The original network request is not modified.

```powershell
python -m pip install -r sidecars/mitmproxy/requirements-build.txt
python -m unittest discover -s sidecars/mitmproxy/tests -v
python sidecars/mitmproxy/package_sidecar.py
python sidecars/mitmproxy/verify_sidecar_bundle.py sidecars/mitmproxy/dist
```

The bundle contains the executable, capture policy, CycloneDX SBOM, and `sidecar-manifest.json`. The manifest fixes the app, mitmproxy, protocol, envelope and policy versions; records hashes, size, target triple, allowed environment variables, startup/forwarding probes and platform signature status.

CI artifacts are intentionally unsigned. A release pipeline must sign first, rebuild the manifest so the platform verifier records `valid`, then enforce:

```powershell
python sidecars/mitmproxy/verify_sidecar_bundle.py sidecars/mitmproxy/dist --require-signature
```
