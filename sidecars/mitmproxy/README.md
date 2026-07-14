# CodeIsCheap mitmproxy sidecar

This spike pins mitmproxy and packages a single-file `mitmdump` executable that always loads the CodeIsCheap capture addon.

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
```

The generated `dist/sidecar-manifest.json` records version, size, hash, startup probe, forwarding fidelity, and credential-canary results. Spike artifacts are intentionally unsigned; production signing and SBOM generation remain release requirements.
