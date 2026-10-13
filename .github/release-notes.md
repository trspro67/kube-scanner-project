A small Go prototype for scanning Kubernetes configuration and container images.

Download the ZIP for your operating system and processor, extract it, and open
a terminal in the extracted folder. Each ZIP includes kubesec, kubectl, Trivy,
example manifests, a README, and dependency license notices.

- macOS: `darwin-amd64` for Intel, `darwin-arm64` for Apple Silicon.
- Linux: `linux-amd64` for Intel/AMD, `linux-arm64` for ARM64.
- Windows: `windows-amd64` for Intel/AMD 64-bit Windows.

```sh
./kubesec scan examples/pod.yaml
./kubesec scan examples/pod-safe.yaml
./kubesec scan image nginx:latest
./kubesec scan
```

On Windows, use `.\kubesec.exe` in PowerShell. Keep `bin/` beside the executable.
Live cluster scans need your kubeconfig and cluster access. Image scans download
Trivy's vulnerability databases and may need registry credentials.

The configuration checks cover privileged containers, host network and PID
sharing, and privilege escalation settings in Pods and Deployments. This is a
prototype with a limited rule set; no findings does not mean the workload is
secure. Image vulnerabilities are reported by Trivy.

All five bundles pass Go tests, `go vet`, bundled executable checks, safe and
unsafe YAML examples, and an image scan on matching native GitHub runners before
publication. Live cluster scanning is not part of these automated checks.

`SHA256SUMS` contains the checksums of the five ZIP files.
