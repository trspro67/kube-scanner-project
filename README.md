# kubesec

A small Go CLI for Kubernetes security checks and container image vulnerabilities.

## Quick start

[Download a release](https://github.com/trspro67/kube-scanner-project/releases/latest)
for your OS and processor. Unzip it and open a terminal in the extracted folder.
kubectl and Trivy are included; keep `bin/` beside the executable.

```sh
./kubesec scan                         # Current cluster and namespace
./kubesec scan examples/pod.yaml       # YAML file or directory
./kubesec scan image nginx:latest      # Image vulnerabilities via Trivy
```

On Windows, use `.\kubesec.exe`. Cluster scans need a configured kubeconfig and
permission to list pods. Image scans need internet access for the registry and
vulnerability database.

## Checks

Checks privileged containers, host networking, host PID sharing, and privilege
escalation. Findings include severity and a suggested fix. Image findings show
fixed package versions when Trivy reports them.

Supports Pod and Deployment YAML, including init containers. Live scans read pods
in one namespace; use `--namespace NAME` to choose another. Scans are read-only.
This prototype covers a small set of checks, not a full security audit.

## Development

Requires Go 1.27.2 or newer. Source runs also need kubectl for cluster scans and
Trivy for image scans.

```sh
go run . scan examples/pod.yaml
go test ./...
go build -o kubesec .
```

## Packaging

Run `bash scripts/package.sh all` on macOS or Linux to create ZIPs in `dist/`.
Supports macOS and Linux on AMD64/ARM64, plus Windows AMD64.

GitHub Actions tests all five bundles. Pushing a new `vX.Y.Z` tag publishes a
release with the ZIPs and checksums after the checks pass.
