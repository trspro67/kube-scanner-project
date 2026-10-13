#!/usr/bin/env bash
set -euo pipefail

# Build on macOS or Linux. Recipients only need to unzip the result.
if [[ $# -eq 1 && "$1" == all ]]; then
  for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do
    bash "$0" "${target%/*}" "${target#*/}"
  done
  exit 0
fi
if [[ $# -ne 0 && $# -ne 2 ]]; then
  printf 'Usage: bash scripts/package.sh [all | <os> <arch>]\n' >&2
  exit 1
fi
target_os="${1:-$(go env GOHOSTOS)}"
target_arch="${2:-$(go env GOHOSTARCH)}"
kubectl_version="${KUBECTL_VERSION:-v1.33.9}"
trivy_version="${TRIVY_VERSION:-0.75.0}"

# Trivy's release names differ from Go's target names.
case "$target_os/$target_arch" in
  darwin/amd64) trivy_platform=macOS-64bit ;;
  darwin/arm64) trivy_platform=macOS-ARM64 ;;
  linux/amd64) trivy_platform=Linux-64bit ;;
  linux/arm64) trivy_platform=Linux-ARM64 ;;
  windows/amd64) trivy_platform=windows-64bit ;;
  *) printf 'No bundled Trivy release for %s/%s.\n' "$target_os" "$target_arch" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
mkdir -p dist
work="$(mktemp -d "$root/dist/.package.XXXXXX")"
trap 'rm -rf "$work"' EXIT
name="kubesec-$target_os-$target_arch"
bundle="$work/$name"
mkdir -p "$bundle/bin" "$bundle/licenses" "$work/trivy"
suffix=""
archive_ext=tar.gz
if [[ "$target_os" == windows ]]; then
  suffix=.exe
  archive_ext=zip
fi

download() {
  curl --fail --silent --show-error --location --retry 2 --connect-timeout 15 --max-time 180 "$1" --output "$2"
}

verify() {
  local file="$1" expected="$2" actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  fi
  if [[ ! "$expected" =~ ^[a-fA-F0-9]{64}$ || "$actual" != "$expected" ]]; then
    printf 'Checksum verification failed for %s.\n' "$file" >&2
    exit 1
  fi
}

printf 'Building %s with kubectl %s and Trivy %s...\n' "$name" "$kubectl_version" "$trivy_version"
CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -o "$bundle/kubesec$suffix" .

kubectl_url="https://dl.k8s.io/release/$kubectl_version/bin/$target_os/$target_arch/kubectl$suffix"
download "$kubectl_url" "$bundle/bin/kubectl$suffix"
download "$kubectl_url.sha256" "$work/kubectl.sha256"
verify "$bundle/bin/kubectl$suffix" "$(tr -d '[:space:]' < "$work/kubectl.sha256")"

trivy_archive="trivy_${trivy_version}_${trivy_platform}.$archive_ext"
trivy_url="https://github.com/aquasecurity/trivy/releases/download/v$trivy_version"
download "$trivy_url/$trivy_archive" "$work/$trivy_archive"
download "$trivy_url/trivy_${trivy_version}_checksums.txt" "$work/trivy-checksums.txt"
verify "$work/$trivy_archive" "$(awk -v name="$trivy_archive" '$2 == name {print $1}' "$work/trivy-checksums.txt")"
if [[ "$target_os" == windows ]]; then
  unzip -q "$work/$trivy_archive" -d "$work/trivy"
else
  tar -xzf "$work/$trivy_archive" -C "$work/trivy" trivy LICENSE README.md
fi
cp "$work/trivy/trivy$suffix" "$bundle/bin/"
chmod +x "$bundle/bin/kubectl$suffix" "$bundle/bin/trivy$suffix"

# Preserve upstream licenses and notices with the distributed binaries.
cp "$work/trivy/LICENSE" "$bundle/licenses/trivy-LICENSE"
cp "$work/trivy/README.md" "$bundle/licenses/trivy-README.md"
download "https://raw.githubusercontent.com/aquasecurity/trivy/v$trivy_version/NOTICE" "$bundle/licenses/trivy-NOTICE"
download "https://raw.githubusercontent.com/kubernetes/kubernetes/$kubectl_version/LICENSE" "$bundle/licenses/kubectl-LICENSE"
cp "$(go env GOROOT)/LICENSE" "$bundle/licenses/go-LICENSE"
yaml_dir="$(go list -m -f '{{.Dir}}' go.yaml.in/yaml/v3)"
cp "$yaml_dir/LICENSE" "$bundle/licenses/yaml-LICENSE"
cp "$yaml_dir/NOTICE" "$bundle/licenses/yaml-NOTICE"

cat > "$bundle/DEPENDENCIES.txt" <<EOF
kubectl: $kubectl_version (https://github.com/kubernetes/kubernetes)
Trivy: $trivy_version (https://github.com/aquasecurity/trivy)
Go: $(go env GOVERSION)
YAML: $(go list -m -f '{{.Version}}' go.yaml.in/yaml/v3)

kubectl and Trivy are unmodified upstream binaries in bin/.
Keep bin/ next to kubesec. Licenses and notices are in licenses/.
Cluster scans use your kubeconfig and may require your provider's login tool.
Image scans download vulnerability databases and may need registry credentials.
EOF
cp README.md "$bundle/README.md"
cp -R examples "$bundle/examples"

# Create a fresh archive, avoiding stale files when rebuilding a package.
(cd "$work" && zip -qr "$name.zip" "$name")
mv "$work/$name.zip" "$root/dist/$name.zip"
printf 'Created %s/dist/%s.zip\n' "$root" "$name"
