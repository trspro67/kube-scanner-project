package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestClusterPodsUseExistingChecks(t *testing.T) {
	// This fixture follows the list returned by kubectl, including omitted kind.
	data := []byte(`apiVersion: v1
kind: PodList
items:
  - metadata:
      name: risky
      namespace: demo
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: web
          securityContext:
            privileged: true
  - kind: Pod
    metadata:
      name: restricted
      namespace: demo
    spec:
      containers:
        - name: web
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
`)
	pods, err := parsePodList(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 2 || pods[0].Kind != "Pod" || pods[0].Metadata.Namespace != "demo" {
		t.Fatalf("pod list metadata was not preserved: %+v", pods)
	}
	if findings := checkPod(pods[0].Spec.PodSpec); len(findings) != 4 {
		t.Errorf("got %d findings for risky pod, want all four checks", len(findings))
	}
	if findings := checkPod(pods[1].Spec.PodSpec); len(findings) != 0 {
		t.Errorf("unexpected findings for restricted settings: %+v", findings)
	}
}

func TestParsePodListRejectsUnexpectedData(t *testing.T) {
	for _, data := range []string{"kind: [", "kind: ConfigMap", "kind: List\nitems:\n  - kind: Secret"} {
		if _, err := parsePodList([]byte(data)); err == nil {
			t.Errorf("expected an error for %q", data)
		}
	}
}

func TestParseEmptyPodList(t *testing.T) {
	pods, err := parsePodList([]byte("kind: List\nitems: []\n"))
	if err != nil || len(pods) != 0 {
		t.Fatalf("expected an empty pod list, got %v, %v", pods, err)
	}
}

func TestKubectlFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this fake executable uses a POSIX shell")
	}
	directory := t.TempDir()
	script := "#!/bin/sh\nprintf 'Forbidden: cannot list pods' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(directory, "kubectl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	_, err := runKubectl("get", "pods")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("expected the Kubernetes permission error, got %v", err)
	}
}

func TestClusterNamespaceSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this fake executable uses a POSIX shell")
	}
	directory := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = "config" ]; then
  printf 'test-context\n%s' "$KUBESEC_TEST_CONTEXT_NAMESPACE"
  exit 0
fi
if [ "$1" != "get" ] || [ "$2" != "pods" ] || [ "$3" != "--context" ] || [ "$4" != "test-context" ] || [ "$5" != "--namespace" ] || [ "$6" != "$KUBESEC_TEST_EXPECT_NAMESPACE" ]; then
  printf 'Unexpected context or namespace arguments' >&2
  exit 1
fi
printf 'kind: List\nitems: []\n'
`
	if err := os.WriteFile(filepath.Join(directory, "kubectl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	tests := []struct {
		name       string
		configured string
		override   string
		want       string
	}{
		{name: "context namespace", configured: "team", want: "team"},
		{name: "explicit namespace", configured: "team", override: "demo", want: "demo"},
		{name: "default namespace", want: "default"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("KUBESEC_TEST_CONTEXT_NAMESPACE", test.configured)
			t.Setenv("KUBESEC_TEST_EXPECT_NAMESPACE", test.want)
			if err := scanCluster(test.override); err != nil {
				t.Fatal(err)
			}
		})
	}
}
