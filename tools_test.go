package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestToolPathPrefersBundledTool(t *testing.T) {
	directory := t.TempDir()
	bin := filepath.Join(directory, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	name := "trivy"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	want := filepath.Join(bin, name)
	if err := os.WriteFile(want, []byte("test executable"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	if got := toolPathIn(directory, "trivy"); got != want {
		t.Fatalf("got %q, want bundled tool %q", got, want)
	}
}

func TestToolPathFallsBackWhenBundleIsAbsent(t *testing.T) {
	want := "kubectl"
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := toolPathIn(t.TempDir(), "kubectl"); got != want {
		t.Fatalf("got %q, want PATH lookup for %q", got, want)
	}
}
