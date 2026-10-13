package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseImageReport(t *testing.T) {
	data, err := os.ReadFile("testdata/trivy-report.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseImageReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if report.ArtifactName != "example:latest" || len(report.Results) != 2 {
		t.Fatalf("image name or result groups were lost: %+v", report)
	}
	vulnerabilities := report.Results[0].Vulnerabilities
	if len(vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(vulnerabilities))
	}
	first := vulnerabilities[0]
	if first.ID != "CVE-EXAMPLE-0001" || first.Package != "lib-example" || first.Installed != "1.0" || first.Fixed != "1.1" || first.Severity != "HIGH" {
		t.Errorf("JSON fields were not mapped correctly: %+v", first)
	}
	if vulnerabilities[1].Fixed != "" {
		t.Errorf("missing FixedVersion must stay empty, got %q", vulnerabilities[1].Fixed)
	}
	if len(report.Results[1].Vulnerabilities) != 0 {
		t.Error("a null vulnerability list should decode as empty")
	}
}

func TestImageReportWithoutVulnerabilities(t *testing.T) {
	data := []byte(`{"SchemaVersion":2,"ArtifactName":"example:latest","ArtifactType":"container_image","Results":[]}`)
	report, err := parseImageReport(data)
	if err != nil || len(report.Results) != 0 {
		t.Fatalf("expected a valid empty report, got %+v, %v", report, err)
	}
}

func TestImageReportRejectsUnexpectedData(t *testing.T) {
	for _, data := range []string{
		`{`,
		`{}`,
		`null`,
		`{"SchemaVersion":99,"ArtifactName":"example","ArtifactType":"container_image"}`,
		`{"SchemaVersion":2,"ArtifactName":"example","ArtifactType":"filesystem"}`,
	} {
		if _, err := parseImageReport([]byte(data)); err == nil {
			t.Errorf("expected an error for %s", data)
		}
	}
}

func TestTrivyFailureIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this fake executable uses a POSIX shell")
	}
	directory := t.TempDir()
	script := "#!/bin/sh\nprintf 'registry authentication required' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(directory, "trivy"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	_, err := runTrivy("example:latest")
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Fatalf("expected the scanner error, got %v", err)
	}
}
