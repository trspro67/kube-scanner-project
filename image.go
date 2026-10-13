package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// We only decode the report fields used by our output. Other JSON fields are ignored.
type ImageReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []ImageResult `json:"Results"`
}

type ImageResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []ImageVulnerability `json:"Vulnerabilities"`
}

type ImageVulnerability struct {
	ID        string `json:"VulnerabilityID"`
	Package   string `json:"PkgName"`
	Installed string `json:"InstalledVersion"`
	Fixed     string `json:"FixedVersion"`
	Severity  string `json:"Severity"`
}

func scanImage(image string) error {
	if strings.TrimSpace(image) == "" {
		return errors.New("provide a container image reference")
	}
	fmt.Printf("Scanning image vulnerabilities: %s\n", image)
	data, err := runTrivy(image)
	if err != nil {
		return err
	}
	report, err := parseImageReport(data)
	if err != nil {
		return err
	}
	printImageReport(report)
	return nil
}

func runTrivy(image string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// JSON goes to stdout. Diagnostics go to stderr, so they cannot corrupt JSON.
	// --exit-code 0 means findings are a successful scan, not a process failure.
	command := exec.CommandContext(ctx, toolPath("trivy"), "image", "--scanners", "vuln",
		"--format", "json", "--exit-code", "0", "--no-progress", "--quiet", "--", image)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("image scan timed out after 2 minutes: %w", ctx.Err())
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("Trivy is required for image scanning; keep the package's bin folder or install trivy on PATH")
		}
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("Trivy failed: %s", message)
		}
		return nil, fmt.Errorf("Trivy failed: %w", err)
	}
	return output, nil
}

func parseImageReport(data []byte) (ImageReport, error) {
	var report ImageReport
	if err := json.Unmarshal(data, &report); err != nil {
		return report, fmt.Errorf("decode Trivy JSON: %w", err)
	}
	// Reject unexpected data rather than accidentally reporting an empty scan.
	if report.SchemaVersion != 2 || report.ArtifactType != "container_image" || report.ArtifactName == "" {
		return report, errors.New("expected a Trivy schema version 2 container-image report")
	}
	return report, nil
}

func printImageReport(report ImageReport) {
	fmt.Printf("Image: %s\n", report.ArtifactName)
	count := 0
	for _, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		fmt.Printf("\nTarget: %s\n", result.Target)
		for _, vulnerability := range result.Vulnerabilities {
			fixed := vulnerability.Fixed
			if fixed == "" {
				fixed = "not reported"
			}
			fmt.Printf("  %s %s: %s\n    Installed: %s | Fixed: %s\n",
				severityLabel(vulnerability.Severity), vulnerability.ID, vulnerability.Package,
				vulnerability.Installed, fixed)
			count++
		}
	}
	if count == 0 {
		fmt.Printf("  %s\n", colorize("No known vulnerabilities reported by Trivy.", ansiGreen))
		return
	}
	fmt.Printf("\nVulnerability findings: %d\n", count)
}
