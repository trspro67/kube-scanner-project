package main

import (
	"strings"
	"testing"
)

func TestCheckPod(t *testing.T) {
	enabled, disabled := true, false
	privileged := testContainer("web")
	privileged.SecurityContext.Privileged = &enabled
	unprivileged := testContainer("safe")
	unprivileged.SecurityContext.Privileged = &disabled
	initContainer := testContainer("setup")
	initContainer.SecurityContext.Privileged = &enabled

	tests := []struct {
		name           string
		spec           PodSpec
		wantContainers []string
	}{
		{
			name:           "privileged regular container",
			spec:           PodSpec{Containers: []Container{privileged}},
			wantContainers: []string{"web"},
		},
		{
			name: "explicitly unprivileged container",
			spec: PodSpec{Containers: []Container{unprivileged}},
		},
		{
			name: "omitted privileged setting",
			spec: PodSpec{Containers: []Container{testContainer("default")}},
		},
		{
			name:           "privileged init container",
			spec:           PodSpec{InitContainers: []Container{initContainer}},
			wantContainers: []string{"setup"},
		},
		{
			name: "mixed regular and init containers",
			spec: PodSpec{
				Containers:     []Container{unprivileged, privileged},
				InitContainers: []Container{initContainer},
			},
			wantContainers: []string{"web", "setup"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := checkPod(test.spec)
			if len(findings) != len(test.wantContainers) {
				t.Fatalf("got %d findings, want %d", len(findings), len(test.wantContainers))
			}
			for i, finding := range findings {
				if finding.Container != test.wantContainers[i] {
					t.Errorf("got container %q, want %q", finding.Container, test.wantContainers[i])
				}
				if finding.Severity != "HIGH" || finding.Message == "" || finding.Fix == "" {
					t.Errorf("finding must include HIGH severity, an explanation, and a fix: %+v", finding)
				}
			}
		})
	}
}

func TestHostNetworkReportedOnce(t *testing.T) {
	findings := checkPod(PodSpec{
		HostNetwork:    true,
		Containers:     []Container{testContainer("web"), testContainer("sidecar")},
		InitContainers: []Container{testContainer("setup")},
	})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one pod-level finding", len(findings))
	}
	finding := findings[0]
	if finding.Container != "" || finding.Severity != "MEDIUM" || finding.Message == "" || finding.Fix == "" {
		t.Errorf("expected a MEDIUM pod-level finding with explanation and fix: %+v", finding)
	}
}

func TestHostNetworkAndPrivileged(t *testing.T) {
	enabled := true
	container := testContainer("web")
	container.SecurityContext.Privileged = &enabled
	findings := checkPod(PodSpec{
		HostNetwork: true,
		Containers:  []Container{container},
	})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want a host-network and a privileged finding", len(findings))
	}
	if findings[0].Container != "" || findings[0].Severity != "MEDIUM" {
		t.Errorf("expected host-network finding first, got %+v", findings[0])
	}
	if findings[1].Container != "web" || findings[1].Severity != "HIGH" {
		t.Errorf("expected privileged-container finding second, got %+v", findings[1])
	}
}

func TestHostPIDReportedOnce(t *testing.T) {
	findings := checkPod(PodSpec{
		HostPID:        true,
		Containers:     []Container{testContainer("web"), testContainer("sidecar")},
		InitContainers: []Container{testContainer("setup")},
	})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one pod-level finding", len(findings))
	}
	finding := findings[0]
	if finding.Container != "" || finding.Severity != "MEDIUM" {
		t.Errorf("expected a MEDIUM pod-level finding: %+v", finding)
	}
	if !strings.Contains(finding.Message, "PID") || !strings.Contains(finding.Fix, "hostPID") {
		t.Errorf("finding must explain host PID sharing and identify the setting to change: %+v", finding)
	}
}

func TestHostNamespacesAndPrivileged(t *testing.T) {
	enabled := true
	container := testContainer("web")
	container.SecurityContext.Privileged = &enabled
	findings := checkPod(PodSpec{
		HostNetwork: true,
		HostPID:     true,
		Containers:  []Container{container},
	})
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want both host namespace findings and one privileged finding", len(findings))
	}
	if !strings.Contains(findings[0].Fix, "hostNetwork") || !strings.Contains(findings[1].Fix, "hostPID") {
		t.Errorf("expected separate host-network and host-PID recommendations, got %+v", findings[:2])
	}
	if findings[2].Container != "web" || findings[2].Severity != "HIGH" {
		t.Errorf("expected privileged-container finding too, got %+v", findings[2])
	}
}

// Disable escalation in fixtures for tests that focus on other checks.
func testContainer(name string) Container {
	disabled := false
	container := Container{Name: name}
	container.SecurityContext.AllowPrivilegeEscalation = &disabled
	return container
}

func TestPrivilegeEscalation(t *testing.T) {
	enabled, disabled := true, false
	tests := []struct {
		name      string
		allow     *bool
		init      bool
		os        string
		wantCount int
	}{
		{name: "explicitly disabled", allow: &disabled},
		{name: "explicitly enabled", allow: &enabled, wantCount: 1},
		{name: "omitted setting", wantCount: 1},
		{name: "init container omitted setting", init: true, wantCount: 1},
		{name: "init container disabled", allow: &disabled, init: true},
		{name: "Windows omitted setting", os: "windows"},
		{name: "Windows enabled setting", allow: &enabled, os: "windows"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			container := Container{Name: "web"}
			container.SecurityContext.AllowPrivilegeEscalation = test.allow
			spec := PodSpec{}
			spec.OS.Name = test.os
			if test.init {
				spec.InitContainers = []Container{container}
			} else {
				spec.Containers = []Container{container}
			}
			findings := checkPod(spec)
			if len(findings) != test.wantCount {
				t.Fatalf("got %d findings, want %d", len(findings), test.wantCount)
			}
			for _, finding := range findings {
				if finding.Container != "web" || finding.Severity != "MEDIUM" || finding.Message == "" || !strings.Contains(finding.Fix, "allowPrivilegeEscalation") {
					t.Errorf("expected an actionable escalation finding for web: %+v", finding)
				}
			}
		})
	}
}

func TestPrivilegedAndEscalation(t *testing.T) {
	enabled := true
	container := Container{Name: "web"}
	container.SecurityContext.Privileged = &enabled
	container.SecurityContext.AllowPrivilegeEscalation = &enabled
	findings := checkPod(PodSpec{Containers: []Container{container}})
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want privileged and escalation findings", len(findings))
	}
	if findings[0].Severity != "HIGH" || findings[1].Severity != "MEDIUM" {
		t.Errorf("expected both checks to run for the same container: %+v", findings)
	}
}
