package main

// These structs contain only the fields needed for the first few checks.
type Manifest struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		PodSpec  `yaml:",inline"`
		Template struct {
			Spec PodSpec `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type PodSpec struct {
	OS struct {
		Name string `yaml:"name"`
	} `yaml:"os"`
	HostNetwork    bool        `yaml:"hostNetwork"`
	HostPID        bool        `yaml:"hostPID"`
	Containers     []Container `yaml:"containers"`
	InitContainers []Container `yaml:"initContainers"`
}

type Container struct {
	Name            string `yaml:"name"`
	Image           string `yaml:"image"`
	SecurityContext struct {
		// Pointers distinguish an omitted setting (nil) from explicit false.
		Privileged               *bool `yaml:"privileged"`
		AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
	} `yaml:"securityContext"`
}

type Finding struct {
	Severity  string
	Container string // Leave empty for pod-level findings.
	Message   string
	Fix       string
}

func checkPod(spec PodSpec) []Finding {
	var findings []Finding

	// Host namespace settings belong to the pod; report each once.
	if spec.HostNetwork {
		findings = append(findings, Finding{
			Severity: "MEDIUM",
			Message:  "Pod shares the host network namespace, reducing network isolation.",
			Fix:      "Set hostNetwork to false in the pod spec unless host networking is required.",
		})
	}
	if spec.HostPID {
		findings = append(findings, Finding{
			Severity: "MEDIUM",
			Message:  "Pod shares the host PID namespace, reducing process isolation.",
			Fix:      "Set hostPID to false in the pod spec unless host process visibility is required.",
		})
	}

	// Visit both groups so init containers receive the same checks.
	for _, containers := range [][]Container{spec.Containers, spec.InitContainers} {
		for _, container := range containers {
			privileged := container.SecurityContext.Privileged
			// && stops before reading the pointer when it is nil.
			if privileged != nil && *privileged {
				findings = append(findings, Finding{
					Severity:  "HIGH",
					Container: container.Name,
					Message:   "Privileged mode is enabled.",
					Fix:       "Set securityContext.privileged to false if privileged access is not required.",
				})
			}

			allowEscalation := container.SecurityContext.AllowPrivilegeEscalation
			// This Linux-only rule requires an explicit false; nil also triggers it.
			if spec.OS.Name != "windows" && (allowEscalation == nil || *allowEscalation) {
				findings = append(findings, Finding{
					Severity:  "MEDIUM",
					Container: container.Name,
					Message:   "Privilege escalation is not explicitly disabled.",
					Fix:       "Set securityContext.allowPrivilegeEscalation to false when escalation is not required.",
				})
			}
		}
	}

	return findings
}
