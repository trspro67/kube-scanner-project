package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

func scanCluster(namespace string) error {
	// Read only the context name and namespace, without exposing credentials.
	config, err := runKubectl("config", "view", "--minify", "-o",
		`jsonpath={.current-context}{"\n"}{.contexts[0].context.namespace}`)
	if err != nil {
		return fmt.Errorf("read current Kubernetes context: %w", err)
	}
	fields := strings.SplitN(string(config), "\n", 2)
	contextName := strings.TrimSpace(fields[0])
	if contextName == "" {
		return errors.New("no current Kubernetes context is configured")
	}
	if namespace == "" && len(fields) == 2 {
		namespace = strings.TrimSpace(fields[1])
	}
	if namespace == "" {
		namespace = "default"
	}
	fmt.Printf("Checking pod security settings.\nContext: %s | Namespace: %s\n", contextName, namespace)

	// Pin the selected context and namespace for this read-only request.
	data, err := runKubectl("get", "pods", "--context", contextName,
		"--namespace", namespace, "--request-timeout=10s", "-o", "yaml")
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	pods, err := parsePodList(data)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		fmt.Println("No pods found in this namespace.")
		return nil
	}
	for _, pod := range pods {
		printManifest("cluster", pod)
	}
	return nil
}

func parsePodList(data []byte) ([]Manifest, error) {
	var list struct {
		Kind  string     `yaml:"kind"`
		Items []Manifest `yaml:"items"`
	}
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("decode cluster pods: %w", err)
	}
	if list.Kind != "List" && list.Kind != "PodList" {
		return nil, fmt.Errorf("expected a Kubernetes pod list, got kind %q", list.Kind)
	}
	for i := range list.Items {
		// Typed Kubernetes lists may omit kind from individual items.
		if list.Items[i].Kind == "" {
			list.Items[i].Kind = "Pod"
		}
		if list.Items[i].Kind != "Pod" {
			return nil, fmt.Errorf("expected Pod in cluster results, got %q", list.Items[i].Kind)
		}
	}
	return list.Items, nil
}

func runKubectl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Pass arguments directly to the executable; no shell is involved.
	command := exec.CommandContext(ctx, toolPath("kubectl"), args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("kubectl timed out: %w", ctx.Err())
		}
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("kubectl is required for live scanning; keep the package's bin folder or install kubectl on PATH")
		}
		if message := strings.TrimSpace(stderr.String()); message != "" {
			// kubectl may repeat discovery warnings; keep its final error line.
			lines := strings.Split(message, "\n")
			return nil, fmt.Errorf("kubectl failed: %s", lines[len(lines)-1])
		}
		return nil, fmt.Errorf("kubectl failed: %w", err)
	}
	return output, nil
}
