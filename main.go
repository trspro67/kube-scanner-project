package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

const usage = `Usage:
  kubesec scan
  kubesec scan --namespace <name>
  kubesec scan <file.yaml|directory>
  kubesec scan image <image>

Checks Pod and Deployment manifests for privileged containers,
host namespace sharing, and privilege escalation settings.
Live scanning requires kubectl and uses the current context and its namespace.
Image vulnerability scanning requires Trivy.`

const (
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiReset  = "\x1b[0m"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(usage)
		return nil
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q; use kubesec --help", args[0])
	}
	if len(args) > 1 && args[1] == "image" {
		if len(args) == 3 && (args[2] == "--help" || args[2] == "-h") {
			fmt.Println(usage)
			return nil
		}
		if len(args) != 3 {
			return errors.New("expected one image; use kubesec scan image <image>")
		}
		return scanImage(args[2])
	}
	scanFlags := flag.NewFlagSet("scan", flag.ContinueOnError)
	scanFlags.Usage = func() { fmt.Println(usage) }
	namespace := scanFlags.String("namespace", "", "Namespace for live cluster scanning")
	if err := scanFlags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	paths := scanFlags.Args()
	if len(paths) == 0 {
		return scanCluster(*namespace)
	}
	if len(paths) != 1 {
		return errors.New("expected one file or directory; use kubesec --help")
	}
	if *namespace != "" {
		return errors.New("--namespace is only used for live cluster scanning")
	}

	fmt.Println("Checking pod security settings.")
	info, err := os.Stat(paths[0])
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return scanFile(paths[0])
	}
	entries, err := os.ReadDir(paths[0])
	if err != nil {
		return err
	}
	files := 0
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		if entry.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		if err := scanFile(filepath.Join(paths[0], entry.Name())); err != nil {
			return err
		}
		files++
	}
	if files == 0 {
		return errors.New("directory contains no YAML files")
	}
	return nil
}

func scanFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	for document := 1; ; document++ {
		var manifest Manifest
		if err := decoder.Decode(&manifest); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return fmt.Errorf("%s, document %d: %w", path, document, err)
		}
		if manifest.Kind == "" {
			continue // Empty YAML document.
		}
		printManifest(path, manifest)
	}
}

func printManifest(source string, manifest Manifest) {
	var spec PodSpec
	switch manifest.Kind {
	case "Pod":
		spec = manifest.Spec.PodSpec
	case "Deployment":
		spec = manifest.Spec.Template.Spec
	default:
		fmt.Printf("Skipping %s %s (unsupported kind)\n", manifest.Kind, manifest.Metadata.Name)
		return
	}
	namespace := manifest.Metadata.Namespace
	if namespace == "" {
		namespace = "<unspecified>"
	}
	fmt.Printf("\n%s: %s %s/%s\n", source, manifest.Kind, namespace, manifest.Metadata.Name)
	for _, container := range spec.InitContainers {
		fmt.Printf("  Init container: %s (%s)\n", container.Name, container.Image)
	}
	for _, container := range spec.Containers {
		fmt.Printf("  Container: %s (%s)\n", container.Name, container.Image)
	}
	findings := checkPod(spec)
	if len(findings) == 0 {
		fmt.Printf("  %s\n", colorize("No findings.", ansiGreen))
	}
	for _, finding := range findings {
		subject := finding.Container
		if subject == "" {
			subject = "pod"
		}
		fmt.Printf("  %s %s: %s\n    Fix: %s\n", severityLabel(finding.Severity), subject, finding.Message, finding.Fix)
	}
}

func severityLabel(severity string) string {
	label := "[" + severity + "]"
	switch severity {
	case "CRITICAL", "HIGH":
		return colorize(label, ansiRed)
	case "MEDIUM":
		return colorize(label, ansiYellow)
	default:
		return label
	}
}

func colorize(text, color string) string {
	// Keep pipes, files, and terminals that disable color in plain text.
	info, err := os.Stdout.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return text
	}
	// Reset immediately so the following text keeps its normal color.
	return color + text + ansiReset
}
