package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// Packaged tools live beside kubesec in bin/. Source runs use tools on PATH.
func toolPath(name string) string {
	executable, err := os.Executable()
	if err != nil {
		return name
	}
	return toolPathIn(filepath.Dir(executable), name)
}

func toolPathIn(directory, name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bundled := filepath.Join(directory, "bin", name)
	// Return an existing path even if it cannot be executed, so its error is visible.
	if _, err := os.Stat(bundled); !os.IsNotExist(err) {
		return bundled
	}
	return name
}
