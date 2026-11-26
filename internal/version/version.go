package version

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

// Version constants are tracked independently so config schema, lockfile/preset
// resolution semantics, and CLI releases can evolve cleanly without breaking
// git-revert rollback.
const (
	SchemaVersion   = "1"
	ResolverVersion = "1"
)

// CLIVersion and Commit may be overridden at link time via -ldflags.
var (
	CLIVersion = "0.3.0"
	Commit     = "dev"
)

// Info describes the running waypost binary and contract versions.
type Info struct {
	CLIVersion      string `json:"cli_version"`
	Commit          string `json:"commit"`
	SchemaVersion   string `json:"schema_version"`
	ResolverVersion string `json:"resolver_version"`
	GoVersion       string `json:"go_version"`
	BinarySHA256    string `json:"binary_sha256,omitempty"`
	Modified        bool   `json:"modified,omitempty"`
	Platform        string `json:"platform"`
}

// Current returns the runtime version metadata.
func Current() Info {
	commit := Commit
	modified := false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && commit == "dev" {
				commit = setting.Value
			}
			if setting.Key == "vcs.modified" {
				modified = setting.Value == "true"
			}
		}
	}
	return Info{
		CLIVersion:      CLIVersion,
		Commit:          commit,
		Modified:        modified,
		SchemaVersion:   SchemaVersion,
		ResolverVersion: ResolverVersion,
		GoVersion:       runtime.Version(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// Verifier returns build metadata and the identity of the running executable.
func Verifier() Info {
	info := Current()
	name, err := os.Executable()
	if err != nil {
		return info
	}
	file, err := os.Open(name)
	if err != nil {
		return info
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err == nil {
		info.BinarySHA256 = hex.EncodeToString(hash.Sum(nil))
	}
	return info
}
