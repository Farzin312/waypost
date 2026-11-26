package version

import "runtime"

// Version constants are tracked independently so config schema, lockfile/preset
// resolution semantics, and CLI releases can evolve cleanly without breaking
// git-revert rollback.
const (
	SchemaVersion   = "1"
	ResolverVersion = "1"
)

// CLIVersion and Commit may be overridden at link time via -ldflags.
var (
	CLIVersion = "0.2.0"
	Commit     = "dev"
)

// Info describes the running waypost binary and contract versions.
type Info struct {
	CLIVersion      string `json:"cli_version"`
	Commit          string `json:"commit"`
	SchemaVersion   string `json:"schema_version"`
	ResolverVersion string `json:"resolver_version"`
	GoVersion       string `json:"go_version"`
	Platform        string `json:"platform"`
}

// Current returns the runtime version metadata.
func Current() Info {
	return Info{
		CLIVersion:      CLIVersion,
		Commit:          Commit,
		SchemaVersion:   SchemaVersion,
		ResolverVersion: ResolverVersion,
		GoVersion:       runtime.Version(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
	}
}
