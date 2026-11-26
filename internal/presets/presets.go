package presets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

//go:embed base.yaml app-ts.yaml polyglot-native.yaml
var fs embed.FS

// BuiltinRef represents a resolved embedded preset.
type BuiltinRef struct {
	Name    string
	Version string
	Ref     string
	SHA256  string
	Raw     []byte
}

var catalog = map[string]struct {
	file    string
	version string
}{
	"base":            {file: "base.yaml", version: "1.0.0"},
	"app-ts":          {file: "app-ts.yaml", version: "1.0.0"},
	"polyglot-native": {file: "polyglot-native.yaml", version: "1.0.0"},
}

// Names returns all built-in preset names in sorted order.
func Names() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsBuiltin reports whether ref uses the builtin:<name>[@<version>] syntax.
func IsBuiltin(ref string) bool {
	return strings.HasPrefix(strings.TrimSpace(ref), "builtin:")
}

// Resolve loads a built-in preset by ref (e.g., "builtin:base@1.0.0" or "builtin:app-ts").
func Resolve(ref string) (*BuiltinRef, error) {
	trimmed := strings.TrimSpace(ref)
	if !strings.HasPrefix(trimmed, "builtin:") {
		return nil, fmt.Errorf("not a builtin preset reference: %q", ref)
	}
	rest := strings.TrimPrefix(trimmed, "builtin:")
	name := rest
	reqVer := ""
	if idx := strings.IndexByte(rest, '@'); idx >= 0 {
		name = rest[:idx]
		reqVer = rest[idx+1:]
	}
	entry, ok := catalog[name]
	if !ok {
		return nil, fmt.Errorf("unknown builtin preset %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	if reqVer != "" && reqVer != entry.version && reqVer != "v1" && reqVer != "latest" {
		return nil, fmt.Errorf("builtin preset %q has version %s, requested %q", name, entry.version, reqVer)
	}
	raw, err := fs.ReadFile(entry.file)
	if err != nil {
		return nil, fmt.Errorf("read embedded preset %q: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	return &BuiltinRef{
		Name:    name,
		Version: entry.version,
		Ref:     fmt.Sprintf("builtin:%s@%s", name, entry.version),
		SHA256:  hex.EncodeToString(sum[:]),
		Raw:     raw,
	}, nil
}
