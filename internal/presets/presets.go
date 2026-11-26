package presets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.yaml
var fs embed.FS

// BuiltinRef represents a resolved embedded preset.
type BuiltinRef struct {
	Name    string
	Version string
	Ref     string
	SHA256  string
	Raw     []byte
}

const LatestVersion = "1.1.0"

var catalog = map[string]map[string]string{
	"base":            {"1.0.0": "base.yaml", "1.1.0": "base-1.1.0.yaml"},
	"app-ts":          {"1.0.0": "app-ts.yaml", "1.1.0": "app-ts-1.1.0.yaml"},
	"polyglot-native": {"1.0.0": "polyglot-native.yaml", "1.1.0": "polyglot-native-1.1.0.yaml"},
}

func Floating(ref string) bool {
	_, v, _ := strings.Cut(strings.TrimSpace(ref), "@")
	return v == "" || v == "v1" || v == "latest"
}

// Anchor resolves a floating ref through the exact versions in a frozen chain.
func Anchor(ref string, pinned map[string]string) string {
	if IsBuiltin(ref) && Floating(ref) {
		name, _, _ := strings.Cut(strings.TrimSpace(ref), "@")
		if exact := pinned[name]; exact != "" {
			return exact
		}
	}
	return ref
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
	versions, ok := catalog[name]
	if !ok {
		return nil, fmt.Errorf("unknown builtin preset %q (available: %s)", name, strings.Join(Names(), ", "))
	}
	if Floating(trimmed) {
		reqVer = LatestVersion
	}
	file, ok := versions[reqVer]
	if !ok {
		return nil, fmt.Errorf("unknown version %q of builtin preset %q", reqVer, name)
	}
	raw, err := fs.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read embedded preset %q: %w", name, err)
	}
	sum := sha256.Sum256(raw)
	return &BuiltinRef{
		Name:    name,
		Version: reqVer,
		Ref:     fmt.Sprintf("builtin:%s@%s", name, reqVer),
		SHA256:  hex.EncodeToString(sum[:]),
		Raw:     raw,
	}, nil
}
