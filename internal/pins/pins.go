// Package pins inspects declared contract pins and reconciles explicit snapshots offline.
package pins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
)

const maxArtifactBytes = 32 << 20

type Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

func ReadManifest(view *repoview.View, rel string) (*Manifest, error) {
	var cached Manifest
	if view.CachedParse(rel, "npm-manifest", &cached) {
		return &cached, nil
	}
	raw, err := view.Read(rel, repopath.MaxPolicyBytes)
	if err != nil {
		return nil, err
	}
	var manifest *Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, errors.New("expected a package manifest object")
	}
	view.CacheParse(rel, "npm-manifest", *manifest)
	return manifest, nil
}

type Result struct {
	Version     string        `json:"pins_version"`
	Snapshots   []Snapshot    `json:"snapshots"`
	Pins        []Observation `json:"pins"`
	Diagnostics []string      `json:"diagnostics"`
}

type Snapshot struct {
	Repo string `json:"repo"`
	repoview.Identity
}

type Observation struct {
	config.CrossRepoPin
	Snapshot         int    `json:"snapshot"`
	Declared         string `json:"declared_version,omitempty"`
	Observed         string `json:"observed_version,omitempty"`
	ArtifactIdentity string `json:"artifact_identity,omitempty"`
	representation   string
	Integrity        string `json:"integrity,omitempty"`
	ReleaseLine      string `json:"release_line,omitempty"`
	ProducerVersion  string `json:"producer_version,omitempty"`
	Status           string `json:"status"`
	Detail           string `json:"detail,omitempty"`
}

type Input struct {
	View       *repoview.View
	Pins       []config.CrossRepoPin
	Configured bool
}

func Reconcile(projects []Input) Result {
	out := Result{Version: "1", Snapshots: []Snapshot{}, Pins: []Observation{}, Diagnostics: []string{}}
	for i, p := range projects {
		out.Snapshots = append(out.Snapshots, Snapshot{p.View.Repo, p.View.Identity})
		if !p.Configured {
			out.Diagnostics = append(out.Diagnostics, fmt.Sprintf("%s has no Waypost policy", p.View.Repo))
			continue
		}
		for _, pin := range p.Pins {
			o := Inspect(p.View, pin)
			o.Snapshot = i
			out.Pins = append(out.Pins, o)
		}
	}
	type release struct{ contract, version, representation string }
	type signature struct {
		release
		algorithm string
	}
	newest := make(map[string]string)
	identities := make(map[signature]string)
	conflicts := make(map[release]bool)
	for _, pin := range out.Pins {
		if pin.Status != "aligned" || pin.ContractID == "" {
			continue
		}
		if pin.Role == "producer" && CompareVersion(pin.Observed, newest[pin.ContractID]) > 0 {
			newest[pin.ContractID] = pin.Observed
		}
		key := release{pin.ContractID, pin.Observed, pin.representation}
		if pin.representation == "" {
			continue
		}
		digests := []string{pin.ArtifactIdentity}
		if size, values := integrityParts(pin.Integrity); len(values) == 1 {
			kind := map[int]string{64: "sha512", 48: "sha384", 32: "sha256", 20: "sha1"}[size]
			digests = append(digests, fmt.Sprintf("%s:%x", kind, values[0]))
		}
		for _, digest := range digests {
			algorithm, value, ok := strings.Cut(digest, ":")
			if !ok {
				continue
			}
			sig := signature{key, algorithm}
			if seen := identities[sig]; seen != "" && seen != value {
				conflicts[key] = true
			}
			identities[sig] = value
		}
	}
	for i := range out.Pins {
		pin := &out.Pins[i]
		if pin.Status != "aligned" {
			continue
		}
		key := release{pin.ContractID, pin.Observed, pin.representation}
		switch {
		case conflicts[key]:
			pin.Status, pin.Detail = "drift", "same contract version has conflicting artifact bytes"
		case pin.Role == "consumer" && CompareVersion(newest[pin.ContractID], pin.Observed) > 0:
			pin.Status, pin.ProducerVersion = "behind", newest[pin.ContractID]
			pin.Detail = "consumer matches its declared release"
		}
	}
	return out
}

func Inspect(view *repoview.View, pin config.CrossRepoPin) Observation {
	o := Observation{CrossRepoPin: pin, Declared: pin.Version, Status: "unknown"}
	if pin.Source == nil {
		root, _ := ReadManifest(view, "package.json")
		contracts, _ := ReadManifest(view, "contracts/package.json")
		o.Observed = LegacyVersion(pin, root, contracts)
	} else {
		if err := inspectTyped(view, &o); err != nil {
			o.Status, o.Detail = "drift", err.Error()
			return o
		}
	}
	if o.Observed != "" {
		o.Status = "aligned"
		if o.Observed != pin.Version {
			o.Status, o.Detail = "drift", "declared and observed versions differ"
		}
		for i, r := range o.Observed {
			if r == '.' {
				o.ReleaseLine = o.Observed[:i] + ".x"
				break
			}
		}
	}
	return o
}

func inspectTyped(view *repoview.View, o *Observation) error {
	src := o.Source
	manifest, err := ReadManifest(view, src.Manifest)
	if err != nil {
		return fmt.Errorf("source manifest %q: %w", src.Manifest, err)
	}
	switch src.Kind {
	case "npm-package-version":
		o.Observed = DependencyVersion(manifest.Version)
		if o.Observed == "" {
			return errors.New("source manifest does not declare an exact package version")
		}
		if repopath.Valid(o.Artifact) && (strings.HasSuffix(o.Artifact, ".tgz") || strings.HasSuffix(o.Artifact, ".json") && !strings.HasPrefix(o.Artifact, "@") || view.Files[o.Artifact].Regular()) {
			return inspectArtifact(view, o, o.Artifact, manifest.Name, "")
		}
		return nil
	case "npm-dependency":
		spec, err := dependency(manifest, src.Package)
		if err != nil {
			return err
		}
		o.Observed = DependencyVersion(spec)
		if o.Observed == "" {
			return fmt.Errorf("dependency %q must declare an exact or vendored package version", src.Package)
		}
		integrity, err := lockIntegrity(view, src.Manifest, src.Package, o.Observed)
		if err != nil {
			return err
		}
		o.Integrity = integrity
		o.representation = "npm-tarball:" + src.Package
		if size, values := integrityParts(integrity); len(values) == 1 {
			kind := map[int]string{64: "sha512", 48: "sha384", 32: "sha256", 20: "sha1"}[size]
			o.ArtifactIdentity = fmt.Sprintf("%s:%x", kind, values[0])
		}
		if file, ok := strings.CutPrefix(spec, "file:"); ok {
			if strings.HasPrefix(file, "/") || strings.Contains(file, "\\") {
				return errors.New("vendored artifact must be within the repository")
			}
			rel := path.Join(path.Dir(src.Manifest), file)
			return inspectArtifact(view, o, rel, src.Package, integrity)
		}
		return nil
	}
	return fmt.Errorf("unsupported pin source %q", src.Kind)
}

func dependency(m *Manifest, name string) (string, error) {
	var value string
	for _, fields := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies, m.PeerDependencies} {
		if other := fields[name]; other != "" {
			if value != "" && value != other {
				return "", fmt.Errorf("conflicting declarations for dependency %q", name)
			}
			value = other
		}
	}
	if value == "" {
		return "", fmt.Errorf("source manifest does not declare dependency %q", name)
	}
	return value, nil
}

func lockIntegrity(view *repoview.View, manifest, pkg, expected string) (string, error) {
	type entry struct{ Version, Integrity, Resolved string }
	var doc struct {
		Packages     map[string]entry `json:"packages"`
		Dependencies map[string]entry `json:"dependencies"`
	}
	dir := path.Dir(manifest)
	for parent := dir; ; parent = path.Dir(parent) {
		rel := path.Join(parent, "package-lock.json")
		raw, exists, err := view.Lookup(rel, 8<<20)
		if err != nil {
			return "", err
		}
		if exists {
			if err := json.Unmarshal(raw, &doc); err != nil {
				return "", fmt.Errorf("%s: %w", rel, err)
			}
			workspace := strings.TrimPrefix(strings.TrimPrefix(dir, parent), "/")
			if parent == "." && dir != "." {
				workspace = dir
			}
			locked, found := doc.Packages[path.Join(workspace, "node_modules", pkg)]
			if !found {
				locked, found = doc.Packages["node_modules/"+pkg]
			}
			if !found {
				locked, found = doc.Dependencies[pkg]
			}
			if !found {
				return "", fmt.Errorf("%s has no lock entry for %q", rel, pkg)
			}
			lockedVersion := locked.Version
			if lockedVersion == "" {
				lockedVersion = resolvedDependencyVersion(locked.Resolved)
			}
			if lockedVersion != expected && DependencyVersion(lockedVersion) != expected {
				return "", fmt.Errorf("%s locks %q at %q, expected %s", rel, pkg, locked.Version, expected)
			}
			if locked.Integrity != "" && !validIntegrity(locked.Integrity) {
				return "", fmt.Errorf("%s has invalid integrity for %q", rel, pkg)
			}
			return locked.Integrity, nil
		}
		if parent == "." {
			break
		}
	}
	return "", nil
}

func inspectArtifact(view *repoview.View, o *Observation, rel, name, integrity string) error {
	raw, err := view.Read(rel, maxArtifactBytes)
	if err != nil {
		return fmt.Errorf("artifact %q: %w", rel, err)
	}
	o.ArtifactIdentity = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if strings.HasSuffix(rel, ".tgz") {
		o.representation = "npm-tarball:" + name
	} else {
		o.representation = "file:" + path.Base(rel)
	}
	if integrity != "" && !matchIntegrity(raw, integrity) {
		return fmt.Errorf("artifact %q fails lock integrity", rel)
	}
	if !strings.HasSuffix(rel, ".tgz") {
		return nil
	}
	zip, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("artifact %q: %w", rel, err)
	}
	defer zip.Close()
	tr := tar.NewReader(io.LimitReader(zip, maxArtifactBytes+1))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("artifact %q has no package manifest", rel)
		}
		if err != nil {
			return fmt.Errorf("artifact %q: %w", rel, err)
		}
		if h.Name != "package/package.json" {
			continue
		}
		if h.Size > repopath.MaxPolicyBytes || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) {
			return fmt.Errorf("artifact %q manifest must be a bounded regular file", rel)
		}
		var m Manifest
		if err := json.NewDecoder(tr).Decode(&m); err != nil {
			return fmt.Errorf("artifact %q manifest: %w", rel, err)
		}
		if m.Version != o.Observed || (name != "" && m.Name != name) {
			return fmt.Errorf("artifact %q contains %s@%s, expected %s@%s", rel, m.Name, m.Version, name, o.Observed)
		}
		return nil
	}
}

func integrityParts(spec string) (int, [][]byte) {
	var strongest int
	var digests [][]byte
	for _, part := range strings.Fields(spec) {
		kind, encoded, _ := strings.Cut(part, "-")
		size := map[string]int{"sha512": 64, "sha384": 48, "sha256": 32, "sha1": 20}[kind]
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if size == 0 || err != nil || len(decoded) != size || size < strongest {
			continue
		}
		if size > strongest {
			strongest = size
			digests = nil
		}
		digests = append(digests, decoded)
	}
	return strongest, digests
}

func validIntegrity(spec string) bool { size, _ := integrityParts(spec); return size > 0 }
func matchIntegrity(raw []byte, spec string) bool {
	size, expected := integrityParts(spec)
	var digest []byte
	switch size {
	case 64:
		x := sha512.Sum512(raw)
		digest = x[:]
	case 48:
		x := sha512.Sum384(raw)
		digest = x[:]
	case 32:
		x := sha256.Sum256(raw)
		digest = x[:]
	case 20:
		x := sha1.Sum(raw)
		digest = x[:]
	}
	return slices.ContainsFunc(expected, func(want []byte) bool { return bytes.Equal(digest, want) })
}

const semver = `(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`

var exactVersion = regexp.MustCompile(`^` + semver + `$`)
var vendoredVersion = regexp.MustCompile(`^file:(?:[^/]+/)*[^/]+?-(` + semver + `)\.tgz$`)

func resolvedDependencyVersion(resolved string) string {
	if version := DependencyVersion(resolved); version != "" {
		return version
	}
	u, err := url.Parse(resolved)
	if err == nil && (u.Scheme == "https" || u.Scheme == "http") {
		return DependencyVersion("file:" + path.Base(u.Path))
	}
	return ""
}

func DependencyVersion(spec string) string {
	if exactVersion.MatchString(spec) {
		return spec
	}
	if m := vendoredVersion.FindStringSubmatch(spec); m != nil {
		return m[1]
	}
	return ""
}

func LegacyVersion(pin config.CrossRepoPin, root, contracts *Manifest) string {
	if root != nil {
		for _, name := range []string{pin.Artifact, pin.ID} {
			if value, err := dependency(root, name); err == nil {
				if version := DependencyVersion(value); version != "" {
					return version
				}
				break
			}
		}
	}
	artifact := strings.TrimPrefix(pin.Artifact, "./")
	if contracts != nil && (pin.ID == "contracts" || artifact == "contracts" || strings.HasPrefix(artifact, "contracts/") ||
		(contracts.Name != "" && (contracts.Name == pin.Artifact || contracts.Name == pin.ID))) && exactVersion.MatchString(contracts.Version) {
		return contracts.Version
	}
	return ""
}

func CompareVersion(a, b string) int {
	if !exactVersion.MatchString(a) || !exactVersion.MatchString(b) {
		return strings.Compare(a, b)
	}
	a, _, _ = strings.Cut(a, "+")
	b, _, _ = strings.Cut(b, "+")
	a, ap, apre := strings.Cut(a, "-")
	b, bp, bpre := strings.Cut(b, "-")
	cmp := slices.CompareFunc(strings.Split(a, "."), strings.Split(b, "."), compareNumber)
	if cmp != 0 {
		return cmp
	}
	if apre != bpre {
		if apre {
			return -1
		}
		return 1
	}
	return slices.CompareFunc(strings.Split(ap, "."), strings.Split(bp, "."), func(a, b string) int {
		an, bn := numeric(a), numeric(b)
		if an && bn {
			return compareNumber(a, b)
		}
		if an != bn {
			if an {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
}

func compareNumber(a, b string) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return strings.Compare(a, b)
}

func numeric(value string) bool {
	return value != "" && strings.Trim(value, "0123456789") == ""
}

// InputPaths discovers repository-local artifacts whose edits trigger the pin.
func InputPaths(view *repoview.View, pin config.CrossRepoPin) []string {
	src := pin.Source
	if src == nil {
		return nil
	}
	paths := []string{src.Manifest}
	if src.Kind != "npm-dependency" {
		return paths
	}
	dir := path.Dir(src.Manifest)
	for parent := dir; ; parent = path.Dir(parent) {
		lock := path.Join(parent, "package-lock.json")
		if _, exists := view.Files[lock]; exists {
			paths = append(paths, lock)
			break
		}
		if parent == "." {
			break
		}
	}
	if manifest, err := ReadManifest(view, src.Manifest); err == nil {
		if value, err := dependency(manifest, src.Package); err == nil {
			if file, ok := strings.CutPrefix(value, "file:"); ok && !strings.HasPrefix(file, "/") {
				if rel := path.Join(dir, file); repopath.Valid(rel) {
					paths = append(paths, rel)
				}
			}
		}
	}
	return paths
}
