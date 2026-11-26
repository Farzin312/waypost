package compmap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat  string
		tgt  string
		want bool
	}{
		{"**/*.ts", "app/index.ts", true},
		{"**/*.ts", "index.ts", true},
		{"**/*.ts", "app/index.js", false},
		{".github/workflows/**", ".github/workflows/ci.yml", true},
		{".github/workflows/**", ".github/workflows/nested/test.yml", true},
		{"tools/**", "tools/validate.py", true},
		{"tools/**", "game/tools/validate.py", false},
		{"**/*.uproject", "game/DreamRealm.uproject", true},
		{".waypost.yaml", ".waypost.yaml", true},
	}
	for _, tc := range cases {
		if got := MatchGlob(tc.pat, tc.tgt); got != tc.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pat, tc.tgt, got, tc.want)
		}
	}
}

func TestBuildPolyglotAndReverseDependencyImpact(t *testing.T) {
	dir := t.TempDir()
	// Create a mini polyglot repo: game/Demo.uproject + tools/pyproject.toml + unmapped art/
	if err := os.MkdirAll(filepath.Join(dir, "game"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "game/Demo.uproject"), []byte(`{"EngineAssociation":"5.6","Modules":[{"Name":"Demo","Type":"Runtime"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tools/pyproject.toml"), []byte("[project]\nname = \"validators\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		SchemaVersion: "1",
		Components: []config.ComponentConfig{
			{
				ID:        "data",
				Root:      "data",
				Language:  "json",
				Paths:     []string{"data/**"},
			},
			{
				ID:        "game",
				Root:      "game",
				Language:  "cpp",
				DependsOn: []string{"data"},
				Paths:     []string{"game/**"},
			},
		},
		Pins: []config.CrossRepoPin{
			{
				ID:       "schema-pin",
				Producer: "org/shared-schemas",
				Artifact: "v2/content.schema.json",
				Consumer: "data",
				Paths:    []string{"data/**"},
			},
		},
	}

	tracked := []string{"game/Demo.uproject", "tools/pyproject.toml", "data/items.json", "art/hero.fbx"}
	m, err := Build(dir, cfg, tracked)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(m.Components) != 3 {
		t.Fatalf("expected 3 components (data, game, validators), got %+v", m.Components)
	}
	if !reflect.DeepEqual(m.UnmappedPaths, []string{"art/hero.fbx"}) {
		t.Fatalf("expected art/hero.fbx unmapped, got %v", m.UnmappedPaths)
	}
	if len(m.CoverageGaps) == 0 {
		t.Fatal("expected explicit Unreal coverage gap")
	}

	// Changing data/items.json + art/hero.fbx should directly hit `data`,
	// transitively impact `game` ("what builds on data"), trigger `schema-pin`,
	// and flag art/hero.fbx as unmapped!
	imp := m.ImpactedByPaths([]string{"data/items.json", "art/hero.fbx"})
	if !reflect.DeepEqual(imp.DirectComponents, []string{"data"}) {
		t.Fatalf("unexpected DirectComponents: %v", imp.DirectComponents)
	}
	if !reflect.DeepEqual(imp.TransitiveDependents, []string{"game"}) {
		t.Fatalf("unexpected TransitiveDependents: %v", imp.TransitiveDependents)
	}
	if !reflect.DeepEqual(imp.TriggeredPins, []string{"schema-pin"}) {
		t.Fatalf("unexpected TriggeredPins: %v", imp.TriggeredPins)
	}
	if !reflect.DeepEqual(imp.UnmappedPaths, []string{"art/hero.fbx"}) {
		t.Fatalf("unexpected UnmappedPaths: %v", imp.UnmappedPaths)
	}
}
