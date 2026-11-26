package pins

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/repoview"
)

func TestPinReconciliationSeparatesLagFromArtifactDrift(t *testing.T) {
	fixture := func(version, role, artifact string, stamp string) Input {
		t.Helper()
		dir := t.TempDir()
		write := func(rel string, raw []byte) {
			t.Helper()
			name := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		packageJSON, _ := json.Marshal(map[string]string{"name": "demo", "version": version, "stamp": stamp})
		var archive bytes.Buffer
		zip := gzip.NewWriter(&archive)
		tr := tar.NewWriter(zip)
		header := &tar.Header{Name: "package/package.json", Size: int64(len(packageJSON)), Mode: 0o644}
		if err := tr.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Write(packageJSON); err != nil {
			t.Fatal(err)
		}
		if err := tr.Close(); err != nil {
			t.Fatal(err)
		}
		if err := zip.Close(); err != nil {
			t.Fatal(err)
		}
		write(artifact, archive.Bytes())
		pin := config.CrossRepoPin{ID: "demo", Producer: "org/demo", Consumer: "org/app", Artifact: artifact, Version: version, Role: role, ContractID: "demo"}
		pin.Source = &config.PinSource{Kind: "npm-package-version", Manifest: "package.json"}
		if role == "consumer" {
			artifactFile := "file:./" + artifact
			manifest, _ := json.Marshal(map[string]any{"dependencies": map[string]string{"demo": artifactFile}})
			write("package.json", manifest)
			sum := sha512.Sum512(archive.Bytes())
			integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
			lock, _ := json.Marshal(map[string]any{"packages": map[string]any{"node_modules/demo": map[string]string{"version": version, "integrity": integrity}}})
			write("package-lock.json", lock)
			pin.Source.Kind, pin.Source.Package = "npm-dependency", "demo"
		} else {
			write("package.json", packageJSON)
		}
		view, err := repoview.Working(dir)
		if err != nil {
			t.Fatal(err)
		}
		return Input{View: view, Pins: []config.CrossRepoPin{pin}, Configured: true}
	}
	producer := fixture("2.0.0", "producer", "art/demo-2.0.0.tgz", "producer")
	consumer := fixture("1.0.0", "consumer", "vendor/demo-1.0.0.tgz", "older")
	if report := Reconcile([]Input{producer, consumer}); report.Pins[1].Status != "behind" || report.Pins[1].ProducerVersion != "2.0.0" {
		t.Fatalf("legitimate release lag reported as drift: %+v", report)
	}
	conflicting := fixture("2.0.0", "consumer", "vendor/demo-2.0.0.tgz", "different")
	if report := Reconcile([]Input{producer, conflicting}); report.Pins[0].Status != "drift" || report.Pins[1].Status != "drift" {
		t.Fatalf("same-version conflicts not reported: %+v", report)
	}
	pin := consumer.Pins[0]
	pin.Source.Manifest = "missing.json"
	if got := Inspect(consumer.View, pin); got.Status != "drift" {
		t.Fatalf("missing typed source was accepted: %+v", got)
	}
}

func TestReconcileComparesOnlyCanonicalArtifactRepresentation(t *testing.T) {
	producer, consumer := t.TempDir(), t.TempDir()
	write := func(dir, rel, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(producer, "package.json", `{"name":"contract","version":"1.0.0"}`)
	write(producer, "openapi.json", `{"openapi":"3.1.0"}`)
	write(consumer, "package.json", `{"dependencies":{"contract":"1.0.0"}}`)
	digest := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	writeLock := func(version string) {
		write(consumer, "package-lock.json", `{"packages":{"node_modules/contract":{"version":"`+version+`","resolved":"https://example.test/contract-1.0.0.tgz","integrity":"sha256-`+digest+`"}}}`)
	}
	writeLock("1.0.0")
	view := func(dir string) *repoview.View {
		t.Helper()
		v, err := repoview.Working(dir)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	p := config.CrossRepoPin{ID: "spec", ContractID: "contract", Role: "producer", Version: "1.0.0", Artifact: "openapi.json", Source: &config.PinSource{Kind: "npm-package-version", Manifest: "package.json"}}
	c := config.CrossRepoPin{ID: "pkg", ContractID: "contract", Role: "consumer", Version: "1.0.0", Artifact: "contract", Source: &config.PinSource{Kind: "npm-dependency", Manifest: "package.json", Package: "contract"}}
	report := Reconcile([]Input{{View: view(producer), Pins: []config.CrossRepoPin{p}, Configured: true}, {View: view(consumer), Pins: []config.CrossRepoPin{c}, Configured: true}})
	if report.Pins[0].Status != "aligned" || report.Pins[1].Status != "aligned" {
		t.Fatalf("compared JSON to tarball: %+v", report.Pins)
	}
	writeLock("2.0.0")
	if got := Inspect(view(consumer), c); got.Status != "drift" {
		t.Fatalf("contradictory explicit lock version: %+v", got)
	}
	writeLock("")
	if got := Inspect(view(consumer), c); got.Status != "aligned" {
		t.Fatalf("omitted lock version did not use resolved: %+v", got)
	}
}
