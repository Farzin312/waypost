package gitdiff

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseNameStatusRenameAndDelete(t *testing.T) {
	raw := "M\tsrc/app.ts\nR100\told/auth.ts\tnew/auth.ts\nD\tlegacy/secret.ts\nA\tdocs/guide.md\n"
	changes := ParseNameStatus(raw)
	if len(changes) != 4 {
		t.Fatalf("expected 4 changes, got %d: %+v", len(changes), changes)
	}
	if changes[1].Status != "R" || changes[1].OldPath != "old/auth.ts" || changes[1].Path != "new/auth.ts" {
		t.Fatalf("unexpected rename entry: %+v", changes[1])
	}
	if changes[2].Status != "D" || changes[2].Path != "legacy/secret.ts" {
		t.Fatalf("unexpected delete entry: %+v", changes[2])
	}
}

func TestInspectBothSidesOfRenameAndReadFileAtRef(t *testing.T) {
	dir := t.TempDir()
	mustGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}

	mustGit("init", "-b", "main")
	if err := os.MkdirAll(filepath.Join(dir, "trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust/policy.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "remove.txt"), []byte("bye\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit("add", ".")
	mustGit("commit", "-m", "init")

	mustGit("checkout", "-b", "feat/rename")
	if err := os.MkdirAll(filepath.Join(dir, "public"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustGit("mv", "trust/policy.txt", "public/policy.txt")
	mustGit("rm", "remove.txt")
	mustGit("commit", "-m", "rename trust file and delete file")

	snap, err := Inspect(dir, "main", "ci")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	want := []string{"public/policy.txt", "remove.txt", "trust/policy.txt"}
	if !reflect.DeepEqual(snap.AffectedPaths, want) {
		t.Fatalf("AffectedPaths mismatch:\ngot:  %v\nwant: %v", snap.AffectedPaths, want)
	}

	raw, ok, err := ReadFileAtRef(dir, snap.BaseSHA, "trust/policy.txt")
	if err != nil || !ok || string(raw) != "v1\n" {
		t.Fatalf("ReadFileAtRef failed: ok=%v err=%v raw=%q", ok, err, string(raw))
	}
}
