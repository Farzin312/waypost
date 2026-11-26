package verify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

func TestParallelChecksOverlapWithExclusiveBarriersAndStableResults(t *testing.T) {
	checks := make([]changeplan.Check, 5)
	for i := range checks {
		checks[i] = changeplan.Check{Check: config.Check{ID: string(rune('a' + i)), Serial: config.BoolPtr(i == 2)}, Selected: true}
	}
	for _, jobs := range []int{1, 2} {
		var active, peak atomic.Int32
		var barrier atomic.Bool
		started := make(chan struct{})
		var arrived atomic.Int32
		done := make(chan []CheckResult, 1)
		go func() {
			done <- schedule(checks, jobs, func(c changeplan.Check) CheckResult {
				n := active.Add(1)
				for max := peak.Load(); n > max && !peak.CompareAndSwap(max, n); max = peak.Load() {
				}
				if c.Check.ID == "c" {
					if n != 1 {
						t.Error("exclusive check started before workers drained")
					}
					barrier.Store(true)
				} else if c.Check.ID < "c" && jobs == 2 {
					if arrived.Add(1) == 2 {
						close(started)
					}
					select {
					case <-started:
					case <-time.After(2 * time.Second):
					}
				} else if c.Check.ID > "c" && !barrier.Load() {
					t.Error("parallel group started before exclusive check")
				}
				time.Sleep(15 * time.Millisecond)
				active.Add(-1)
				return CheckResult{ID: c.Check.ID, Status: StatusPass}
			})
		}()
		results := <-done
		for i, c := range results {
			if c.ID != checks[i].Check.ID {
				t.Fatalf("out of order results %+v", results)
			}
		}
		if int(peak.Load()) != jobs {
			t.Fatalf("jobs %d used %d concurrent workers", jobs, peak.Load())
		}
	}
}

func TestTimeoutCancelsCheckDescendants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix shell")
	}
	dir := t.TempDir()
	check := changeplan.Check{Check: config.Check{ID: "timed", Command: "(sleep 2; touch escaped) & wait", TimeoutSeconds: 1}, Selected: true}
	got := executeCheckContext(context.Background(), dir, check, "full", handoff{})
	if got.Status != StatusFail || got.ExitCode != 124 {
		t.Fatalf("incorrect timeout result %+v", got)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "escaped")); !os.IsNotExist(err) {
		t.Fatalf("descendant survived timeout: %v", err)
	}
}

func TestChangedFileHandoffUsesNULAndVerifiedSHAs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses Unix path characters")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	dir := t.TempDir()
	gitBoundaryFixture(t, dir, "init", "-b", "main")
	root := `schema_version: "1"
components: [{id: app, root: app}]
checks:
  - id: record
    command: python3 capture.py
    local_command: python3 capture.py
    paths: [app/**]
`
	writeBoundaryFixture(t, dir, config.ConfigFileName, root)
	writeBoundaryFixture(t, dir, "capture.py", `import os,pathlib
data=pathlib.Path(os.environ["WAYPOST_CHANGED_FILES_FILE"]).read_bytes()
pathlib.Path(os.environ["CAPTURE_FILE"]).write_bytes(data)
assert os.environ["WAYPOST_BASE_SHA"] == os.environ["EXPECT_SHA"]
assert os.environ["WAYPOST_HEAD_SHA"] == os.environ["EXPECT_SHA"]
`)
	old := "app/old path.go"
	writeBoundaryFixture(t, dir, old, "package app\nvar x = 1\n")
	writeBoundaryFixture(t, dir, "app/delete.go", "package app\n")
	writeBoundaryFixture(t, dir, "app/seam_test.go", "package app\n")
	gitBoundaryFixture(t, dir, "add", ".")
	gitBoundaryFixture(t, dir, "commit", "-m", "base")
	head, err := gitdiff.ResolveCommit(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "capture")
	t.Setenv("CAPTURE_FILE", capture)
	t.Setenv("EXPECT_SHA", head)
	t.Setenv("WAYPOST_BASE_SHA", "untrusted")
	name := "app/-é \t\n$(false);.go"
	gitBoundaryFixture(t, dir, "mv", "--", old, name)
	gitBoundaryFixture(t, dir, "rm", "--", "app/delete.go")
	rec, err := Run(dir, Options{Base: "HEAD"})
	if err != nil || rec.Summary.Outcome != StatusPass || rec.Checks[0].Lane != "full" {
		t.Fatalf("unsafe diff did not take full lane: %+v %v", rec, err)
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{name, "app/delete.go", old}
	slices.Sort(want)
	if string(raw) != strings.Join(want, "\x00")+"\x00" {
		t.Fatalf("handoff %q want %q", raw, want)
	}
	gitBoundaryFixture(t, dir, "reset", "--hard", "HEAD")
	writeBoundaryFixture(t, dir, old, "package app\nvar x = 2\n")
	rec, err = Run(dir, Options{Base: "HEAD"})
	if err != nil || rec.Summary.Outcome != StatusPass || rec.Checks[0].Lane != "full" {
		t.Fatalf("unsafe production selector did not take full lane: %+v %v", rec, err)
	}
}
