package syncer

import (
	"sync"
	"testing"

	"github.com/Farzin312/waypost/internal/config"
)

func TestConcurrentSyncAppliesOnce(t *testing.T) {
	dir := t.TempDir()
	syncWrite(t, dir, config.ConfigFileName, "schema_version: '1'\n")
	var wg sync.WaitGroup
	type outcome struct {
		report Report
		err    error
	}
	results := make(chan outcome, 2)
	for range 2 {
		wg.Go(func() { report, err := Run(dir, Options{Apply: true}); results <- outcome{report, err} })
	}
	wg.Wait()
	close(results)
	n := 0
	for result := range results {
		if result.err != nil || result.report.Pending() {
			t.Fatalf("concurrent sync: %+v", result)
		}
		if result.report.LockRefreshed {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one publisher, got %d", n)
	}
}
