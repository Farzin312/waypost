package repowrite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestTransactionRollsBackEveryPublishFailure(t *testing.T) {
	for _, failed := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			dir := t.TempDir()
			tx, close, err := Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer close()
			for _, rel := range []string{".waypost.yaml", ".waypost.lock", ".waypost.baseline.json"} {
				if err := os.WriteFile(filepath.Join(dir, rel), []byte("before"), 0o644); err != nil {
					t.Fatal(err)
				}
				tx.mutations = append(tx.mutations, Mutation{Path: rel, Old: []byte("before"), New: []byte("after")})
			}
			n := 0
			injected := errors.New("injected publication failure")
			tx.publishFile = func(src, dst string) error {
				n++
				if n == failed {
					return injected
				}
				return tx.root.Rename(src, dst)
			}
			if err := tx.commit(); !errors.Is(err, injected) {
				t.Fatalf("expected injected failure: %v", err)
			}
			for _, m := range tx.mutations {
				raw, err := os.ReadFile(filepath.Join(dir, m.Path))
				if err != nil || string(raw) != "before" {
					t.Fatalf("partial publication of %s: %q %v", m.Path, raw, err)
				}
			}
			if _, err := os.Stat(filepath.Join(tx.meta, journalName)); !os.IsNotExist(err) {
				t.Fatalf("journal was not recovered %v", err)
			}
		})
	}
}
