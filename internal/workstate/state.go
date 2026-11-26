// Package workstate records local verification in per-worktree Git metadata.
package workstate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
)

func recordPath(prefix string) string {
	sum := sha256.Sum256([]byte(prefix))
	return filepath.Join("waypost", fmt.Sprintf("last-receipt-%x.json", sum))
}

type Summary struct {
	Overall string   `json:"overall,omitempty"`
	Failing []string `json:"failing_checks,omitempty"`
	Unrun   []string `json:"unrun_required_checks,omitempty"`
	Omitted int      `json:"omitted_checks,omitempty"`
}

type Status struct {
	Verification string `json:"verification"`
	Diagnostic   string `json:"diagnostic,omitempty"`
	Summary
	UntestedComponents []string `json:"untested_components,omitempty"`
}

type Selection struct {
	BaseSHA    string `json:"base_sha"`
	TargetSHA  string `json:"target_sha"`
	PlanDigest string `json:"plan_digest"`
}

type record struct {
	Selection
	Diagnostic  string `json:"diagnostic,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Head        string `json:"head_sha"`
	Summary
}

// Fingerprint includes bytes, file names, executable bits, symlink targets and HEAD.
func Fingerprint(view *repoview.View) (string, error) {
	if !gitdiff.ValidSHA(view.SHA) {
		return "", fmt.Errorf("HEAD unavailable")
	}
	root, err := os.OpenRoot(view.Repo)
	if err != nil {
		return "", err
	}
	defer root.Close()
	hash := sha256.New()
	field := func(s string) {
		_ = binary.Write(hash, binary.LittleEndian, uint64(len(s)))
		_, _ = io.WriteString(hash, s)
	}
	field(view.SHA)
	field(string(view.Index))
	dirty, err := gitdiff.WorktreeChanges(view.Repo)
	if err != nil {
		return "", err
	}
	paths := view.Paths()
	const override = ".waypost.local.yaml"
	if _, listed := view.Files[override]; !listed {
		if info, err := root.Lstat(override); err == nil {
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("%q is not a regular file", override)
			}
			paths = append(paths, override)
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	for _, path := range paths {
		entry := view.Files[path]
		field(path)
		field(entry.Mode)
		field(entry.Blob)
		switch {
		case entry.Mode == "160000":
			head, dirty, err := gitdiff.SubmoduleState(view.Repo, path)
			if err != nil {
				return "", fmt.Errorf("fingerprint submodule %q: %w", path, err)
			}
			field(head)
			field(fmt.Sprint(dirty))
		case entry.Clean && !dirty[path]:
			field("clean")
		case entry.Mode == "120000":
			link, err := root.Readlink(path)
			if err != nil {
				return "", err
			}
			field("symlink")
			field(link)
		case entry.Regular() || path == override:
			if err := repopath.CheckRegular(view.Repo, path); err != nil {
				return "", err
			}
			file, err := root.Open(path)
			if err != nil {
				return "", err
			}
			stat, err := file.Stat()
			if err != nil || !stat.Mode().IsRegular() {
				file.Close()
				return "", fmt.Errorf("cannot fingerprint %q", path)
			}
			field(entry.Mode)
			_ = binary.Write(hash, binary.LittleEndian, stat.Size())
			n, err := io.Copy(hash, file)
			after, statErr := file.Stat()
			file.Close()
			if err != nil || statErr != nil || n != stat.Size() || stat.Size() != after.Size() || stat.ModTime() != after.ModTime() {
				return "", fmt.Errorf("%q changed while fingerprinting", path)
			}
		default:
			return "", fmt.Errorf("unsupported worktree entry %q", path)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func Save(view *repoview.View, selection Selection, fingerprint, diagnostic string, summary Summary) error {
	if !gitdiff.ValidSHA(view.SHA) {
		return nil
	}
	dir := view.GitDir
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll("waypost", 0o700); err != nil {
		return err
	}
	info, err := root.Lstat("waypost")
	if err != nil || !info.IsDir() {
		return fmt.Errorf("unsafe workstate directory")
	}
	data, err := json.Marshal(record{Fingerprint: fingerprint, Head: view.SHA, Summary: summary, Selection: selection, Diagnostic: diagnostic})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(dir, "waypost"), ".receipt-*")
	if err != nil {
		return err
	}
	name := filepath.Join("waypost", filepath.Base(tmp.Name()))
	defer root.Remove(name)
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(name, recordPath(view.Prefix))
}

func Read(view *repoview.View, selection Selection) Status {
	out := Status{Verification: "none"}
	if view.GitDir == "" {
		return out
	}
	data, err := repopath.Read(view.GitDir, filepath.ToSlash(recordPath(view.Prefix)), 64<<10)
	if err != nil {
		return out
	}
	var r record
	if json.Unmarshal(data, &r) != nil || !gitdiff.ValidSHA(r.Head) {
		return out
	}
	out.Verification = "stale"
	out.Summary = r.Summary
	if r.Diagnostic != "" {
		out.Verification, out.Diagnostic = "unavailable", r.Diagnostic
	} else if r.Head == view.SHA && r.Selection == selection {
		current, err := Fingerprint(view)
		if err != nil {
			out.Verification, out.Diagnostic = "unavailable", err.Error()
		} else if current == r.Fingerprint {
			out.Verification = "fresh"
		}
	}
	return out
}
