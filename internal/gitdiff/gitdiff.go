package gitdiff

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Change describes one git status entry (preserving both old and new paths on renames).
type Change struct {
	Status  string `json:"status"` // A, M, D, R, C, T, U
	Path    string `json:"path"`
	OldPath string `json:"old_path,omitempty"`
}

// Snapshot captures repository git identity and changed paths relative to a base ref.
type Snapshot struct {
	IsGitRepo        bool     `json:"is_git_repo"`
	HeadSHA          string   `json:"head_sha"`
	TreeHash         string   `json:"tree_hash"`
	BaseRef          string   `json:"base_ref,omitempty"`
	BaseSHA          string   `json:"base_sha,omitempty"`
	Dirty            bool     `json:"dirty"`
	Changes          []Change `json:"changes,omitempty"`
	AffectedPaths    []string `json:"affected_paths,omitempty"` // Sorted unique union of Path and OldPath
	MergeBaseError   string   `json:"merge_base_error,omitempty"`
}

// Inspect computes git identity, dirty state, and changed paths against baseRef.
// When mode == "ci", diff is evaluated strictly on committed range <merge-base>..HEAD
// (plus dirty files are still reported so receipts bind honestly to working state).
// When mode == "local", diff includes both committed and uncommitted changes vs baseRef
// (or vs HEAD if baseRef is empty).
func Inspect(repoDir, baseRef, mode string) (*Snapshot, error) {
	snap := &Snapshot{BaseRef: baseRef}
	if _, err := runGit(repoDir, "rev-parse", "--is-inside-work-tree"); err != nil {
		return snap, nil
	}
	snap.IsGitRepo = true

	head, err := runGit(repoDir, "rev-parse", "HEAD")
	if err == nil {
		snap.HeadSHA = strings.TrimSpace(head)
	}
	tree, err := runGit(repoDir, "rev-parse", "HEAD^{tree}")
	if err == nil {
		snap.TreeHash = strings.TrimSpace(tree)
	}

	statusOut, err := runGit(repoDir, "status", "--porcelain")
	if err == nil {
		trimmed := strings.TrimSpace(statusOut)
		snap.Dirty = trimmed != ""
	}

	// Determine effective base SHA.
	var diffBase string
	if baseRef != "" {
		mb, err := runGit(repoDir, "merge-base", baseRef, "HEAD")
		if err != nil {
			// Fallback: check if baseRef itself resolves as a commit (e.g., direct parent SHA).
			if rev, revErr := runGit(repoDir, "rev-parse", "--verify", baseRef+"^{commit}"); revErr == nil {
				diffBase = strings.TrimSpace(rev)
				snap.BaseSHA = diffBase
			} else {
				snap.MergeBaseError = fmt.Sprintf("unable to resolve merge-base for %q: %v", baseRef, err)
				return snap, nil
			}
		} else {
			diffBase = strings.TrimSpace(mb)
			snap.BaseSHA = diffBase
		}
	} else {
		// Auto-detect origin/main, main, master, or HEAD~1 if available.
		for _, candidate := range []string{"origin/main", "main", "master"} {
			if rev, err := runGit(repoDir, "rev-parse", "--verify", candidate+"^{commit}"); err == nil {
				mb, mbErr := runGit(repoDir, "merge-base", strings.TrimSpace(rev), "HEAD")
				if mbErr == nil {
					snap.BaseRef = candidate
					diffBase = strings.TrimSpace(mb)
					snap.BaseSHA = diffBase
					break
				}
			}
		}
	}

	pathSet := make(map[string]bool)
	addChange := func(ch Change) {
		snap.Changes = append(snap.Changes, ch)
		if ch.Path != "" {
			pathSet[filepath.ToSlash(ch.Path)] = true
		}
		if ch.OldPath != "" {
			pathSet[filepath.ToSlash(ch.OldPath)] = true
		}
	}

	if diffBase != "" {
		args := []string{"diff", "-M", "--name-status"}
		if mode == "ci" {
			args = append(args, diffBase, "HEAD")
		} else {
			// Includes committed, staged, and unstaged working tree edits vs merge-base.
			args = append(args, diffBase)
		}
		out, err := runGit(repoDir, args...)
		if err != nil {
			return snap, fmt.Errorf("git diff: %w", err)
		}
		for _, ch := range ParseNameStatus(out) {
			addChange(ch)
		}
	} else if snap.HeadSHA != "" {
		// Single-branch/no-base local inspection: diff working tree vs HEAD.
		out, err := runGit(repoDir, "diff", "-M", "--name-status", "HEAD")
		if err == nil {
			for _, ch := range ParseNameStatus(out) {
				addChange(ch)
			}
		}
	}

	// Include untracked files in local mode (not ignored) so newly added files are mapped.
	if mode != "ci" {
		untracked, err := runGit(repoDir, "ls-files", "--others", "--exclude-standard")
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(untracked), "\n") {
				p := strings.TrimSpace(line)
				if p == "" {
					continue
				}
				if !pathSet[filepath.ToSlash(p)] {
					addChange(Change{Status: "A", Path: filepath.ToSlash(p)})
				}
			}
		}
	}

	snap.AffectedPaths = make([]string, 0, len(pathSet))
	for p := range pathSet {
		snap.AffectedPaths = append(snap.AffectedPaths, p)
	}
	sort.Strings(snap.AffectedPaths)
	return snap, nil
}

// ParseNameStatus parses `git diff -M --name-status` output, preserving BOTH sides
// of renames (R) and copies (C) as well as deletions (D).
func ParseNameStatus(out string) []Change {
	var changes []Change
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		status := strings.TrimSpace(fields[0])
		if len(status) == 0 {
			continue
		}
		code := string(status[0])
		switch code {
		case "R", "C":
			if len(fields) >= 3 {
				changes = append(changes, Change{
					Status:  code,
					OldPath: filepath.ToSlash(fields[1]),
					Path:    filepath.ToSlash(fields[2]),
				})
			}
		default:
			changes = append(changes, Change{
				Status: code,
				Path:   filepath.ToSlash(fields[1]),
			})
		}
	}
	return changes
}

// ReadFileAtRef reads a file from a git commit/ref via `git show <ref>:<relPath>`.
// Returns (nil, false, nil) if the file does not exist at that ref.
func ReadFileAtRef(repoDir, ref, relPath string) ([]byte, bool, error) {
	if ref == "" {
		return nil, false, nil
	}
	spec := ref + ":" + filepath.ToSlash(relPath)
	cmd := exec.Command("git", "-C", repoDir, "show", spec)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "exists on disk, but not in") || strings.Contains(msg, "Path ") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("git show %s: %w (%s)", spec, err, strings.TrimSpace(msg))
	}
	return stdout.Bytes(), true, nil
}

// ListTrackedFiles lists all tracked files in the git repo (used for coverage/unmapped-path audits).
func ListTrackedFiles(repoDir string) ([]string, error) {
	out, err := runGit(repoDir, "ls-files")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		p := strings.TrimSpace(line)
		if p != "" {
			files = append(files, filepath.ToSlash(p))
		}
	}
	sort.Strings(files)
	return files, nil
}

func runGit(repoDir string, args ...string) (string, error) {
	fullArgs := append([]string{"-C", repoDir}, args...)
	cmd := exec.Command("git", fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return stdout.String(), nil
}
