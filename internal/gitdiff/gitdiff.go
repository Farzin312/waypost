package gitdiff

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Change describes one git status entry (preserving both old and new paths on renames).
type Change struct {
	Status  string `json:"status"` // A, M, D, R, C, T, U
	Path    string `json:"path"`
	OldPath string `json:"old_path,omitempty"`
}

// Snapshot captures repository git identity and changed paths relative to a base ref.
// TargetSHA is the resolved tip commit of BaseRef (used for base-branch policy authority),
// while BaseSHA is the merge-base commit (used as the diff starting point).
type Snapshot struct {
	IsGitRepo      bool     `json:"is_git_repo"`
	HeadSHA        string   `json:"head_sha"`
	TreeHash       string   `json:"tree_hash"`
	BaseRef        string   `json:"base_ref,omitempty"`
	TargetSHA      string   `json:"target_sha,omitempty"`
	BaseSHA        string   `json:"base_sha,omitempty"`
	Dirty          bool     `json:"dirty"`
	Changes        []Change `json:"changes,omitempty"`
	AffectedPaths  []string `json:"affected_paths,omitempty"` // Sorted unique union of Path and OldPath
	MergeBaseError string   `json:"merge_base_error,omitempty"`
}

// Inspect computes git identity, dirty state, and changed paths against baseRef.
// Uses NUL-delimited (`-z`) git output so non-ASCII and special filenames are never C-quoted.
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

	statusOut, err := runGit(repoDir, "status", "--porcelain", "-z")
	if err == nil {
		snap.Dirty = len(statusOut) > 0
	}

	// Resolve target commit and strict merge-base.
	var diffBase string
	if baseRef != "" {
		target, targetErr := runGit(repoDir, "rev-parse", "--verify", baseRef+"^{commit}")
		if targetErr != nil {
			snap.MergeBaseError = fmt.Sprintf("unable to resolve base ref %q: %v", baseRef, targetErr)
			return snap, nil
		}
		snap.TargetSHA = strings.TrimSpace(target)
		mb, err := runGit(repoDir, "merge-base", snap.TargetSHA, "HEAD")
		if err != nil {
			snap.MergeBaseError = fmt.Sprintf("unable to compute merge-base between %q and HEAD: %v", baseRef, err)
			return snap, nil
		}
		diffBase = strings.TrimSpace(mb)
		snap.BaseSHA = diffBase
	} else {
		for _, candidate := range []string{"origin/main", "main", "master"} {
			if rev, err := runGit(repoDir, "rev-parse", "--verify", candidate+"^{commit}"); err == nil {
				targetSHA := strings.TrimSpace(rev)
				if mb, mbErr := runGit(repoDir, "merge-base", targetSHA, "HEAD"); mbErr == nil {
					snap.BaseRef = candidate
					snap.TargetSHA = targetSHA
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
		args := []string{"-c", "core.quotepath=false", "diff", "-M", "--name-status", "-z"}
		if mode == "ci" {
			args = append(args, diffBase, "HEAD")
		} else {
			args = append(args, diffBase)
		}
		out, err := runGitBytes(repoDir, args...)
		if err != nil {
			return snap, fmt.Errorf("git diff: %w", err)
		}
		for _, ch := range ParseNameStatusZ(out) {
			addChange(ch)
		}
	} else if snap.HeadSHA != "" {
		out, err := runGitBytes(repoDir, "-c", "core.quotepath=false", "diff", "-M", "--name-status", "-z", "HEAD")
		if err == nil {
			for _, ch := range ParseNameStatusZ(out) {
				addChange(ch)
			}
		}
	}

	// Include untracked files in local mode (NUL-delimited).
	if mode != "ci" {
		untracked, err := runGitBytes(repoDir, "-c", "core.quotepath=false", "ls-files", "--others", "--exclude-standard", "-z")
		if err == nil {
			for _, rawPath := range bytes.Split(untracked, []byte{0}) {
				p := string(rawPath)
				if p == "" {
					continue
				}
				norm := filepath.ToSlash(p)
				if !pathSet[norm] {
					addChange(Change{Status: "A", Path: norm})
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

// ParseNameStatusZ parses NUL-delimited `git diff -M --name-status -z` output,
// preserving literal non-ASCII/special path bytes and BOTH sides of renames/copies.
func ParseNameStatusZ(out []byte) []Change {
	var changes []Change
	tokens := bytes.Split(out, []byte{0})
	for i := 0; i < len(tokens); {
		status := string(tokens[i])
		if status == "" {
			i++
			continue
		}
		code := string(status[0])
		switch code {
		case "R", "C":
			if i+2 < len(tokens) {
				changes = append(changes, Change{
					Status:  code,
					OldPath: filepath.ToSlash(string(tokens[i+1])),
					Path:    filepath.ToSlash(string(tokens[i+2])),
				})
				i += 3
			} else {
				i = len(tokens)
			}
		default:
			if i+1 < len(tokens) {
				changes = append(changes, Change{
					Status: code,
					Path:   filepath.ToSlash(string(tokens[i+1])),
				})
				i += 2
			} else {
				i = len(tokens)
			}
		}
	}
	return changes
}

// ParseNameStatus parses line-delimited `git diff -M --name-status` output.
func ParseNameStatus(out string) []Change {
	var changes []Change
	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || len(fields[0]) == 0 {
			continue
		}
		code := string(fields[0][0])
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
	cleanRel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(relPath)), "./")
	if strings.HasPrefix(cleanRel, "../") || cleanRel == ".." || filepath.IsAbs(relPath) {
		return nil, false, fmt.Errorf("path %q escapes repository root at ref %s", relPath, ref)
	}
	spec := ref + ":./" + cleanRel
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

// RegularFilesAtRef returns repository-relative file sizes for regular blobs in a commit.
func RegularFilesAtRef(repoDir, ref string) (map[string]int64, error) {
	out, err := runGitBytes(repoDir, "ls-tree", "-r", "-l", "-z", ref, "--", ".")
	if err != nil {
		return nil, err
	}
	files := make(map[string]int64)
	for _, record := range bytes.Split(out, []byte{0}) {
		meta, name, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 4 || (fields[0] != "100644" && fields[0] != "100755") {
			continue
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("read size of %q at %s: %w", name, ref, err)
		}
		files[name] = size
	}
	return files, nil
}

// ListTrackedFiles lists all tracked files in the git repo using NUL-delimited output.
func ListTrackedFiles(repoDir string) ([]string, error) {
	return listFiles(repoDir, "--cached")
}

// ListWorkingFiles lists tracked and untracked, non-ignored worktree paths.
func ListWorkingFiles(repoDir string) ([]string, error) {
	return listFiles(repoDir, "--cached", "--others", "--exclude-standard")
}

func listFiles(repoDir string, flags ...string) ([]string, error) {
	args := append([]string{"ls-files", "-z"}, flags...)
	out, err := runGitBytes(repoDir, args...)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) > 0 {
			files = append(files, filepath.ToSlash(string(raw)))
		}
	}
	sort.Strings(files)
	return files, nil
}

func runGit(repoDir string, args ...string) (string, error) {
	b, err := runGitBytes(repoDir, args...)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func runGitBytes(repoDir string, args ...string) ([]byte, error) {
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
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}

// ReadBoundedRegularFileAtRef checks the Git tree entry before reading its blob.
func ReadBoundedRegularFileAtRef(repoDir, ref, relPath string, maxBytes int) ([]byte, bool, error) {
	if !filepath.IsLocal(relPath) || relPath == "." || filepath.ToSlash(filepath.Clean(relPath)) != relPath {
		return nil, false, fmt.Errorf("invalid repository path %q", relPath)
	}
	out, err := runGitBytes(repoDir, "ls-tree", "-l", "-z", ref, "--", ":(literal)"+relPath)
	if err != nil {
		return nil, false, err
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	meta, name, ok := strings.Cut(strings.TrimSuffix(string(out), "\x00"), "\t")
	fields := strings.Fields(meta)
	if !ok || name != relPath || len(fields) != 4 || fields[1] != "blob" ||
		(fields[0] != "100644" && fields[0] != "100755") {
		return nil, false, fmt.Errorf("%q at %s is not a regular file", relPath, ref)
	}
	size, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || size < 0 || size > int64(maxBytes) {
		return nil, false, fmt.Errorf("%q at %s exceeds %d bytes", relPath, ref, maxBytes)
	}
	return ReadFileAtRef(repoDir, ref, relPath)
}
