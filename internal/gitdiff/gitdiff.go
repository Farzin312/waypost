package gitdiff

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	_, _, head, isGit := WorktreeIdentity(repoDir)
	if !isGit {
		return snap, nil
	}
	return InspectWorktree(repoDir, baseRef, mode, head)
}

func InspectWorktree(repoDir, baseRef, mode, head string) (*Snapshot, error) {
	snap := &Snapshot{BaseRef: baseRef, IsGitRepo: true, HeadSHA: head}
	if mode == "ci" {
		if !ValidSHA(head) {
			return snap, errors.New("CI requires a committed HEAD")
		}
		tree, err := runGit(repoDir, "rev-parse", "--verify", head+"^{tree}")
		if err != nil {
			return snap, err
		}
		snap.TreeHash = strings.TrimSpace(tree)
	} else if ValidSHA(head) {
		tree, _ := runGit(repoDir, "rev-parse", "--verify", head+"^{tree}")
		snap.TreeHash = strings.TrimSpace(tree)
	}
	filterArgs, err := inertFilters(repoDir)
	if err != nil {
		return snap, err
	}
	statusOut, err := runGitBytes(repoDir, append(filterArgs, "status", "--porcelain", "-z", "--untracked-files=all", "--ignore-submodules=dirty", "--", ".")...)
	if err != nil {
		return snap, fmt.Errorf("git status: %w", err)
	}
	snap.Dirty = len(statusOut) > 0
	if mode == "ci" {
		flags, err := runGitBytes(repoDir, "ls-files", "-v", "--stage", "-z", "--", ".")
		if err != nil {
			return snap, fmt.Errorf("git index inventory: %w", err)
		}
		for record := range bytes.SplitSeq(flags, []byte{0}) {
			if len(record) <= 2 {
				continue
			}
			meta, name, ok := strings.Cut(string(record[2:]), "\t")
			if !ok {
				return snap, errors.New("malformed Git index entry")
			}
			if record[0] == 'S' || record[0] >= 'a' && record[0] <= 'z' {
				return snap, fmt.Errorf("Git index hides worktree changes for %q", name)
			}
			if strings.HasPrefix(meta, "160000 ") {
				_, dirty, err := SubmoduleState(repoDir, name)
				if err != nil {
					return snap, fmt.Errorf("submodule %q: %w", name, err)
				}
				snap.Dirty = snap.Dirty || dirty
			}
		}
	}

	// Resolve target commit and strict merge-base.
	var diffBase string
	if baseRef != "" {
		target, targetErr := head, error(nil)
		if baseRef != "HEAD" || head == "" {
			target, targetErr = ResolveCommit(repoDir, baseRef)
		}
		if targetErr != nil {
			snap.MergeBaseError = fmt.Sprintf("unable to resolve base ref %q: %v", baseRef, targetErr)
			return snap, nil
		}
		snap.TargetSHA = strings.TrimSpace(target)
		mb, err := head, error(nil)
		if snap.TargetSHA != head {
			mb, err = runGit(repoDir, "merge-base", snap.TargetSHA, head)
		}
		if err != nil {
			snap.MergeBaseError = fmt.Sprintf("unable to compute merge-base between %q and HEAD: %v", baseRef, err)
			return snap, nil
		}
		diffBase = strings.TrimSpace(mb)
		snap.BaseSHA = diffBase
	} else if mode != "ci" {
		for _, candidate := range []string{"@{upstream}", "origin/main", "main", "master"} {
			if rev, err := ResolveCommit(repoDir, candidate); err == nil {
				targetSHA := strings.TrimSpace(rev)
				mb, mbErr := head, error(nil)
				if targetSHA != head {
					mb, mbErr = runGit(repoDir, "merge-base", targetSHA, head)
				}
				if mbErr == nil {
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
		args := []string{"-c", "core.quotepath=false", "diff", "--ignore-submodules=dirty", "--no-ext-diff", "--no-textconv", "-M", "--name-status", "-z"}
		if mode == "ci" {
			args = append(args, diffBase, head)
		} else {
			args = append(args, diffBase)
		}
		out, err := runGitBytes(repoDir, append(filterArgs, append(args, "--", ".")...)...)
		if err != nil {
			return snap, fmt.Errorf("git diff: %w", err)
		}
		for _, ch := range ParseNameStatusZ(out) {
			addChange(ch)
		}
	} else if snap.HeadSHA != "" {
		out, err := runGitBytes(repoDir, append(filterArgs, "-c", "core.quotepath=false", "diff", "--ignore-submodules=dirty", "--no-ext-diff", "--no-textconv", "-M", "--name-status", "-z", "HEAD", "--", ".")...)
		if err != nil {
			return snap, fmt.Errorf("git diff: %w", err)
		}
		{
			for _, ch := range ParseNameStatusZ(out) {
				addChange(ch)
			}
		}
	}

	// Include untracked files in local mode (NUL-delimited).
	if mode != "ci" {
		records := bytes.Split(statusOut, []byte{0})
		for i := 0; i < len(records); i++ {
			record := records[i]
			if len(record) < 4 {
				continue
			}
			code, norm := string(record[:2]), string(record[3:])
			if code == "??" && !pathSet[norm] {
				addChange(Change{Status: "A", Path: norm})
			}
			if strings.ContainsAny(code, "RC") {
				i++
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
	sha, err := ResolveCommit(repoDir, ref)
	if err != nil {
		return nil, false, err
	}
	if !filepath.IsLocal(relPath) || relPath == "." || filepath.ToSlash(filepath.Clean(relPath)) != relPath {
		return nil, false, fmt.Errorf("invalid repository file %q", relPath)
	}
	entry, err := Git(repoDir, "ls-tree", "-z", sha, "--", ":(literal)"+relPath)
	if err != nil || len(entry) == 0 {
		return nil, false, err
	}
	meta, name, ok := strings.Cut(strings.TrimSuffix(string(entry), "\x00"), "\t")
	fields := strings.Fields(meta)
	if !ok || name != relPath || len(fields) != 3 || fields[1] != "blob" || (fields[0] != "100644" && fields[0] != "100755") || !ValidSHA(fields[2]) {
		return nil, false, fmt.Errorf("%q is not a regular file at %s", relPath, sha)
	}
	const limit = 4 << 20
	cmd := exec.Command("git", "--no-replace-objects", "--no-lazy-fetch", "-C", repoDir, "cat-file", "blob", fields[2])
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err = cmd.Start(); err != nil {
		return nil, false, err
	}
	raw, err := io.ReadAll(io.LimitReader(stdout, limit+1))
	if len(raw) > limit || err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, false, fmt.Errorf("%q exceeds %d bytes or could not be read", relPath, limit)
	}
	if err = cmd.Wait(); err != nil {
		return nil, false, err
	}
	return raw, true, nil
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
	fullArgs := append([]string{"--no-replace-objects", "--no-lazy-fetch", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repoDir}, args...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
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

var objectID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func ValidSHA(s string) bool { return objectID.MatchString(s) }

func ResolveCommit(repo, ref string) (string, error) {
	out, err := runGit(repo, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	out = strings.TrimSpace(out)
	if err != nil {
		return "", err
	}
	if !ValidSHA(out) {
		return "", fmt.Errorf("invalid commit object ID for %q", ref)
	}
	return out, nil
}

func IsRepository(repo string) bool {
	out, err := runGit(repo, "rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

// Git executes a static Git plumbing command with replacement objects and lazy fetch disabled.
func Git(repo string, args ...string) ([]byte, error) { return runGitBytes(repo, args...) }

// Diff reports path changes, using an empty tree when parent is empty.
func Diff(repo, parent, child string) ([]Change, error) {
	if !ValidSHA(child) || (parent != "" && !ValidSHA(parent)) {
		return nil, errors.New("diff requires verified commit IDs")
	}
	args := []string{"diff-tree", "--no-ext-diff", "--no-textconv", "--no-commit-id", "-r", "-M", "--name-status", "-z"}
	if parent == "" {
		args = append(args, "--root", child)
	} else {
		args = append(args, parent, child)
	}
	raw, err := Git(repo, append(args, "--", ".")...)
	return ParseNameStatusZ(raw), err
}

// Git status and worktree diff can otherwise invoke configured clean filters.
func inertFilters(repo string) ([]string, error) {
	cmd := exec.Command("git", "-C", repo, "config", "--null", "--name-only", "--get-regexp", `^filter\..*\.(clean|process|required)$`)
	raw, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list Git filters: %w", err)
	}
	var opts []string
	for record := range bytes.SplitSeq(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		key := string(record)
		value := ""
		if strings.HasSuffix(key, ".required") {
			value = "false"
		}
		opts = append(opts, "-c", key+"="+value)
	}
	return opts, nil
}

// WorktreeIdentity resolves project location and HEAD in one invocation.
func WorktreeIdentity(repo string) (dir, prefix, head string, ok bool) {
	raw, err := Git(repo, "rev-parse", "--path-format=absolute", "--git-dir", "--is-inside-work-tree", "--show-prefix", "--revs-only", "HEAD^{commit}")
	if err != nil {
		return "", "", "", false
	}
	// --show-prefix emits an empty line for the worktree root.
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) < 3 || lines[1] != "true" {
		return "", "", "", false
	}
	if len(lines) > 3 && ValidSHA(lines[len(lines)-1]) {
		head, lines = lines[len(lines)-1], lines[:len(lines)-1]
	}
	return lines[0], strings.Join(lines[2:], "\n"), head, true
}

// WorktreeChanges returns paths whose worktree stat or mode differs from the index.
// A cached blob is safe only when the entry also has a normal index stage and flags.
func WorktreeChanges(repo string) (map[string]bool, error) {
	opts, err := inertFilters(repo)
	if err != nil {
		return nil, err
	}
	raw, err := Git(repo, append(opts, "-c", "core.filemode=true", "-c", "core.trustctime=true", "-c", "core.checkStat=default",
		"diff-files", "--ignore-submodules=dirty", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "--", ".")...)
	changed := make(map[string]bool)
	for name := range bytes.SplitSeq(raw, []byte{0}) {
		if len(name) > 0 {
			changed[string(name)] = true
		}
	}
	return changed, err
}

// SubmoduleState checks a populated gitlink using the submodule's own inert
// filter configuration. An uninitialized directory has no worktree state.
func SubmoduleState(repo, rel string) (head string, dirty bool, err error) {
	dir := filepath.Join(repo, filepath.FromSlash(rel))
	if _, err := os.Lstat(filepath.Join(dir, ".git")); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	head, err = ResolveCommit(dir, "HEAD")
	if err != nil {
		return "", false, err
	}
	opts, err := inertFilters(dir)
	if err != nil {
		return "", false, err
	}
	raw, err := Git(dir, append(opts, "status", "--porcelain", "-z", "--ignore-submodules=dirty")...)
	return head, len(raw) > 0, err
}
