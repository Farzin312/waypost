// Package repoview describes working and committed repository inputs without executing code.
package repoview

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/Farzin312/waypost/internal/gitdiff"
	"github.com/Farzin312/waypost/internal/repopath"
)

type File struct {
	Path      string
	Mode      string
	Blob      string
	Size      int64
	Tracked   bool
	Clean     bool
	Submodule string
}

func (f File) Regular() bool { return f.Mode == "100644" || f.Mode == "100755" }

type Identity struct {
	Kind string `json:"kind"`
	SHA  string `json:"sha,omitempty"`
}

type View struct {
	Repo string
	Identity
	Files  map[string]File
	Index  []byte
	GitDir string
	Prefix string
	store  *Store
}

// Store shares one bounded blob reader and a small content cache across trees.
type Store struct {
	parsed map[[2]string]any
	repo   string
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	cache  map[string][]byte
	bytes  int
	trees  map[string][]File
}

func NewStore(repo string) *Store { return &Store{repo: repo, cache: make(map[string][]byte)} }

func (s *Store) Close() error {
	if s.cmd == nil {
		return nil
	}
	_ = s.input.Close()
	err := s.cmd.Wait()
	s.cmd = nil
	return err
}

func (s *Store) Commit(ref string) (*View, error) {
	sha, err := gitdiff.ResolveCommit(s.repo, ref)
	if err != nil {
		return nil, err
	}
	return s.Tree(sha)
}

func (s *Store) Tree(sha string) (*View, error) {
	if !gitdiff.ValidSHA(sha) {
		return nil, errors.New("tree requires a verified commit ID")
	}
	raw, err := gitdiff.Git(s.repo, "ls-tree", "-r", "-l", "-z", sha, "--", ".")
	if err != nil {
		return nil, err
	}
	view := &View{Repo: s.repo, Identity: Identity{Kind: "commit", SHA: sha}, Files: make(map[string]File), store: s}
	for record := range bytes.SplitSeq(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		meta, name, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 4 || !validName(name) || !gitdiff.ValidSHA(fields[2]) {
			return nil, fmt.Errorf("invalid Git tree entry %q", record)
		}
		var size int64
		if fields[1] == "blob" {
			size, err = strconv.ParseInt(fields[3], 10, 64)
			if err != nil || size < 0 {
				return nil, fmt.Errorf("invalid blob size at %q", name)
			}
		}
		view.Files[name] = File{Path: name, Mode: fields[0], Blob: fields[2], Size: size, Tracked: true}
	}
	return view, nil
}

func Working(repo string) (*View, error) {
	view := &View{Repo: repo, Identity: Identity{Kind: "worktree"}, Files: make(map[string]File)}
	add := func(rel string, tracked bool, info fs.FileInfo) {
		entry := File{Path: rel, Tracked: tracked, Size: info.Size()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			entry.Mode = "120000"
		case info.Mode().IsRegular():
			entry.Mode = "100644"
			if info.Mode()&0o111 != 0 {
				entry.Mode = "100755"
			}
		}
		view.Files[rel] = entry
	}
	dir, prefix, head, isGit := gitdiff.WorktreeIdentity(repo)
	if !isGit {
		err := filepath.WalkDir(repo, func(full string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "node_modules", ".venv":
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(repo, full)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			add(filepath.ToSlash(rel), false, info)
			return nil
		})
		return view, err
	}
	view.GitDir, view.Prefix, view.SHA = dir, prefix, head
	raw, err := gitdiff.Git(repo, "ls-files", "-v", "--stage", "--cached", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for record := range bytes.SplitSeq(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		if len(record) < 3 || record[1] != ' ' {
			return nil, fmt.Errorf("invalid Git index entry %q", record)
		}
		rel := string(record[2:])
		tracked := record[0] != '?'
		var fields []string
		if tracked {
			meta, name, ok := strings.Cut(rel, "\t")
			fields = strings.Fields(meta)
			if !ok || len(fields) != 3 || !gitdiff.ValidSHA(fields[1]) {
				return nil, fmt.Errorf("invalid Git index entry %q", record)
			}
			rel = name
			view.Index = append(view.Index, record...)
			view.Index = append(view.Index, 0)
		}
		if !validName(rel) {
			return nil, fmt.Errorf("invalid Git inventory path %q", rel)
		}
		if _, duplicate := view.Files[rel]; duplicate {
			continue
		}
		info, err := root.Lstat(filepath.FromSlash(rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %q: %w", rel, err)
		}
		add(rel, tracked, info)
		if tracked {
			entry := view.Files[rel]
			if fields[0] == "160000" && info.IsDir() {
				entry.Mode = fields[0]
			}
			entry.Blob = fields[1]
			entry.Clean = record[0] == 'H' && fields[2] == "0" && entry.Mode == fields[0]
			view.Files[rel] = entry
		}
	}
	return view, nil
}

func validName(name string) bool {
	return name != "." && !strings.HasPrefix(name, "/") && filepath.ToSlash(filepath.Clean(name)) == name &&
		name != ".." && !strings.HasPrefix(name, "../")
}

func (v *View) Paths() []string {
	out := make([]string, 0, len(v.Files))
	for name := range v.Files {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Inventory retains non-regular entries so their use can be diagnosed.
func (v *View) Inventory() map[string]bool {
	out := make(map[string]bool, len(v.Files))
	for name := range v.Files {
		out[name] = true
	}
	return out
}

func (v *View) Lookup(rel string, limit int) ([]byte, bool, error) {
	entry, ok := v.Files[rel]
	if !ok {
		return nil, false, nil
	}
	if !entry.Regular() {
		return nil, true, fmt.Errorf("%q must be a regular file", rel)
	}
	if entry.Size > int64(limit) {
		return nil, true, fmt.Errorf("%q exceeds %d bytes", rel, limit)
	}
	var raw []byte
	var err error
	if v.store == nil {
		raw, err = repopath.Read(v.Repo, rel, limit)
	} else {
		raw, err = v.store.object(entry.Blob, "blob", entry.Size, limit)
	}
	return raw, true, err
}

func (v *View) Read(rel string, limit int) ([]byte, error) {
	raw, ok, err := v.Lookup(rel, limit)
	if !ok {
		return nil, fmt.Errorf("%s: %w", rel, fs.ErrNotExist)
	}
	return raw, err
}

func (s *Store) object(oid, kind string, expectedSize int64, limit int) ([]byte, error) {
	if data, ok := s.cache[oid]; ok {
		if len(data) > limit {
			return nil, fmt.Errorf("Git %s %s exceeds %d bytes", kind, oid, limit)
		}
		return data, nil
	}
	if s.cmd == nil {
		cmd := exec.Command("git", "--no-replace-objects", "--no-lazy-fetch", "-C", s.repo, "cat-file", "--batch")
		in, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			_ = in.Close()
			return nil, err
		}
		if err = cmd.Start(); err != nil {
			_ = in.Close()
			_ = out.Close()
			return nil, err
		}
		s.cmd, s.input, s.output = cmd, in, bufio.NewReader(out)
	}
	if _, err := fmt.Fprintln(s.input, oid); err != nil {
		return nil, err
	}
	line, err := s.output.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(line))
	if len(fields) != 3 || fields[0] != oid || fields[1] != kind {
		return nil, fmt.Errorf("expected Git %s %s: %q", kind, oid, line)
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 || size > int64(limit) || expectedSize >= 0 && size != expectedSize {
		// Stop an oversized response without retaining or draining it.
		_ = s.cmd.Process.Kill()
		_ = s.Close()
		return nil, fmt.Errorf("Git %s %s has invalid size or exceeds %d bytes", kind, oid, limit)
	}
	raw := make([]byte, size)
	if _, err = io.ReadFull(s.output, raw); err != nil {
		return nil, err
	}
	if end, err := s.output.ReadByte(); err != nil || end != '\n' {
		return nil, fmt.Errorf("invalid Git object terminator for %s", oid)
	}
	if s.bytes+len(raw) <= 32<<20 && len(s.cache) < 16384 {
		s.cache[oid] = raw
		s.bytes += len(raw)
	}
	return raw, nil
}

// HistoricalTree shares the object reader and decoded subtrees across a traversal.
func (s *Store) HistoricalTree(sha, prefix string) (*View, error) {
	if !gitdiff.ValidSHA(sha) {
		return nil, errors.New("tree requires a verified commit ID")
	}
	commit, err := s.object(sha, "commit", -1, 8<<20)
	if err != nil {
		return nil, err
	}
	first, _, _ := bytes.Cut(commit, []byte{'\n'})
	id, ok := strings.CutPrefix(string(first), "tree ")
	if !ok || !gitdiff.ValidSHA(id) {
		return nil, errors.New("invalid Git commit tree")
	}
	view := &View{Repo: s.repo, Identity: Identity{Kind: "commit", SHA: sha}, Files: make(map[string]File), store: s}
	for _, name := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
		if name == "" {
			break
		}
		entries, err := s.treeEntries(id)
		if err != nil {
			return nil, err
		}
		i := slices.IndexFunc(entries, func(e File) bool { return e.Path == name && e.Mode == "40000" })
		if i < 0 {
			return view, nil
		}
		id = entries[i].Blob
	}
	var visit func(string, string, int) error
	visit = func(id, parent string, depth int) error {
		if depth > 256 {
			return errors.New("Git tree exceeds supported depth")
		}
		entries, err := s.treeEntries(id)
		if err != nil {
			return err
		}
		for _, e := range entries {
			e.Path = parent + e.Path
			if e.Mode == "40000" {
				if err := visit(e.Blob, e.Path+"/", depth+1); err != nil {
					return err
				}
			} else {
				view.Files[e.Path] = e
			}
		}
		return nil
	}
	return view, visit(id, "", 0)
}

func (s *Store) treeEntries(oid string) ([]File, error) {
	if entries, ok := s.trees[oid]; ok {
		return entries, nil
	}
	raw, err := s.object(oid, "tree", -1, 64<<20)
	if err != nil {
		return nil, err
	}
	var entries []File
	hashSize := len(oid) / 2
	for len(raw) != 0 {
		meta, rest, ok := bytes.Cut(raw, []byte{0})
		mode, name, split := strings.Cut(string(meta), " ")
		if !ok || !split || !validName(name) || name == "" || strings.Contains(name, "/") || len(rest) < hashSize {
			return nil, fmt.Errorf("invalid Git tree %s", oid)
		}
		entries = append(entries, File{Path: name, Mode: mode, Blob: hex.EncodeToString(rest[:hashSize]), Size: -1, Tracked: true})
		raw = rest[hashSize:]
	}
	if s.trees == nil {
		s.trees = make(map[string][]File)
	}
	if len(s.trees) < 16384 {
		s.trees[oid] = entries
	}
	return entries, nil
}

// CachedParse reuses immutable, path-independent parses for a blob and grammar.
func (v *View) CachedParse(rel, grammar string, dst any) bool {
	e := v.Files[rel]
	if v.store == nil || e.Blob == "" {
		return false
	}
	value, ok := v.store.parsed[[2]string{e.Blob, grammar}]
	if ok {
		reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(value))
	}
	return ok
}

func (v *View) CacheParse(rel, grammar string, value any) {
	e := v.Files[rel]
	if v.store == nil || e.Blob == "" || len(v.store.parsed) >= 32768 {
		return
	}
	if v.store.parsed == nil {
		v.store.parsed = make(map[[2]string]any)
	}
	v.store.parsed[[2]string{e.Blob, grammar}] = value
}

// GitDir returns the metadata directory of this worktree without resolving
// a linked worktree to its common Git directory.
func GitDir(repo string) (string, error) {
	raw, err := gitdiff.Git(repo, "rev-parse", "--path-format=absolute", "--git-dir")
	if err != nil {
		return "", err
	}
	dir := strings.TrimSuffix(string(raw), "\n")
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("Git directory is not absolute")
	}
	return dir, nil
}

// GitPrefix is the project directory's path relative to the Git worktree root.
func GitPrefix(repo string) (string, error) {
	raw, err := gitdiff.Git(repo, "rev-parse", "--show-prefix")
	return strings.TrimSuffix(string(raw), "\n"), err
}
