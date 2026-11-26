// Package repopath validates and reads bounded repository-relative inputs.
package repopath

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const MaxPolicyBytes = 4 << 20

func Valid(rel string) bool {
	return fs.ValidPath(rel) && rel != "." && filepath.IsLocal(rel) &&
		!strings.ContainsAny(rel, "\\:\x00") && !strings.EqualFold(strings.Split(rel, "/")[0], ".git")
}

// Read rejects symlinks in every path component and bounds dynamic file sizes.
func Read(repo, rel string, limit int) ([]byte, error) {
	if !Valid(rel) {
		return nil, fmt.Errorf("invalid repository path %q", rel)
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for parent := path.Dir(rel); parent != "."; parent = path.Dir(parent) {
		info, err := root.Lstat(filepath.FromSlash(parent))
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%q has an unsafe parent %q", rel, parent)
		}
	}
	name := filepath.FromSlash(rel)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", rel)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("%q exceeds %d bytes", rel, limit)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%q changed while opening", rel)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if len(data) > limit {
		return nil, fmt.Errorf("%q exceeds %d bytes", rel, limit)
	}
	return data, err
}

func ValidateGlob(pattern string) error {
	clean := strings.TrimPrefix(pattern, "./")
	if !Valid(clean) {
		return fmt.Errorf("invalid repository glob %q", pattern)
	}
	for _, segment := range strings.Split(clean, "/") {
		if _, err := path.Match(segment, ""); err != nil {
			return fmt.Errorf("invalid repository glob %q: %w", pattern, err)
		}
	}
	return nil
}

// CheckRegular rejects symlinks in a path or its parents without reading contents.
func CheckRegular(repo, rel string) error {
	if !Valid(rel) {
		return fmt.Errorf("invalid repository path %q", rel)
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return err
	}
	defer root.Close()
	for prefix := rel; prefix != "."; prefix = path.Dir(prefix) {
		info, err := root.Lstat(filepath.FromSlash(prefix))
		if err != nil {
			return err
		}
		if (prefix == rel && !info.Mode().IsRegular()) || (prefix != rel && !info.IsDir()) {
			return fmt.Errorf("%q is not a regular repository file", rel)
		}
	}
	return nil
}
