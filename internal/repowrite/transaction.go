package repowrite

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Farzin312/waypost/internal/repopath"
	"github.com/Farzin312/waypost/internal/repoview"
)

const journalName = "sync-transaction.json"

type Mutation struct {
	Path  string
	Old   []byte
	New   []byte
	Mode  fs.FileMode
	Stage string
}

type Transaction struct {
	repo, meta  string
	mutations   []Mutation
	publishFile func(string, string) error
	root        *os.Root
}

func transactionDir(repo string) (string, error) {
	if dir, err := repoview.GitDir(repo); err == nil {
		prefix, err := repoview.GitPrefix(repo)
		if err != nil {
			return "", err
		}
		meta := filepath.Join(dir, "waypost")
		if prefix != "" {
			meta = filepath.Join(meta, fmt.Sprintf("sync-%x", sha256.Sum256([]byte(prefix))))
		}
		return meta, nil
	}
	path, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "waypost", "sync", fmt.Sprintf("%x", sha256.Sum256([]byte(path)))), nil
}

func Acquire(repo string) (*Transaction, func(), error) {
	none := func() {}
	meta, err := transactionDir(repo)
	if err != nil {
		return nil, none, err
	}
	if err = os.MkdirAll(meta, 0o700); err != nil {
		return nil, none, err
	}
	info, err := os.Lstat(meta)
	if err != nil || !info.IsDir() {
		return nil, none, errors.New("unsafe sync metadata directory")
	}
	lock, err := os.OpenFile(filepath.Join(meta, "sync.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, none, err
	}
	if err = lockFile(lock); err != nil {
		_ = lock.Close()
		return nil, none, err
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		_ = lock.Close()
		return nil, none, err
	}
	close := func() { _ = root.Close(); _ = lock.Close() }
	tx := &Transaction{repo: repo, meta: meta, publishFile: root.Rename, root: root}
	if err = tx.recover(); err != nil {
		close()
		return nil, none, err
	}
	return tx, close, nil
}

func Read(repo, rel string) ([]byte, error) {
	data, err := repopath.Read(repo, rel, repopath.MaxPolicyBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err == nil && data == nil {
		data = []byte{}
	}
	return data, err
}

func Same(a, b []byte) bool { return (a == nil) == (b == nil) && bytes.Equal(a, b) }

func (t *Transaction) expect() error {
	for _, item := range t.mutations {
		live, err := Read(t.repo, item.Path)
		if err != nil {
			return err
		}
		if !Same(live, item.Old) {
			return fmt.Errorf("%s changed during sync; rerun waypost sync", item.Path)
		}
	}
	return nil
}

func (t *Transaction) recover() error {
	file := filepath.Join(t.meta, journalName)
	raw, err := repopath.Read(t.meta, journalName, 34<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var mutations []Mutation
	if err = json.Unmarshal(raw, &mutations); err != nil {
		return fmt.Errorf("read sync journal: %w", err)
	}
	if len(mutations) == 0 || len(mutations) > 3 {
		return errors.New("invalid sync journal")
	}
	seen := make(map[string]bool)
	for _, item := range mutations {
		if !repopath.Valid(item.Path) || seen[item.Path] || strings.EqualFold(item.Path, ".waypost.local.yaml") ||
			(item.Stage != "" && (!repopath.Valid(item.Stage) || filepath.Dir(item.Stage) != filepath.Dir(item.Path) ||
				!strings.HasPrefix(filepath.Base(item.Stage), ".waypost-stage-"))) {
			return fmt.Errorf("invalid sync recovery path %q", item.Path)
		}
		seen[item.Path] = true
		live, err := Read(t.repo, item.Path)
		if err != nil {
			return err
		}
		if !Same(live, item.New) && !Same(live, item.Old) {
			return fmt.Errorf("cannot recover sync transaction: %s changed after the interrupted publish", item.Path)
		}
	}
	for i := len(mutations) - 1; i >= 0; i-- {
		item := mutations[i]
		live, err := Read(t.repo, item.Path)
		if err != nil {
			return err
		}
		if Same(live, item.Old) {
			continue
		}
		if !Same(live, item.New) {
			return fmt.Errorf("cannot recover %s: file changed", item.Path)
		}
		if err := t.install(item.Path, item.Old, item.Mode); err != nil {
			return err
		}
	}
	for _, item := range mutations {
		if item.Stage != "" {
			if err := t.root.Remove(item.Stage); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	if err := os.Remove(file); err != nil {
		return err
	}
	return flushDir(t.meta)
}

// Commit publishes an expected set of file replacements or removals as one transaction.
func (t *Transaction) Commit(mutations ...Mutation) error {
	t.mutations = mutations
	return t.commit()
}

// CheckReady reports an incomplete transaction without changing the repository.
func CheckReady(repo string) error {
	meta, err := transactionDir(repo)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(meta, journalName)); err == nil {
		return errors.New("an interrupted policy write needs recovery; run waypost sync --apply")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (t *Transaction) commit() error {
	if len(t.mutations) == 0 {
		return nil
	}
	if len(t.mutations) > 3 {
		return errors.New("too many policy files in one transaction")
	}
	seen := make(map[string]bool)
	for _, item := range t.mutations {
		if !repopath.Valid(item.Path) || seen[item.Path] || strings.EqualFold(item.Path, ".waypost.local.yaml") || len(item.New) > repopath.MaxPolicyBytes {
			return fmt.Errorf("invalid policy publication %q", item.Path)
		}
		seen[item.Path] = true
	}
	if err := t.expect(); err != nil {
		return err
	}
	for i := range t.mutations {
		item := &t.mutations[i]
		item.Mode = 0o644
		if item.Old != nil {
			info, err := t.root.Lstat(item.Path)
			if err != nil {
				return err
			}
			item.Mode = info.Mode().Perm()
		}
		if item.New != nil {
			item.Stage = filepath.ToSlash(filepath.Join(filepath.Dir(item.Path), ".waypost-stage-"+rand.Text()))
		}
	}

	raw, err := json.Marshal(t.mutations)
	if err != nil {
		return err
	}
	journal, err := stage(t.meta, raw, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(journal)
	key := filepath.Join(t.meta, journalName)
	if err := os.Rename(journal, key); err != nil {
		return err
	}
	if err := flushDir(t.meta); err != nil {
		return errors.Join(err, t.recover())
	}
	for _, item := range t.mutations {
		if item.Stage != "" {
			if err := t.root.MkdirAll(filepath.Dir(item.Stage), 0o755); err != nil {
				return errors.Join(err, t.recover())
			}
			if err := t.stage(item.Stage, item.New, item.Mode); err != nil {
				return errors.Join(err, t.recover())
			}
		}
	}
	if err := t.expect(); err != nil {
		return errors.Join(err, t.recover())
	}
	for _, item := range t.mutations {
		live, err := Read(t.repo, item.Path)
		if err == nil && !Same(live, item.Old) {
			err = fmt.Errorf("%s changed before publication", item.Path)
		}
		if err == nil && item.New == nil {
			err = t.root.Remove(item.Path)
		} else if err == nil {
			err = t.publishFile(item.Stage, item.Path)
		}
		if err == nil {
			err = flushDir(filepath.Join(t.repo, filepath.Dir(item.Path)))
		}
		if err != nil {
			return errors.Join(err, t.recover())
		}
	}
	if err := os.Remove(key); err != nil {
		return errors.Join(err, t.recover())
	}
	return flushDir(t.meta)
}

func (t *Transaction) install(rel string, data []byte, mode fs.FileMode) error {
	if data == nil {
		if err := t.root.Remove(rel); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		temp := filepath.ToSlash(filepath.Join(filepath.Dir(rel), ".waypost-stage-"+rand.Text()))
		if err := t.stage(temp, data, mode); err != nil {
			return err
		}
		defer t.root.Remove(temp)
		if err := t.root.Rename(temp, rel); err != nil {
			return err
		}
	}
	return flushDir(filepath.Join(t.repo, filepath.Dir(rel)))
}

func (t *Transaction) stage(rel string, data []byte, mode fs.FileMode) error {
	f, err := t.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Chmod(mode), f.Sync(), f.Close()); err != nil {
		_ = t.root.Remove(rel)
		return err
	}
	return nil
}

func stage(dir string, data []byte, mode fs.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".waypost-stage-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
