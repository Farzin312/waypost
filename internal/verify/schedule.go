package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Farzin312/waypost/internal/repoview"
	"github.com/Farzin312/waypost/internal/shellcmd"
	"sync"

	"github.com/Farzin312/waypost/internal/changeplan"
	"github.com/Farzin312/waypost/internal/config"
	"github.com/Farzin312/waypost/internal/gitdiff"
)

type handoff struct{ file, base, head string }

func handoffFile(snap *gitdiff.Snapshot) (handoff, func(), error) {
	none := func() {}
	if !gitdiff.ValidSHA(snap.BaseSHA) || !gitdiff.ValidSHA(snap.HeadSHA) {
		return handoff{}, none, nil
	}
	dir, err := os.MkdirTemp("", "waypost-changes-")
	if err != nil {
		return handoff{}, none, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	file := filepath.Join(dir, "paths")
	var data []byte
	for _, path := range snap.AffectedPaths {
		if path == "" || strings.ContainsRune(path, 0) {
			cleanup()
			return handoff{}, none, fmt.Errorf("invalid changed path %q", path)
		}
		data = append(data, path...)
		data = append(data, 0)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		cleanup()
		return handoff{}, none, err
	}
	return handoff{file, snap.BaseSHA, snap.HeadSHA}, cleanup, nil
}

func (h handoff) env() []string {
	env := shellcmd.Environment()
	if h.file != "" {
		env = append(env, "WAYPOST_NO_TESTS_EXIT_CODE=5")
		env = append(env, "WAYPOST_CHANGED_FILES_FILE="+h.file, "WAYPOST_BASE_SHA="+h.base, "WAYPOST_HEAD_SHA="+h.head)
	}
	return env
}

func schedule(checks []changeplan.Check, jobs int, run func(changeplan.Check) CheckResult) []CheckResult {
	results := make([]CheckResult, len(checks))
	for start := 0; start < len(checks); {
		if jobs == 1 || config.BoolVal(checks[start].Check.Serial, true) || !checks[start].Selected {
			results[start] = run(checks[start])
			start++
			continue
		}
		end := start + 1
		for end < len(checks) && !config.BoolVal(checks[end].Check.Serial, true) {
			end++
		}
		var workers sync.WaitGroup
		tasks := make(chan int)
		for range min(jobs, end-start) {
			workers.Go(func() {
				for index := range tasks {
					results[index] = run(checks[index])
				}
			})
		}
		for i := start; i < end; i++ {
			tasks <- i
		}
		close(tasks)
		workers.Wait()
		start = end
	}
	return results
}

const noTestsExitCode = 5

var selectorToken = regexp.MustCompile(`^[A-Za-z0-9_./:@=-]+$`)

// For production changes, only use selectors with explicit existing test
// arguments and a runner that fails when those tests cannot run.
func explicitTestCommand(command, workdir string, view *repoview.View) bool {
	args := strings.Fields(command)
	for _, arg := range args {
		if !selectorToken.MatchString(arg) || arg == "--passWithNoTests" {
			return false
		}
	}
	var files []string
	switch {
	case len(args) > 2 && args[0] == "node":
		i := 1
		if len(args) > 4 && args[i] == "--import" && !strings.HasPrefix(args[i+1], "-") {
			i += 2
		}
		if args[i] != "--test" {
			return false
		}
		files = args[i+1:]
	case len(args) > 5 && args[0] == "npm" && args[1] == "run" && args[3] == "--" && args[4] == "--runTestsByPath":
		manifest, err := view.Read(path.Join(workdir, "package.json"), 512<<10)
		var pkg struct{ Scripts map[string]string }
		if err != nil || json.Unmarshal(manifest, &pkg) != nil {
			return false
		}
		script := strings.Fields(pkg.Scripts[args[2]])
		if len(script) == 0 || script[0] != "jest" {
			return false
		}
		for _, token := range script[1:] {
			// Whitelist ordinary runner tuning flags. Selection and shell-control flags are excluded.
			if !selectorToken.MatchString(token) || (token != "--runInBand" && !strings.HasPrefix(token, "--maxWorkers=")) {
				return false
			}
		}
		files = args[5:]
	default:
		return false
	}
	if len(files) == 0 {
		return false
	}
	for _, name := range files {
		if strings.HasPrefix(name, "-") || !view.Files[path.Join(workdir, name)].Regular() {
			return false
		}
	}
	return true
}
