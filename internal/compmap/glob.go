package compmap

import (
	"path"
	"strings"
)

// MatchGlob matches a slash-normalized relative path against a glob pattern
// supporting `*`, `?`, and `**` across directory boundaries in O(len(pat)*len(tgt)) time.
func MatchGlob(pattern, target string) bool {
	pattern = strings.TrimPrefix(path.Clean(strings.ReplaceAll(pattern, "\\", "/")), "./")
	target = strings.TrimPrefix(path.Clean(strings.ReplaceAll(target, "\\", "/")), "./")
	if pattern == "." || pattern == "" {
		return false
	}
	if pattern == "**" || pattern == "**/*" {
		return true
	}
	patSegs := strings.Split(pattern, "/")
	tgtSegs := strings.Split(target, "/")

	// Iterative dynamic programming avoids exponential backtracking on repeated `**`.
	m := len(patSegs)
	n := len(tgtSegs)
	dp := make([]bool, n+1)
	dp[0] = true

	for i := 1; i <= m; i++ {
		next := make([]bool, n+1)
		p := patSegs[i-1]
		if p == "**" {
			// `**` matches zero or more target segments.
			matched := false
			for j := 0; j <= n; j++ {
				if dp[j] {
					matched = true
				}
				next[j] = matched
			}
		} else {
			for j := 1; j <= n; j++ {
				if !dp[j-1] {
					continue
				}
				if ok, err := path.Match(p, tgtSegs[j-1]); err == nil && ok {
					next[j] = true
				}
			}
		}
		dp = next
	}
	return dp[n]
}

// MatchAnyGlob returns true if target matches any pattern in patterns.
func MatchAnyGlob(patterns []string, target string) bool {
	for _, p := range patterns {
		if MatchGlob(p, target) {
			return true
		}
	}
	return false
}
