package compmap

import (
	"path"
	"strings"
)

// MatchGlob matches a slash-normalized relative path against a gitignore/glob-style
// pattern supporting `*`, `?`, and `**` across directory boundaries.
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
	return matchSegments(patSegs, tgtSegs)
}

func matchSegments(pat, tgt []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// Collapse consecutive ** segments.
			for len(pat) > 1 && pat[1] == "**" {
				pat = pat[1:]
			}
			// Trailing ** matches everything remaining (including zero segments).
			if len(pat) == 1 {
				return true
			}
			// Try matching zero or more target segments.
			for i := 0; i <= len(tgt); i++ {
				if matchSegments(pat[1:], tgt[i:]) {
					return true
				}
			}
			return false
		}
		if len(tgt) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], tgt[0])
		if err != nil || !ok {
			return false
		}
		pat = pat[1:]
		tgt = tgt[1:]
	}
	return len(tgt) == 0
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
