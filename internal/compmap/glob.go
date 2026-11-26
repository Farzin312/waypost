package compmap

import (
	"path"
	"strings"
)

type Glob struct{ segments []string }

func CompileGlobs(patterns []string) []Glob {
	out := make([]Glob, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimPrefix(path.Clean(strings.ReplaceAll(pattern, "\\", "/")), "./")
		if pattern != "." {
			out = append(out, Glob{strings.Split(pattern, "/")})
		}
	}
	return out
}

func MatchCompiled(globs []Glob, target string) bool {
	if len(globs) == 0 {
		return false
	}
	segments := strings.Split(path.Clean(target), "/")
	for _, glob := range globs {
		if glob.match(segments) {
			return true
		}
	}
	return false
}

func MatchGlob(pattern, target string) bool {
	return MatchAnyGlob([]string{pattern}, target)
}

func MatchAnyGlob(patterns []string, target string) bool {
	return MatchCompiled(CompileGlobs(patterns), target)
}

func (g Glob) match(target []string) bool {
	segments := g.segments
	for len(segments) > 0 && segments[0] != "**" {
		if len(target) == 0 {
			return false
		}
		ok, _ := path.Match(segments[0], target[0])
		if !ok {
			return false
		}
		segments, target = segments[1:], target[1:]
	}
	if len(segments) == 0 {
		return len(target) == 0
	}
	if len(segments) == 1 {
		return true
	}
	dp := make([]bool, len(target)+1)
	dp[0] = true
	for _, pattern := range segments {
		if pattern == "**" {
			for i := 1; i < len(dp); i++ {
				dp[i] = dp[i] || dp[i-1]
			}
			continue
		}
		for i := len(target); i > 0; i-- {
			ok, _ := path.Match(pattern, target[i-1])
			dp[i] = dp[i-1] && ok
		}
		dp[0] = false
	}
	return dp[len(target)]
}
