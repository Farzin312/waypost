package archgraph

import (
	"path"
	"regexp"
	"strings"
)

var pythonImportRE = regexp.MustCompile("(?m)^[ \t]*(?:from[ \t]+(\\.*[A-Za-z_][A-Za-z0-9_.]*|\\.+)[ \t]+)?import\\b[ \t]*(\\([^)]*\\)|(?:[^\\r\\n;\\\\]|\\\\\\r?\\n)*)")
var pythonModuleRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

func extractPythonImports(src []byte) []parsedRef {
	// Keep line breaks and mask comments before matching parenthesized lists.
	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		lines[i], _, _ = strings.Cut(line, "#")
	}
	source := strings.Join(lines, "\n")
	var refs []parsedRef
	line, previous := 1, 0
	for _, match := range pythonImportRE.FindAllStringSubmatchIndex(source, -1) {
		line += strings.Count(source[previous:match[0]], "\n")
		previous = match[0]
		base := ""
		if match[2] >= 0 {
			base = source[match[2]:match[3]]
			refs = append(refs, parsedRef{line: line, spec: base})
		}
		names := strings.Trim(source[match[4]:match[5]], "()")
		names = strings.ReplaceAll(strings.ReplaceAll(names, "\\\r\n", ""), "\\\n", "")
		for _, part := range strings.Split(names, ",") {
			fields := strings.Fields(part)
			if len(fields) == 0 || !pythonModuleRE.MatchString(fields[0]) {
				continue
			}
			spec := fields[0]
			if base != "" {
				if strings.HasSuffix(base, ".") {
					spec = base + spec
				} else {
					spec = base + "." + spec
				}
			}
			refs = append(refs, parsedRef{line: line, spec: spec})
		}
	}
	return refs
}

func resolvePythonImport(fromFile, spec string, files map[string]bool) string {
	if strings.HasPrefix(spec, ".") {
		module := strings.TrimLeft(spec, ".")
		dir := path.Dir(fromFile)
		for dots := len(spec) - len(module); dots > 1; dots-- {
			if dir == "." {
				return ""
			}
			dir = path.Dir(dir)
		}
		return matchPythonTarget(path.Join(dir, strings.ReplaceAll(module, ".", "/")), files)
	}
	module := strings.ReplaceAll(spec, ".", "/")
	if target := matchPythonTarget(module, files); target != "" {
		return target
	}
	return matchPythonTarget(path.Join(path.Dir(fromFile), module), files)
}

func matchPythonTarget(stem string, files map[string]bool) string {
	if stem != "." && files[stem+".py"] {
		return stem + ".py"
	}
	if init := path.Join(stem, "__init__.py"); files[init] {
		return init
	}
	return ""
}
