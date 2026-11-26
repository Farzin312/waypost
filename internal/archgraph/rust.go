package archgraph

import (
	"path"
	"regexp"
	"strings"
)

var cargoNameRE = regexp.MustCompile(`^name[ \t]*=[ \t]*["']([A-Za-z0-9_-]+)["'][ \t]*(?:#.*)?$`)

func rustCrateName(src []byte) string {
	var packageName, libraryName string
	section := ""
	for line := range strings.SplitSeq(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section, _, _ = strings.Cut(line, "]")
		}
		if m := cargoNameRE.FindStringSubmatch(line); m != nil {
			switch section {
			case "[package":
				packageName = m[1]
			case "[lib":
				libraryName = m[1]
			}
		}
	}
	if libraryName != "" {
		packageName = libraryName
	}
	return strings.ReplaceAll(packageName, "-", "_")
}

func extractRustImports(src []byte) []parsedRef {
	lexer := jsLexer{src: string(src), line: 1, rust: true}
	var tokens []jsToken
	for tok, ok := lexer.next(); ok; tok, ok = lexer.next() {
		tokens = append(tokens, tok)
	}
	var refs []parsedRef
	for i, tok := range tokens {
		next := tsTokenAt(tokens, i+1)
		switch {
		case tok.isWord("mod") && next.kind == 'i' && tsTokenAt(tokens, i+2).kind == ';':
			refs = append(refs, parsedRef{line: tok.line, spec: "mod::" + next.text})
		case tok.isWord("use"):
			tree := rustUseTree{tokens: tokens[i+1:], line: tok.line}
			if tree.parse("", 0) && tree.at(0).kind == ';' {
				refs = append(refs, tree.refs...)
			}
		}
	}
	return refs
}

type rustUseTree struct {
	tokens []jsToken
	pos    int
	line   int
	refs   []parsedRef
}

func (t *rustUseTree) at(offset int) jsToken {
	return tsTokenAt(t.tokens, t.pos+offset)
}

func (t *rustUseTree) separator() bool {
	if t.at(0).kind != ':' || t.at(1).kind != ':' {
		return false
	}
	t.pos += 2
	return true
}

func (t *rustUseTree) parse(prefix string, depth int) bool {
	if depth > 128 {
		return false
	}
	t.separator() // optional absolute path prefix
	for {
		part := t.at(0)
		t.pos++
		switch part.kind {
		case '{':
			for t.at(0).kind != '}' {
				if !t.parse(prefix, depth+1) {
					return false
				}
				if t.at(0).kind != ',' {
					break
				}
				t.pos++
			}
			if t.at(0).kind != '}' {
				return false
			}
			t.pos++
			return true
		case 'i', '*':
			name := part.text
			if part.kind == '*' {
				name = "*"
			}
			if !part.isWord("self") || prefix == "" || t.at(0).kind == ':' {
				prefix += "::" + name
			}
			if t.separator() {
				continue
			}
			if t.at(0).isWord("as") && t.at(1).kind == 'i' {
				t.pos += 2
			}
			t.refs = append(t.refs, parsedRef{line: t.line, spec: strings.TrimPrefix(prefix, "::")})
			return true
		default:
			return false
		}
	}
}

func resolveRustImport(fromFile, spec string, files map[string]bool, crates map[string]string) string {
	srcRoot := ""
	if idx := strings.LastIndex(fromFile, "/src/"); idx >= 0 {
		srcRoot = fromFile[:idx+4]
	} else if strings.HasPrefix(fromFile, "src/") {
		srcRoot = "src"
	}
	base := path.Dir(fromFile)
	switch name := path.Base(fromFile); name {
	case "lib.rs", "main.rs", "mod.rs":
	default:
		base = path.Join(base, strings.TrimSuffix(name, ".rs"))
	}
	prefix, suffix, _ := strings.Cut(spec, "::")
	switch prefix {
	case "mod", "self":
	case "super":
		base = path.Dir(base)
		for strings.HasPrefix(suffix, "super::") {
			base = path.Dir(base)
			suffix = strings.TrimPrefix(suffix, "super::")
		}
	case "crate":
		base = srcRoot
	default:
		base = crates[prefix]
	}
	if base == "" || ((prefix == "self" || prefix == "super") && srcRoot != "" &&
		base != srcRoot && !strings.HasPrefix(base, srcRoot+"/")) {
		return ""
	}

	// Resolve the longest module path first, then allow its trailing exported symbol.
	relative := strings.ReplaceAll(suffix, "::", "/")
	for relative != "" && relative != "." {
		stem := path.Join(base, relative)
		if files[stem+".rs"] {
			return stem + ".rs"
		}
		if files[stem+"/mod.rs"] {
			return stem + "/mod.rs"
		}
		if prefix == "mod" {
			return ""
		}
		relative = path.Dir(relative)
	}
	if prefix == "crate" || prefix == "self" || prefix == "super" || crates[prefix] != "" {
		for _, file := range []string{base + ".rs", path.Join(base, "mod.rs"), path.Join(base, "lib.rs"), path.Join(base, "main.rs")} {
			if files[file] {
				return file
			}
		}
	}
	return ""
}
