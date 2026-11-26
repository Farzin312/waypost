package archgraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Farzin312/waypost/internal/compmap"
)

type jsToken struct {
	text string
	kind byte
	line int
}

type jsLexer struct {
	src  string
	pos  int
	line int
	rust bool
}

func (l *jsLexer) take() byte {
	c := l.src[l.pos]
	l.pos++
	if c == '\n' || (c == '\r' && (l.pos == len(l.src) || l.src[l.pos] != '\n')) {
		l.line++
	}
	return c
}

func (l *jsLexer) at(prefix string) bool {
	return strings.HasPrefix(l.src[l.pos:], prefix)
}

func (l *jsLexer) skipComment() bool {
	switch {
	case l.at("//"):
		for l.pos < len(l.src) && l.src[l.pos] != '\r' && l.src[l.pos] != '\n' {
			l.pos++
		}
	case l.at("/*"):
		l.pos += 2
		for depth := 1; l.pos < len(l.src) && depth > 0; {
			switch {
			case l.at("*/"):
				depth--
				l.pos += 2
			case l.rust && l.at("/*"):
				depth++
				l.pos += 2
			default:
				l.take()
			}
		}
	default:
		return false
	}
	return true
}

func (l *jsLexer) quoted(quote byte) (string, bool) {
	l.pos++ // opening delimiter
	start := l.pos
	for l.pos < len(l.src) {
		c := l.take()
		switch {
		case c == quote:
			return l.src[start : l.pos-1], true
		case c == '\\' && l.pos < len(l.src):
			if l.at("\r\n") {
				l.take()
			}
			l.take()
		case (c == '\n' || c == '\r') && !(l.rust && quote == '"'):
			return "", false
		}
	}
	return "", false
}

// skipTemplate skips both template text and interpolation, including nested templates.
func (l *jsLexer) skipTemplate() {
	l.pos++
	depth := []int{0} // zero denotes template text, positive denotes interpolation braces
	for l.pos < len(l.src) && len(depth) > 0 {
		top := &depth[len(depth)-1]
		c := l.src[l.pos]
		if *top == 0 {
			switch {
			case c == '\\':
				l.take()
				if l.pos < len(l.src) {
					l.take()
				}
			case c == 96: // backtick
				l.pos++
				depth = depth[:len(depth)-1]
			case l.at("${"):
				l.pos += 2
				*top = 1
			default:
				l.take()
			}
			continue
		}
		switch {
		case l.skipComment():
		case c == 96:
			l.pos++
			depth = append(depth, 0)
		case c == '\'' || c == '"':
			l.quoted(c)
		default:
			l.take()
			switch c {
			case '{':
				*top++
			case '}':
				*top--
			}
		}
	}
}

func identifierByte(c byte) bool {
	return c == '_' || c == '$' || c >= 128 || c >= 'A' && c <= 'Z' ||
		c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func (l *jsLexer) next() (jsToken, bool) {
	for l.pos < len(l.src) {
		start, line := l.pos, l.line
		c := l.src[start]
		switch {
		case l.skipComment():
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f':
			l.take()
			continue
		case c == 96 && !l.rust:
			l.skipTemplate()
			return jsToken{kind: c, line: line}, true
		case l.rust && c == 'r' && (l.at("r#") || l.at(`r"`)):
			if end, ok := l.rustRawStringEnd(); ok {
				for l.pos < end {
					l.take()
				}
				return jsToken{kind: 's', line: line}, true
			}
			l.pos++
			return jsToken{text: "r", kind: 'i', line: line}, true
		case c == '\'' && l.rust && l.rustLifetime():
			l.pos++
			for l.pos < len(l.src) && identifierByte(l.src[l.pos]) {
				l.pos++
			}
			return jsToken{text: l.src[start:l.pos], kind: 'i', line: line}, true
		case c == '\'' || c == '"':
			value, ok := l.quoted(c)
			if !ok {
				return jsToken{kind: '?', line: line}, true
			}
			return jsToken{text: value, kind: 's', line: line}, true
		case identifierByte(c):
			l.pos++
			for l.pos < len(l.src) && identifierByte(l.src[l.pos]) {
				l.pos++
			}
			return jsToken{text: l.src[start:l.pos], kind: 'i', line: line}, true
		default:
			l.take()
			return jsToken{kind: c, line: line}, true
		}
	}
	return jsToken{}, false
}

func (l *jsLexer) rustLifetime() bool {
	i := l.pos + 1
	for i < len(l.src) && identifierByte(l.src[i]) {
		i++
	}
	return i > l.pos+1 && (i == len(l.src) || l.src[i] != '\'')
}

func (l *jsLexer) rustRawStringEnd() (int, bool) {
	i := l.pos + 1
	for i < len(l.src) && l.src[i] == '#' {
		i++
	}
	if i == len(l.src) || l.src[i] != '"' {
		return 0, false
	}
	end := l.src[i:i+1] + l.src[l.pos+1:i]
	if offset := strings.Index(l.src[i+1:], end); offset >= 0 {
		return i + 1 + offset + len(end), true
	}
	return len(l.src), true
}

func (t jsToken) isWord(word string) bool { return t.kind == 'i' && t.text == word }

func extractTSImports(src []byte) []parsedRef {
	lexer := jsLexer{src: string(src), line: 1}
	var tokens []jsToken
	for tok, ok := lexer.next(); ok; tok, ok = lexer.next() {
		tokens = append(tokens, tok)
	}
	var refs []parsedRef
	for i, tok := range tokens {
		if tok.kind != 'i' || (i > 0 && tokens[i-1].kind == '.') {
			continue
		}
		switch tok.text {
		case "import", "export", "require":
			if spec := tsImportSpecifier(tok.text, tokens[i+1:]); spec != "" {
				refs = append(refs, parsedRef{line: tok.line, spec: spec})
			}
		}
	}
	return refs
}

func tsTokenAt(tokens []jsToken, i int) jsToken {
	if i >= len(tokens) {
		return jsToken{}
	}
	return tokens[i]
}

func tsImportSpecifier(keyword string, tokens []jsToken) string {
	first := tsTokenAt(tokens, 0)
	switch {
	case keyword != "export" && first.kind == '(':
		arg, end := tsTokenAt(tokens, 1), tsTokenAt(tokens, 2)
		if arg.kind == 's' && (end.kind == ')' || (keyword == "import" && end.kind == ',')) {
			return decodeJSString(arg.text)
		}
		return ""
	case keyword == "require":
		return ""
	case keyword == "import" && first.kind == 's':
		return decodeJSString(first.text)
	}
	i := 0
	if first.isWord("type") && !tsTokenAt(tokens, 1).isWord("from") && tsTokenAt(tokens, 1).kind != ',' {
		i++
	}
	if keyword == "import" && tsTokenAt(tokens, i).kind == 'i' {
		i++ // default binding
		if tsTokenAt(tokens, i).kind == ',' {
			i++
		}
	}
	switch tsTokenAt(tokens, i).kind {
	case '{':
		i++
		// Named bindings have no nested braces.
		for i < len(tokens) && tokens[i].kind != '}' {
			if tokens[i].kind == '{' || tokens[i].kind == ';' {
				return ""
			}
			i++
		}
		i++
	case '*':
		i++
		if tsTokenAt(tokens, i).isWord("as") && tsTokenAt(tokens, i+1).kind == 'i' {
			i += 2
		}
	default:
		if keyword == "export" || i == 0 {
			return ""
		}
	}
	if tsTokenAt(tokens, i).isWord("from") && tsTokenAt(tokens, i+1).kind == 's' {
		return decodeJSString(tokens[i+1].text)
	}
	return ""
}

func decodeJSString(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var out strings.Builder
	for len(s) > 0 {
		if s[0] != '\\' {
			out.WriteByte(s[0])
			s = s[1:]
			continue
		}
		if len(s) < 2 {
			break
		}
		escaped := s[1:]
		switch escaped[0] {
		case '\r', '\n': // line continuation
			s = strings.TrimPrefix(escaped, "\r")
			s = strings.TrimPrefix(s, "\n")
		case '\'', '"':
			out.WriteByte(escaped[0])
			s = escaped[1:]
		default:
			if c, multibyte, rest, err := strconv.UnquoteChar(s, 0); err == nil {
				if multibyte {
					out.WriteRune(c)
				} else {
					out.WriteByte(byte(c))
				}
				s = rest
			} else if strings.HasPrefix(escaped, "u{") {
				code, rest, closed := strings.Cut(escaped[2:], "}")
				value, err := strconv.ParseUint(code, 16, 32)
				if closed && err == nil {
					out.WriteRune(rune(value))
					s = rest
				} else {
					return ""
				}
			} else {
				out.WriteByte(escaped[0])
				s = escaped[1:]
			}
		}
	}
	return out.String()
}

type tsAliasConfig struct {
	baseDir string
	baseURL string
	paths   []tsPathMapping
}

type tsPathMapping struct {
	pattern string
	prefix  string
	suffix  string
	hasStar bool
	baseURL string
	targets []string
}

type tsConfigLoader struct {
	repo         string
	ignore       []string
	allowedFiles map[string]bool
}

func tsConfigPriority(name string) int {
	switch name {
	case "tsconfig.json":
		return 0
	case "tsconfig.base.json":
		return 1
	default:
		return 2
	}
}

func (l tsConfigLoader) load(rel string, chain []string) (tsAliasConfig, error) {
	if len(chain) >= 24 || slices.Contains(chain, rel) {
		return tsAliasConfig{}, fmt.Errorf("tsconfig extends cycle or depth limit at %s", rel)
	}
	if !validRepoPath(rel) || compmap.MatchAnyGlob(l.ignore, rel) || (l.allowedFiles != nil && !l.allowedFiles[rel]) {
		return tsAliasConfig{}, fmt.Errorf("tsconfig extends references unavailable file %q", rel)
	}
	raw, err := compmap.ReadBoundedRegularFile(l.repo, filepath.Join(l.repo, rel), maxSourceFileBytes)
	if err != nil {
		return tsAliasConfig{}, err
	}

	var doc struct {
		Extends         json.RawMessage `json:"extends"`
		CompilerOptions struct {
			BaseURL *string             `json:"baseUrl"`
			Paths   map[string][]string `json:"paths"`
		} `json:"compilerOptions"`
	}
	if err := json.Unmarshal(cleanJSONC(raw), &doc); err != nil {
		return tsAliasConfig{}, err
	}
	var parents []string
	if len(doc.Extends) > 0 {
		var single string
		if err := json.Unmarshal(doc.Extends, &single); err == nil {
			parents = []string{single}
		} else if err := json.Unmarshal(doc.Extends, &parents); err != nil {
			return tsAliasConfig{}, fmt.Errorf("invalid extends: %w", err)
		}
	}

	out := tsAliasConfig{baseDir: path.Dir(rel)}
	paths := make(map[string]tsPathMapping)
	for _, parent := range parents {
		if !strings.HasPrefix(parent, "./") && !strings.HasPrefix(parent, "../") {
			continue
		}
		name := path.Join(out.baseDir, parent)
		ancestry := append(chain, rel)
		// A suffix such as .base is part of a common TS config basename.
		if !strings.HasSuffix(name, ".json") && l.allowedFiles != nil && !l.allowedFiles[name] {
			name += ".json"
		}
		tc, err := l.load(name, ancestry)
		if errors.Is(err, os.ErrNotExist) && !strings.HasSuffix(name, ".json") {
			tc, err = l.load(name+".json", ancestry)
		}
		if err != nil {
			return tsAliasConfig{}, fmt.Errorf("extends %q: %w", parent, err)
		}
		if tc.baseURL != "" {
			out.baseURL = tc.baseURL
		}
		for _, mapping := range tc.paths {
			paths[mapping.pattern] = mapping
		}
	}
	if doc.CompilerOptions.BaseURL != nil {
		out.baseURL = path.Join(out.baseDir, filepath.ToSlash(*doc.CompilerOptions.BaseURL))
	}
	for pattern, targets := range doc.CompilerOptions.Paths {
		prefix, suffix, hasStar := strings.Cut(pattern, "*")
		paths[pattern] = tsPathMapping{pattern: pattern, prefix: prefix, suffix: suffix, hasStar: hasStar, targets: targets, baseURL: out.baseDir}
	}
	for _, mapping := range paths {
		if out.baseURL != "" {
			mapping.baseURL = out.baseURL
		}
		out.paths = append(out.paths, mapping)
	}
	sort.Slice(out.paths, func(i, j int) bool {
		a, b := out.paths[i], out.paths[j]
		if a.hasStar != b.hasStar {
			return !a.hasStar
		}
		if len(a.prefix) != len(b.prefix) {
			return len(a.prefix) > len(b.prefix)
		}
		return a.pattern < b.pattern
	})
	return out, nil
}

func cleanJSONC(raw []byte) []byte {
	lexer := jsLexer{src: string(raw), line: 1}
	clean := make([]byte, 0, len(raw))
	for lexer.pos < len(raw) {
		start := lexer.pos
		if lexer.skipComment() {
			clean = append(clean, ' ')
			continue
		}
		if raw[start] == '"' {
			lexer.quoted('"')
		} else {
			lexer.pos++
		}
		clean = append(clean, raw[start:lexer.pos]...)
	}
	lexer = jsLexer{src: string(clean), line: 1}
	out := make([]byte, 0, len(clean))
	for lexer.pos < len(clean) {
		start := lexer.pos
		if clean[start] == '"' {
			lexer.quoted('"')
		} else {
			lexer.pos++
			if clean[start] == ',' {
				rest := bytes.TrimLeft(clean[lexer.pos:], " \t\r\n")
				if len(rest) > 0 && (rest[0] == '}' || rest[0] == ']') {
					continue
				}
			}
		}
		out = append(out, clean[start:lexer.pos]...)
	}
	return out
}

func matchingTSConfig(relFile string, configs []tsAliasConfig) *tsAliasConfig {
	for i := range configs {
		dir := configs[i].baseDir
		if dir == "." || strings.HasPrefix(relFile, dir+"/") {
			return &configs[i]
		}
	}
	return nil
}
