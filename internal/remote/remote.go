package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxPresetBytes = 2 * 1024 * 1024 // 2 MiB safety cap
	fetchTimeout   = 15 * time.Second
	maxRedirects   = 5
)

var (
	clientMu          sync.RWMutex
	testHTTPClient    *http.Client
	allowPrivateForUT bool
)

// SetTestHTTPClient overrides the HTTP client for TLS loopback unit tests and returns a restore func.
func SetTestHTTPClient(c *http.Client) func() {
	clientMu.Lock()
	prevClient := testHTTPClient
	prevAllow := allowPrivateForUT
	testHTTPClient = c
	allowPrivateForUT = c != nil
	clientMu.Unlock()
	return func() {
		clientMu.Lock()
		testHTTPClient = prevClient
		allowPrivateForUT = prevAllow
		clientMu.Unlock()
	}
}

// Result represents a resolved and SHA-256-verified remote preset.
type Result struct {
	Ref       string
	URL       string
	SHA256    string
	Raw       []byte
	FromCache bool
}

// IsRemote reports whether ref is a remote preset (`github:...` or `https://...`).
func IsRemote(ref string) bool {
	t := strings.TrimSpace(ref)
	return strings.HasPrefix(t, "github:") || strings.HasPrefix(t, "https://")
}

// ResolveURL translates a remote ref into a canonical HTTPS download URL.
// Supported forms:
//   - github:<owner>/<repo>/<path>@<ref>  -> https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
//   - https://<host>/<path>
func ResolveURL(ref string) (string, error) {
	t := strings.TrimSpace(ref)
	if strings.HasPrefix(t, "github:") {
		spec := strings.TrimPrefix(t, "github:")
		atIdx := strings.LastIndexByte(spec, '@')
		if atIdx <= 0 || atIdx == len(spec)-1 {
			return "", fmt.Errorf("github preset ref %q must include @<ref> (e.g. github:owner/repo/path.yaml@v1.0.0)", ref)
		}
		pathPart := spec[:atIdx]
		gitRef := spec[atIdx+1:]
		if strings.Contains(gitRef, "..") || strings.ContainsAny(gitRef, " \t\r\n") {
			return "", fmt.Errorf("invalid git ref %q in %q", gitRef, ref)
		}
		segs := strings.Split(pathPart, "/")
		if len(segs) < 3 || segs[0] == "" || segs[1] == "" {
			return "", fmt.Errorf("github preset ref %q must be github:<owner>/<repo>/<path>@<ref>", ref)
		}
		owner := segs[0]
		repo := segs[1]
		var escapedFileSegs []string
		for _, s := range segs[2:] {
			if s == "" || s == "." || s == ".." {
				return "", fmt.Errorf("invalid path segment %q in github preset ref %q", s, ref)
			}
			escapedFileSegs = append(escapedFileSegs, url.PathEscape(s))
		}
		return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
			url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(gitRef), strings.Join(escapedFileSegs, "/")), nil
	}

	u, err := url.Parse(t)
	if err != nil {
		return "", fmt.Errorf("invalid remote preset URL %q: %w", ref, err)
	}
	if u.Scheme == "https" && u.Host != "" {
		return u.String(), nil
	}
	return "", fmt.Errorf("remote preset %q must use https:// or github:<owner>/<repo>/<path>@<ref>", ref)
}

// CacheDir returns the content-addressed local preset cache directory.
func CacheDir() string {
	if custom := strings.TrimSpace(os.Getenv("WAYPOST_CACHE_DIR")); custom != "" {
		return filepath.Join(custom, "presets")
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); xdg != "" {
		return filepath.Join(xdg, "waypost", "presets")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".cache", "waypost", "presets")
	}
	return filepath.Join(os.TempDir(), "waypost-cache", "presets")
}

// IsValidSHA256Hex reports whether s is a valid 64-char lowercase hex SHA-256 digest.
func IsValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Fetch resolves a remote preset, checking the content-addressed cache first when
// expectedSHA256 is known. When expectedSHA256 is non-empty, downloaded or cached
// bytes MUST match byte-for-byte or Fetch fails closed.
func Fetch(ref, expectedSHA256 string, offline bool) (*Result, error) {
	return fetch(ref, expectedSHA256, offline, true)
}

// FetchReadOnly verifies downloaded or cached bytes without updating the cache.
func FetchReadOnly(ref, expectedSHA256 string, offline bool) (*Result, error) {
	return fetch(ref, expectedSHA256, offline, false)
}

func fetch(ref, expectedSHA256 string, offline, updateCache bool) (*Result, error) {
	resolvedURL, err := ResolveURL(ref)
	if err != nil {
		return nil, err
	}

	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expectedSHA256 != "" && !IsValidSHA256Hex(expectedSHA256) {
		return nil, fmt.Errorf("invalid expected sha256 digest %q for remote preset %q", expectedSHA256, ref)
	}

	cacheDir := CacheDir()
	if expectedSHA256 != "" {
		cachePath := filepath.Join(cacheDir, expectedSHA256+".yaml")
		if raw, err := readCache(cachePath); err == nil {
			actual := sha256Hex(raw)
			if actual == expectedSHA256 {
				return &Result{
					Ref:       ref,
					URL:       resolvedURL,
					SHA256:    actual,
					Raw:       raw,
					FromCache: true,
				}, nil
			}
		}
	}

	if offline {
		return nil, fmt.Errorf("offline mode enabled and remote preset %q (sha256=%q) is not in local cache (%s)", ref, expectedSHA256, cacheDir)
	}

	client := buildHTTPClient()
	req, err := http.NewRequest(http.MethodGet, resolvedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", resolvedURL, err)
	}
	req.Header.Set("User-Agent", "waypost-cli")
	req.Header.Set("Accept", "application/yaml, text/yaml, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch remote preset %q: %w", resolvedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch remote preset %q returned HTTP %d", resolvedURL, resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxPresetBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read remote preset %q: %w", resolvedURL, err)
	}
	if len(raw) > maxPresetBytes {
		return nil, fmt.Errorf("remote preset %q exceeds maximum allowed size (%d bytes)", resolvedURL, maxPresetBytes)
	}

	actual := sha256Hex(raw)
	if expectedSHA256 != "" && actual != expectedSHA256 {
		return nil, fmt.Errorf("remote preset %q sha256 mismatch: expected %s, got %s", ref, expectedSHA256, actual)
	}

	// Best-effort atomic write to local content-addressed cache.
	if updateCache {
		if err := os.MkdirAll(cacheDir, 0o755); err == nil {
			if f, err := os.CreateTemp(cacheDir, ".preset-*.tmp"); err == nil {
				tmpName := f.Name()
				if _, wErr := f.Write(raw); wErr == nil {
					_ = f.Close()
					_ = os.Rename(tmpName, filepath.Join(cacheDir, actual+".yaml"))
				} else {
					_ = f.Close()
					_ = os.Remove(tmpName)
				}
			}
		}

	}
	return &Result{
		Ref:       ref,
		URL:       resolvedURL,
		SHA256:    actual,
		Raw:       raw,
		FromCache: false,
	}, nil
}

func buildHTTPClient() *http.Client {
	clientMu.RLock()
	custom := testHTTPClient
	allowPrivate := allowPrivateForUT
	clientMu.RUnlock()

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing non-https redirect to %s", req.URL.Scheme)
		}
		return nil
	}

	if custom != nil {
		c := *custom
		c.Timeout = fetchTimeout
		c.CheckRedirect = checkRedirect
		return &c
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var allowedIP net.IP
		for _, ipAddr := range ips {
			if !allowPrivate && isDisallowedIP(ipAddr.IP) {
				return nil, fmt.Errorf("refusing connection to non-public IP %s for host %q", ipAddr.IP, host)
			}
			if allowedIP == nil {
				allowedIP = ipAddr.IP
			}
		}
		if allowedIP == nil {
			return nil, fmt.Errorf("no IP addresses resolved for %q", host)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(allowedIP.String(), port))
	}
	return &http.Client{
		Timeout:       fetchTimeout,
		Transport:     tr,
		CheckRedirect: checkRedirect,
	}
}

func isDisallowedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func readCache(filename string) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPresetBytes {
		return nil, fmt.Errorf("invalid cached preset file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("cached preset changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPresetBytes+1))
	if len(raw) > maxPresetBytes {
		return nil, fmt.Errorf("cached preset exceeds %d bytes", maxPresetBytes)
	}
	return raw, err
}
