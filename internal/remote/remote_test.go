package remote

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveURL(t *testing.T) {
	u, err := ResolveURL("github:Farzin312/waypost/examples/app-ts/.waypost.yaml@v0.1.0")
	if err != nil {
		t.Fatalf("ResolveURL failed: %v", err)
	}
	want := "https://raw.githubusercontent.com/Farzin312/waypost/v0.1.0/examples/app-ts/.waypost.yaml"
	if u != want {
		t.Fatalf("got %q, want %q", u, want)
	}
	for _, bad := range []string{
		"http://example.com/preset.yaml",
		"http://127.0.0.1:8080/preset.yaml",
		"http://localhost/preset.yaml",
		"github:Farzin312/waypost/no-ref.yaml",
		"github:Farzin312/waypost/../escape.yaml@v1",
	} {
		if _, err := ResolveURL(bad); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

func TestDisallowedInternalIPsBlocked(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.5", "::1", "0.0.0.0"} {
		if !isDisallowedIP(net.ParseIP(s)) {
			t.Fatalf("expected %s to be disallowed", s)
		}
	}
	if isDisallowedIP(net.ParseIP("185.199.108.133")) {
		t.Fatal("expected public GitHub IP to be allowed")
	}
}

func TestFetchCachesVerifiesAndSupportsOffline(t *testing.T) {
	t.Setenv("WAYPOST_CACHE_DIR", t.TempDir())
	body := []byte("schema_version: \"1\"\nname: remote-org\n")
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	defer SetTestHTTPClient(srv.Client())()

	res1, err := Fetch(srv.URL+"/org.yaml", "", false)
	if err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}
	if res1.FromCache || hits != 1 {
		t.Fatalf("expected network fetch on first call, hits=%d fromCache=%v", hits, res1.FromCache)
	}

	// Second call with pinned SHA and offline=true MUST serve from local cache with zero network calls!
	res2, err := Fetch(srv.URL+"/org.yaml", res1.SHA256, true)
	if err != nil {
		t.Fatalf("offline cached fetch failed: %v", err)
	}
	if !res2.FromCache || hits != 1 {
		t.Fatalf("expected cache hit with zero network calls, hits=%d fromCache=%v", hits, res2.FromCache)
	}

	// Wrong expected SHA or path-traversal digest must fail closed!
	if _, err := Fetch(srv.URL+"/org.yaml", "0000000000000000000000000000000000000000000000000000000000000000", false); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
	if _, err := Fetch(srv.URL+"/org.yaml", "../../etc/passwd", false); err == nil {
		t.Fatal("expected invalid digest path traversal to be rejected")
	}
}
