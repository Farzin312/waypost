//go:build darwin || linux || freebsd || netbsd || openbsd

package archgraph

import (
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Farzin312/waypost/internal/compmap"
)

func TestBoundedReaderRejectsPipesAndSockets(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "go.mod")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	// Open a socket with a short filesystem path for Unix-domain socket limits.
	socketPath := filepath.Join(dir, "s")
	socket, err := net.Listen("unix", socketPath)
	if err != nil && strings.Contains(err.Error(), "invalid argument") {
		t.Skipf("temporary socket path exceeds platform limit: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	for _, name := range []string{pipe, socketPath} {
		if _, err := compmap.ReadBoundedRegularFile(dir, name, maxSourceFileBytes); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("unsafe read of %s: %v", name, err)
		}
	}
	cm, err := compmap.Build(dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(dir, cm, nil)
	if err != nil || len(report.ScanErrors) != 1 || !strings.Contains(report.ScanErrors[0], "go.mod") {
		t.Fatalf("FIFO manifest scan: %v, %+v", err, report)
	}
}
