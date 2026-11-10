package explorer

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestProxyArgumentsAndBoundedOutput(t *testing.T) {
	name := "--server=https://evil.invalid; $(touch nope)"
	args := proxyArguments(name)
	if args[0] != "--context="+name || !slices.Contains(args, "--as=system:serviceaccount:peeker-system:peeker-reader") || !slices.Contains(args, "--address=127.0.0.1") || !slices.Contains(args, "--port=0") {
		t.Fatal(args)
	}
	o := &proxyOutput{ready: make(chan string, 1)}
	for _, part := range []string{"noise\nStarting to serve on 0.0.0.0:8001\n", "Starting to serve on 127.0.0.1:0\n", "Starting to serve on 127.0.0.1:", "12345\r\n"} {
		if _, err := o.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case base := <-o.ready:
		if base != "http://127.0.0.1:12345" {
			t.Fatal(base)
		}
	default:
		t.Fatal("missing startup address")
	}
	o = &proxyOutput{ready: make(chan string, 1)}
	if _, err := o.Write([]byte(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("unbounded startup line")
	}
	o = &proxyOutput{ready: make(chan string, 1)}
	if _, err := o.Write([]byte(strings.Repeat("x\n", 33000))); err == nil {
		t.Fatal("unbounded startup output")
	}
	b := &boundedOutput{limit: 4}
	if _, err := b.Write([]byte("12345")); err == nil || b.Len() != 0 {
		t.Fatal("unbounded context output")
	}
}

func TestKubectlProcessLifecycle(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = config ]; then\n  printf 'two\\none\\n'\n  exit 0\nfi\nprintf 'Starting to serve on 127.0.0.1:12345\\n'\nexec /bin/sleep 60\n"
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	runner := kubectlRunner{}
	names, err := runner.names(context.Background())
	if err != nil || !slices.Equal(names, []string{"one", "two"}) {
		t.Fatal(names, err)
	}
	process, err := runner.start(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	process.stop()
	process.stop()
	select {
	case <-process.done:
	default:
		t.Fatal("proxy still running after stop")
	}
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if process, err := runner.start(ctx, "one"); err == nil || process != nil {
		t.Fatal("cancelled startup succeeded")
	}
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.start(context.Background(), "one"); err == nil {
		t.Fatal("failed process succeeded")
	}
}
