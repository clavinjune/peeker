package explorer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type proxyProcess struct {
	client *Client
	stop   context.CancelFunc
	done   <-chan struct{}
}

type contextRunner interface {
	names(context.Context) ([]string, error)
	start(context.Context, string) (*proxyProcess, error)
}

type kubectlRunner struct{}

func CurrentContext(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "config", "current-context")
	output := &boundedOutput{limit: 2048}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, io.Discard, time.Second
	if cmd.Run() != nil {
		return "", errors.New("Cannot read current context; specify --context or --proxy")
	}
	name := strings.TrimSpace(output.String())
	if name == "" || len(name) > 1024 || strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("Invalid current context")
	}
	return name, nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("command output exceeds limit")
	}
	return b.Buffer.Write(p)
}

func (kubectlRunner) names(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "kubectl", "config", "get-contexts", "-o", "name")
	output := &boundedOutput{limit: 64 * 1024}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, io.Discard, time.Second
	if cmd.Run() != nil {
		return nil, errors.New("Cannot list contexts. Check that kubectl and a readable kubeconfig are available.")
	}
	names := []string{}
	for _, name := range strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n") {
		name = strings.TrimSuffix(name, "\r")
		if name != "" && len(name) <= 1024 && !strings.ContainsAny(name, "\x00\r\n") {
			names = append(names, name)
		}
	}
	if len(names) > 256 {
		return nil, errors.New("Context list exceeds 256 entries.")
	}
	sort.Strings(names)
	return names, nil
}

func proxyArguments(name string) []string {
	return []string{"--context=" + name, "--as=system:serviceaccount:peeker-system:peeker-reader", "--as-group=system:serviceaccounts", "--as-group=system:serviceaccounts:peeker-system", "--as-group=system:authenticated", "proxy", "--address=127.0.0.1", "--port=0", `--accept-hosts=^127\.0\.0\.1$`, "--reject-methods=POST,PUT,PATCH,DELETE,CONNECT,TRACE,OPTIONS,HEAD"}
}

var proxyStartLine = regexp.MustCompile(`^Starting to serve on 127\.0\.0\.1:([0-9]{1,5})$`)

type proxyOutput struct {
	pending []byte
	total   int
	ready   chan string
	ended   bool
}

func (o *proxyOutput) Write(p []byte) (int, error) {
	n := len(p)
	for _, b := range p {
		if o.ended {
			break
		}
		o.total++
		if len(o.pending) >= 4096 || o.total > 64*1024 {
			return 0, errors.New("proxy startup output exceeds limit")
		}
		if b != '\n' {
			o.pending = append(o.pending, b)
			continue
		}
		match := proxyStartLine.FindSubmatch(bytes.TrimSuffix(o.pending, []byte("\r")))
		o.pending = o.pending[:0]
		if len(match) == 2 {
			port, _ := strconv.Atoi(string(match[1]))
			if port > 0 && port <= 65535 {
				o.ready <- "http://127.0.0.1:" + strconv.Itoa(port)
				o.ended = true
			}
		}
	}
	return n, nil
}

func (kubectlRunner) start(ctx context.Context, name string) (*proxyProcess, error) {
	lifetime, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(lifetime, "kubectl", proxyArguments(name)...)
	output := &proxyOutput{ready: make(chan string, 1)}
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, io.Discard, time.Second
	if cmd.Start() != nil {
		stop()
		return nil, errors.New("Cannot start kubectl proxy. Check that kubectl is installed.")
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case base := <-output.ready:
		client, err := NewClient(base)
		if err == nil {
			return &proxyProcess{client, func() { stop(); <-done }, done}, nil
		}
	case <-ctx.Done():
	case <-timer.C:
	case <-done:
	}
	stop()
	<-done
	return nil, errors.New("Proxy startup failed. Check context connectivity, local authentication and permission to impersonate peeker-reader.")
}
