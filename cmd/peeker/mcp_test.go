package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPCommandHelper(t *testing.T) {
	if os.Getenv("PEEKER_MCP_TEST_HELPER") != "1" {
		return
	}
	if err := run("not-an-http-listener", os.Getenv("PEEKER_MCP_TEST_PROXY"), "", true, true); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMCPCommandTransportAndProxyCleanup(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(strconv.FormatBool(managed), func(t *testing.T) {
			dir := t.TempDir()
			pidPath := filepath.Join(dir, "proxy.pid")
			script := "#!/bin/sh\nif [ \"$1\" = config ]; then printf 'one\\n'; exit 0; fi\nprintf '%s' \"$$\" > \"$PEEKER_TEST_PID\"\nprintf 'Starting to serve on 127.0.0.1:12345\\n'\nexec /bin/sleep 60\n"
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPCommandHelper$")
			proxy := "http://127.0.0.1:1"
			if managed {
				proxy = ""
			}
			cmd.Env = append(os.Environ(), "PEEKER_MCP_TEST_HELPER=1", "PEEKER_MCP_TEST_PROXY="+proxy, "PATH="+dir, "PEEKER_TEST_PID="+pidPath)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			client := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 3 * time.Second}, nil)
			if err != nil {
				t.Fatal(err, stderr.String())
			}
			defer session.Close()
			tools, err := session.ListTools(ctx, nil)
			if err != nil || len(tools.Tools) != 4 {
				t.Fatal(tools, err)
			}
			status, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "cluster_status", Arguments: map[string]any{}})
			if err != nil || status.IsError {
				t.Fatal(status, err)
			}
			raw, _ := json.Marshal(status.StructuredContent)
			if !strings.Contains(string(raw), `"status":"ready"`) {
				t.Fatal(string(raw))
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
				t.Fatal("stdio did not exit cleanly on EOF", cmd.ProcessState, stderr.String())
			}
			if managed {
				raw, err := os.ReadFile(pidPath)
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				if syscall.Kill(pid, 0) == nil {
					t.Fatal("managed proxy survived client disconnect")
				}
			}
		})
	}
}
