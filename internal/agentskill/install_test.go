package agentskill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPreservesExistingSkill(t *testing.T) {
	root := t.TempDir()
	path, err := Install(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "http://127.0.0.1:8080/mcp") || !strings.Contains(string(data), "untrusted data") {
		t.Fatal("incomplete skill", err)
	}
	if err := os.WriteFile(path, []byte("user skill"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root); err == nil {
		t.Fatal("existing skill was overwritten")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "user skill" {
		t.Fatal(string(data))
	}
}

func TestInstallCannotEscapeRootThroughSymlink(t *testing.T) {
	root, other := t.TempDir(), t.TempDir()
	if err := os.Symlink(other, filepath.Join(root, ".agents")); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root); err == nil {
		t.Fatal("escaped root")
	}
	entries, err := os.ReadDir(other)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside selected root", err)
	}
}
