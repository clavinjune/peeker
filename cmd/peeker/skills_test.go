package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSkillCLIProjectAndGlobal(t *testing.T) {
	project, home := t.TempDir(), t.TempDir()
	t.Chdir(project)
	t.Setenv("HOME", home)
	if err := installSkill([]string{"add"}); err != nil {
		t.Fatal(err)
	}
	if err := installSkill([]string{"add", "--global"}); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{project, home} {
		if _, err := os.Stat(filepath.Join(root, ".agents", "skills", "peeker", "SKILL.md")); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{}, {"remove"}, {"add", "elsewhere"}, {"add", "--unknown"}} {
		if installSkill(args) == nil {
			t.Fatal("accepted invalid arguments", args)
		}
	}
}
