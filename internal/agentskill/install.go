package agentskill

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed SKILL.md
var content []byte

func Install(directory string) (string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	const folder = ".agents/skills/peeker"
	const file = folder + "/SKILL.md"
	if err := root.MkdirAll(folder, 0755); err != nil {
		return "", err
	}
	out, err := root.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("%s already exists; existing skill was preserved", file)
	}
	if err != nil {
		return "", err
	}
	_, err = out.Write(content)
	closeErr := out.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	return filepath.Join(directory, file), nil
}
