package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scan-utility/scanner/internal/config"
)

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# comment\nFOO=bar\nexport BAZ='qux'\nQUOTED=\"hello world\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FOO", "")
	os.Unsetenv("FOO")
	os.Unsetenv("BAZ")
	os.Unsetenv("QUOTED")

	if err := config.LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("FOO"); got != "bar" {
		t.Fatalf("FOO=%q", got)
	}
	if got := os.Getenv("BAZ"); got != "qux" {
		t.Fatalf("BAZ=%q", got)
	}
	if got := os.Getenv("QUOTED"); got != "hello world" {
		t.Fatalf("QUOTED=%q", got)
	}

	t.Setenv("FOO", "keep")
	if err := config.LoadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("FOO"); got != "keep" {
		t.Fatalf("FOO overwritten: %q", got)
	}
}
