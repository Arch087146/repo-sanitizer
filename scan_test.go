package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arch087146/repo-sanitizer/internal/scan"
)

func TestMask(t *testing.T) {
	if got := scan.Mask("sk_live_51JqXAMPLE0000000"); got != "sk_liv…000" {
		t.Fatalf("mask wrong: %q", got)
	}
}

func TestSecretDetection(t *testing.T) {
	dir := t.TempDir()
	files := []string{"config.js"}
	content := "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\nSLACK_TOKEN = xoxb-123456789012-abcdef\n"
	if err := write(dir, "config.js", content); err != nil {
		t.Fatal(err)
	}
	findings := scan.ScanFiles(dir, files)

	kinds := map[string]bool{}
	for _, f := range findings {
		kinds[f.Type] = true
	}
	if !kinds["AWS Access Key ID"] || !kinds["Slack token"] {
		t.Fatalf("expected AWS + Slack detection, got %v", kinds)
	}
	for _, f := range findings {
		if strings.Contains(f.Sample, "AKIAIOSFODNN7EXAMPLE") {
			t.Fatal("finding must be masked, not leaked")
		}
	}
}

func TestFileChecks(t *testing.T) {
	dir := t.TempDir()
	if err := write(dir, ".env", "SECRET=hunter2\n"); err != nil {
		t.Fatal(err)
	}
	findings := scan.ScanFiles(dir, []string{".env"})
	if len(findings) == 0 || findings[0].Sev != "HIGH" {
		t.Fatalf("tracked .env must be HIGH, got %+v", findings)
	}
}

func write(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
}
